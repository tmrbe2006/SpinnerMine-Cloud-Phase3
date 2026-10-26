/**
 * SpinnerMine Cloud - XMRig Mining Adapter (Phase 2A Repaired & Hardened)
 *
 * Implements:
 * 1. SHA-256 cryptographic checksum validation of official XMRig binaries.
 * 2. Real XMRig HTTP API Pause & Resume (POST /1/pause, POST /1/resume).
 * 3. Robust Process Tree Termination (taskkill on Windows, SIGTERM/SIGKILL on POSIX) preventing orphaned processes.
 * 4. Error-safe spawn with ENOENT/EACCES error trapping.
 * 5. Real system CPU usage sampling via os.cpus() deltas (Zero hardcoded metrics).
 * 6. Simulation Isolation: strictly prohibited in Production; restricted exclusively to Vitest/Test environments.
 * 7. Real telemetry polling with strict zero-fabrication in non-test modes.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import { ChildProcess, spawn, exec } from 'child_process';
import { generateXMRigConfig, XMRigConfigOptions } from './xmrig-config';
import { XMRigTelemetry } from '../types';

export interface XMRigAdapterOptions {
  executablePath?: string;
  expectedSha256?: string;
  configOptions: XMRigConfigOptions;
  tempConfigDir?: string;
  pollingIntervalMs?: number;
  onTelemetry?: (telemetry: XMRigTelemetry) => void;
  onError?: (error: Error) => void;
  onExit?: (code: number | null, signal: string | null) => void;
  onLog?: (line: string) => void;
  simulatedMode?: boolean; // STRICTLY FOR TEST/CI ENVIRONMENTS ONLY
}

export const WINDOWS_DEFAULT_XMRIG_PATHS = [
  'C:\\Program Files\\xmrig\\xmrig.exe',
  'C:\\Program Files (x86)\\xmrig\\xmrig.exe',
  'C:\\xmrig\\xmrig.exe',
  'C:\\Tools\\xmrig\\xmrig.exe',
  './bin/xmrig.exe',
  './xmrig.exe'
];

/**
 * Known official SHA-256 hashes of release binaries and archives (Windows x64 MSVC & GCC)
 * Published by xmrig/xmrig on GitHub Releases (SHA256SUMS).
 */
export const KNOWN_OFFICIAL_XMRIG_SHA256: Record<string, string> = {
  // Official XMRig v6.26.0 (Windows x64)
  '6.26.0-exe': '6fa80698d7268f6e88aa88c06fb27ee99e1bcee747c2e76911e6206a5b1aeeb3',
  '6.26.0-zip': 'bba8097cb37d9b458a1cb1137876b27cde6740d17fe4ccbc086ba07d87d9e147',
  '6.26.0': '6fa80698d7268f6e88aa88c06fb27ee99e1bcee747c2e76911e6206a5b1aeeb3',
  // Official XMRig v6.22.2
  '6.22.2-msvc': '1d903d39c7e4e1706c32c44721d6a6c851aa8c4c10df1479478ee93cd67301bc',
  '6.22.2-gcc': '53b37a734ab27bb40626c6434029defbebe8470f2d89b97e7ce85b40c9a3b05f',
  '6.22.2': 'b7e9b04fbb4e815e9e03f191bdf10137ffdd8f7833bc833fc88f615fba393dd1',
  // Official XMRig v6.22.1
  '6.22.1-msvc': '1d8060ce86b65e0eb489ead196660ba8064f711beca612551d40e94a46d8e628',
  '6.22.1-gcc': '7084964c61c889fac649d695427f214d8b99fe8b719d2e9b3fbf6e72f1d2f470',
  '6.22.1': 'ee339aa723e75e11ea89bc9fe84fa2dbe9cf0fe18408cb83a9a8bebfba0e2343',
  // Official XMRig v6.22.0
  '6.22.0-msvc': 'b980b17ef632506ad6747f813572058698e9da843f008c8d395c7f2afc31ebea',
  '6.22.0-gcc': '6a543eaa9cca4909099db2d0a277d2cb970feeba7630ce5310c92be1a4ab240c',
  '6.22.0': '8f3651faec4b8d74dc09b19df4241e75fb6358db82dd9bc649479b1d3cf556c0',
  // Official XMRig v6.21.3
  '6.21.3-msvc': '713263085499ae626a6148fab67932c9a69611b21ac3d04cf52a5e23495f902e',
  '6.21.3-gcc': '281a9c492610a2378a25a803009838106c04692e3fe42828370518c2e8cdbc21',
  '6.21.3': 'f2b059eafe6778f307fc8b1c4b717b1897e684ebcbcfeb4911d3d63b2f9faeb2',
  // Official XMRig v6.21.0 & v6.20.0
  '6.21.0': '36f6d6c9dd3d65b1aa0e557b6ec7fceb5a8397a61d62c9ee562ec8061483be9c',
  '6.20.0': '4a8cb1e309fc57dc0ec9315d18d488fb2c42aa07ff017f8582f3484f3eb44747'
};

export type XMRigReleaseType = 'exe' | 'zip';

export interface XMRigReleaseMetadata {
  version: string;
  type: XMRigReleaseType;
  fileName: string;
  sha256: string;
  description: string;
}

/**
 * Official extracted executable binaries (xmrig.exe) SHA-256 hashes
 */
export const KNOWN_OFFICIAL_XMRIG_EXE_SHA256: Record<string, string> = {
  '6.26.0': '6fa80698d7268f6e88aa88c06fb27ee99e1bcee747c2e76911e6206a5b1aeeb3',
  '6.22.2': 'b7e9b04fbb4e815e9e03f191bdf10137ffdd8f7833bc833fc88f615fba393dd1',
  '6.22.2-msvc': '1d903d39c7e4e1706c32c44721d6a6c851aa8c4c10df1479478ee93cd67301bc',
  '6.22.2-gcc': '53b37a734ab27bb40626c6434029defbebe8470f2d89b97e7ce85b40c9a3b05f',
  '6.22.1': 'ee339aa723e75e11ea89bc9fe84fa2dbe9cf0fe18408cb83a9a8bebfba0e2343',
  '6.22.1-msvc': '1d8060ce86b65e0eb489ead196660ba8064f711beca612551d40e94a46d8e628',
  '6.22.1-gcc': '7084964c61c889fac649d695427f214d8b99fe8b719d2e9b3fbf6e72f1d2f470',
  '6.22.0': '8f3651faec4b8d74dc09b19df4241e75fb6358db82dd9bc649479b1d3cf556c0',
  '6.22.0-msvc': 'b980b17ef632506ad6747f813572058698e9da843f008c8d395c7f2afc31ebea',
  '6.22.0-gcc': '6a543eaa9cca4909099db2d0a277d2cb970feeba7630ce5310c92be1a4ab240c',
  '6.21.3': 'f2b059eafe6778f307fc8b1c4b717b1897e684ebcbcfeb4911d3d63b2f9faeb2',
  '6.21.3-msvc': '713263085499ae626a6148fab67932c9a69611b21ac3d04cf52a5e23495f902e',
  '6.21.3-gcc': '281a9c492610a2378a25a803009838106c04692e3fe42828370518c2e8cdbc21',
  '6.21.0': '36f6d6c9dd3d65b1aa0e557b6ec7fceb5a8397a61d62c9ee562ec8061483be9c',
  '6.20.0': '4a8cb1e309fc57dc0ec9315d18d488fb2c42aa07ff017f8582f3484f3eb44747'
};

/**
 * Official release distribution ZIP archive SHA-256 hashes
 */
export const KNOWN_OFFICIAL_XMRIG_ZIP_SHA256: Record<string, string> = {
  '6.26.0': 'bba8097cb37d9b458a1cb1137876b27cde6740d17fe4ccbc086ba07d87d9e147'
};

/**
 * Distinguishes and identifies an official XMRig release hash as either an executable or ZIP archive.
 */
export function identifyXMRigRelease(hash: string): {
  version: string;
  type: XMRigReleaseType;
  fileName: string;
  matchedKey: string;
} | null {
  if (!hash || typeof hash !== 'string') return null;
  const normalized = hash.trim().toLowerCase();

  for (const [ver, zipHash] of Object.entries(KNOWN_OFFICIAL_XMRIG_ZIP_SHA256)) {
    if (zipHash.toLowerCase() === normalized) {
      return {
        version: ver,
        type: 'zip',
        fileName: `xmrig-${ver}-windows-x64.zip`,
        matchedKey: `${ver}-zip`
      };
    }
  }

  for (const [ver, exeHash] of Object.entries(KNOWN_OFFICIAL_XMRIG_EXE_SHA256)) {
    if (exeHash.toLowerCase() === normalized) {
      return {
        version: ver,
        type: 'exe',
        fileName: 'xmrig.exe',
        matchedKey: ver
      };
    }
  }

  return null;
}

/**
 * Calculates SHA-256 hash of a file on disk.
 */
export async function calculateFileSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(filePath)) {
      return reject(new Error(`File not found: ${filePath}`));
    }
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex').toLowerCase()));
    stream.on('error', (err) => reject(err));
  });
}

export class XMRigAdapter {
  private options: XMRigAdapterOptions;
  private process: ChildProcess | null = null;
  private pollInterval: NodeJS.Timeout | null = null;
  private isMining = false;
  private isPaused = false;
  private activeConfigPath: string | null = null;
  private activeApiPort = 18088;
  private activeApiToken = '';
  private currentTelemetry: XMRigTelemetry = {
    hashrate: 0,
    acceptedShares: 0,
    rejectedShares: 0,
    uptimeSeconds: 0,
    threads: 2,
    connectionStatus: 'disconnected'
  };

  // CPU measurement sampling state
  private lastCpuSample: { idle: number; total: number } | null = null;

  // Process exit cleanup handler
  private boundExitHandler: (() => void) | null = null;

  // Simulation metrics for testing environments
  private simulationTimer: NodeJS.Timeout | null = null;

  constructor(options: XMRigAdapterOptions) {
    this.options = {
      pollingIntervalMs: 2000,
      ...options
    };
  }

  /**
   * Scans default paths to find official XMRig executable on Windows.
   */
  public static detectXMRigInstallation(customSearchDirs: string[] = []): string | null {
    const candidates = [...customSearchDirs, ...WINDOWS_DEFAULT_XMRIG_PATHS];
    for (const candidate of candidates) {
      try {
        if (fs.existsSync(candidate)) {
          const stat = fs.statSync(candidate);
          if (stat.isFile()) {
            return path.resolve(candidate);
          }
        }
      } catch {}
    }
    return null;
  }

  /**
   * Validates a provided executable path by verifying existence, permissions, and SHA-256 checksum.
   * Does NOT consider the filename alone as proof of authenticity.
   * Strictly distinguishes between official ZIP archives and executable binaries.
   */
  public static async validateExecutable(
    exePath: string, 
    expectedSha256?: string
  ): Promise<{ 
    valid: boolean; 
    sha256?: string; 
    matchedVersion?: string; 
    releaseType?: 'exe' | 'zip' | 'custom'; 
    reason?: string 
  }> {
    if (!exePath || typeof exePath !== 'string') {
      return { valid: false, reason: 'Executable path is empty' };
    }

    try {
      if (!fs.existsSync(exePath)) {
        return { valid: false, reason: `File does not exist: ${exePath}` };
      }

      const stat = fs.statSync(exePath);
      if (!stat.isFile()) {
        return { valid: false, reason: `Target path is not a file: ${exePath}` };
      }

      // Minimum reasonable size for XMRig compiled binary (~ 2 MB to 30 MB)
      if (stat.size < 500 * 1024) {
        return { valid: false, reason: 'File size is too small for an authentic XMRig binary (potential stub or script)' };
      }

      // Compute cryptographic SHA-256
      const sha256 = (await calculateFileSha256(exePath)).toLowerCase();

      // If user supplied an expected hash, enforce exact case-insensitive match
      if (expectedSha256) {
        if (sha256 !== expectedSha256.trim().toLowerCase()) {
          return {
            valid: false,
            sha256,
            reason: `SHA-256 mismatch! Expected: ${expectedSha256}, Computed: ${sha256}`
          };
        }
      }

      // Check if file hash matches an official distribution ZIP archive
      const releaseInfo = identifyXMRigRelease(sha256);
      if (releaseInfo?.type === 'zip') {
        return {
          valid: false,
          sha256,
          matchedVersion: `${releaseInfo.version}-zip`,
          releaseType: 'zip',
          reason: `Official XMRig v${releaseInfo.version} distribution ZIP archive recognized (SHA-256: ${sha256}). Please extract 'xmrig.exe' from this archive and select the extracted executable binary to run mining.`
        };
      }

      // Check if hash matches an official executable release
      let matchedVersion: string | undefined;
      if (releaseInfo?.type === 'exe') {
        matchedVersion = releaseInfo.version;
      } else {
        for (const [ver, knownHash] of Object.entries(KNOWN_OFFICIAL_XMRIG_SHA256)) {
          // Skip zip entries when searching for executable binary version
          if (ver.endsWith('-zip')) continue;
          if (knownHash.toLowerCase() === sha256) {
            matchedVersion = ver;
            break;
          }
        }
      }

      // STRICT GATE: Binary MUST match either an explicit expected SHA-256 or a known official release
      if (!expectedSha256 && !matchedVersion) {
        return {
          valid: false,
          sha256,
          reason: `Unverified XMRig binary: SHA-256 (${sha256}) does not match any official trusted release in the database. Explicit expectedSha256 must be provided for custom binaries.`
        };
      }

      return {
        valid: true,
        sha256,
        matchedVersion: matchedVersion || 'custom-verified',
        releaseType: matchedVersion ? 'exe' : 'custom'
      };
    } catch (err: any) {
      return { valid: false, reason: `Verification error: ${err.message}` };
    }
  }

  /**
   * Authoritatively classifies any XMRig release file (executable or ZIP archive),
   * providing cryptographic verification and release metadata.
   */
  public static async validateFile(filePath: string): Promise<{
    valid: boolean;
    sha256: string;
    type: 'exe' | 'zip' | 'unknown';
    version?: string;
    isOfficial: boolean;
    reason?: string;
  }> {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File does not exist: ${filePath}`);
    }
    const sha256 = (await calculateFileSha256(filePath)).toLowerCase();
    const releaseInfo = identifyXMRigRelease(sha256);

    if (releaseInfo) {
      return {
        valid: true,
        sha256,
        type: releaseInfo.type,
        version: releaseInfo.version,
        isOfficial: true,
        reason: releaseInfo.type === 'zip'
          ? `Verified official XMRig v${releaseInfo.version} distribution ZIP archive.`
          : `Verified official XMRig v${releaseInfo.version} executable binary.`
      };
    }

    return {
      valid: false,
      sha256,
      type: 'unknown',
      isOfficial: false,
      reason: `Unverified file: SHA-256 (${sha256}) is not recognized in the official trusted database.`
    };
  }

  /**
   * Starts XMRig with generated secure configuration.
   */
  public async start(): Promise<boolean> {
    if (this.isMining) {
      throw new Error('Mining process is already active. Please stop the existing process before starting anew.');
    }

    // 1. Simulation Isolation Check
    const isTestEnv = process.env.NODE_ENV === 'test' || Boolean(process.env.VITEST);
    if (this.options.simulatedMode) {
      if (!isTestEnv) {
        throw new Error('Security Violation: Simulated mining mode is strictly prohibited in production environments.');
      }
      this.startSimulatedMining();
      return true;
    }

    // In non-test environments or when simulatedMode is not requested, native binary is required
    const exePath = this.options.executablePath || XMRigAdapter.detectXMRigInstallation();
    if (!exePath) {
      if (isTestEnv) {
        // Fallback only allowed in automated testing
        this.startSimulatedMining();
        return true;
      }
      throw new Error('Official XMRig executable not found. Please provide a verified path to xmrig.exe.');
    }

    // 2. Validate Executable & SHA-256
    const validation = await XMRigAdapter.validateExecutable(exePath, this.options.expectedSha256);
    if (!validation.valid) {
      throw new Error(`Security validation failed for XMRig binary: ${validation.reason}`);
    }

    // 3. Generate secure config (strictly validated inputs)
    const generated = generateXMRigConfig(this.options.configOptions);
    this.activeApiPort = generated.apiPort;
    this.activeApiToken = generated.apiToken;

    const configDir = this.options.tempConfigDir || path.resolve('.mining_temp');
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    this.activeConfigPath = path.join(configDir, `xmrig_config_${Date.now()}.json`);
    fs.writeFileSync(this.activeConfigPath, generated.configJson, { mode: 0o600 });

    // 4. Spawn XMRig Child Process with Error Trapping
    return new Promise<boolean>((resolve, reject) => {
      let isSettled = false;

      try {
        this.process = spawn(exePath, ['--config', this.activeConfigPath!], {
          windowsHide: true,
          detached: false,
          stdio: ['ignore', 'pipe', 'pipe']
        });

        // Error trap for spawn failure (e.g. ENOENT, EACCES)
        this.process.once('error', (err) => {
          this.cleanupProcessState();
          if (this.options.onError) {
            this.options.onError(new Error(`Failed to execute XMRig binary: ${err.message}`));
          }
          if (!isSettled) {
            isSettled = true;
            reject(new Error(`Spawn error: ${err.message}`));
          }
        });

        this.process.stdout?.on('data', (chunk) => {
          const line = chunk.toString();
          const trimmed = line.trim();
          if (trimmed.toLowerCase().includes('new job') || trimmed.toLowerCase().includes('job #')) {
            this.currentTelemetry.jobsReceived = (this.currentTelemetry.jobsReceived || 0) + 1;
            this.currentTelemetry.lastPoolResponse = trimmed;
          } else if (trimmed.toLowerCase().includes('accepted') || trimmed.toLowerCase().includes('rejected')) {
            this.currentTelemetry.lastPoolResponse = trimmed;
          }
          if (this.options.onLog) {
            this.options.onLog(line);
          }
        });

        this.process.stderr?.on('data', (chunk) => {
          const errorMsg = chunk.toString();
          if (this.options.onError) {
            this.options.onError(new Error(`XMRig process error: ${errorMsg}`));
          }
        });

        this.process.once('close', (code, signal) => {
          const wasActive = this.isMining;
          this.cleanupProcessState();
          if (!isSettled) {
            isSettled = true;
            reject(new Error(`XMRig process exited immediately with code ${code ?? signal}`));
            return;
          }
          if (wasActive && this.options.onExit) {
            this.options.onExit(code, signal);
          }
        });

        // Register process termination hooks to avoid orphan processes
        this.boundExitHandler = () => {
          this.killProcessTree();
        };
        process.once('exit', this.boundExitHandler);
        process.once('SIGINT', this.boundExitHandler);
        process.once('SIGTERM', this.boundExitHandler);

        // Verification delay to catch immediate startup crashes
        setTimeout(() => {
          if (!isSettled && this.process && !this.process.killed) {
            isSettled = true;
            this.isMining = true;
            this.isPaused = false;
            this.currentTelemetry.connectionStatus = 'connecting';
            this.startApiPolling();
            resolve(true);
          }
        }, 150);
      } catch (err: any) {
        this.cleanupProcessState();
        reject(new Error(`Failed to spawn XMRig: ${err.message}`));
      }
    });
  }

  /**
   * Gracefully and authoritatively terminates the XMRig process and any child subprocesses.
   */
  public async stop(): Promise<void> {
    if (this.simulationTimer) {
      clearInterval(this.simulationTimer);
      this.simulationTimer = null;
    }

    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }

    await this.killProcessTree();
    this.cleanupProcessState();
  }

  /**
   * Real XMRig HTTP API Pause: Calls POST /1/pause on localhost.
   */
  public async pause(): Promise<boolean> {
    if (!this.isMining) return false;
    this.isPaused = true;
    let apiSuccess = false;

    if (this.process && this.activeApiToken) {
      try {
        const response = await fetch(`http://127.0.0.1:${this.activeApiPort}/1/pause`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.activeApiToken}`,
            'Content-Type': 'application/json'
          },
          signal: AbortSignal.timeout(1500)
        });
        if (response.ok) {
          apiSuccess = true;
        }
      } catch {
        // Fallback on POSIX if HTTP API endpoint is not yet ready
        if (process.platform !== 'win32' && this.process && this.process.pid) {
          try {
            process.kill(this.process.pid, 'SIGSTOP');
            apiSuccess = true;
          } catch {}
        }
      }
    } else if (this.simulationTimer) {
      apiSuccess = true;
    }

    this.currentTelemetry.connectionStatus = 'paused';
    this.currentTelemetry.hashrate = 0;
    if (this.options.onTelemetry) {
      this.options.onTelemetry({ ...this.currentTelemetry });
    }
    return apiSuccess;
  }

  /**
   * Real XMRig HTTP API Resume: Calls POST /1/resume on localhost.
   */
  public async resume(): Promise<boolean> {
    if (!this.isMining) return false;
    this.isPaused = false;
    let apiSuccess = false;

    if (this.process && this.activeApiToken) {
      try {
        const response = await fetch(`http://127.0.0.1:${this.activeApiPort}/1/resume`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.activeApiToken}`,
            'Content-Type': 'application/json'
          },
          signal: AbortSignal.timeout(1500)
        });
        if (response.ok) {
          apiSuccess = true;
        }
      } catch {
        // Fallback on POSIX
        if (process.platform !== 'win32' && this.process && this.process.pid) {
          try {
            process.kill(this.process.pid, 'SIGCONT');
            apiSuccess = true;
          } catch {}
        }
      }
    } else if (this.simulationTimer) {
      apiSuccess = true;
    }

    this.currentTelemetry.connectionStatus = 'connected';
    if (this.options.onTelemetry) {
      this.options.onTelemetry({ ...this.currentTelemetry });
    }
    return apiSuccess;
  }

  public getTelemetry(): XMRigTelemetry {
    return { ...this.currentTelemetry };
  }

  public getActiveConfigPath(): string | null {
    return this.activeConfigPath;
  }

  public isProcessActive(): boolean {
    return this.isMining;
  }

  public getPid(): number | null {
    return this.process?.pid || null;
  }

  public isProcessPaused(): boolean {
    return this.isPaused;
  }

  /**
   * Measures actual system CPU usage using os.cpus() deltas.
   * Returns a percentage (0-100) or undefined if measurement is not yet ready.
   * NEVER returns a fake constant.
   */
  private measureRealCpuUsage(): number | undefined {
    try {
      const cpus = os.cpus();
      let idle = 0;
      let total = 0;

      for (const cpu of cpus) {
        for (const type in cpu.times) {
          total += (cpu.times as any)[type];
        }
        idle += cpu.times.idle;
      }

      if (!this.lastCpuSample) {
        this.lastCpuSample = { idle, total };
        return undefined;
      }

      const totalDiff = total - this.lastCpuSample.total;
      const idleDiff = idle - this.lastCpuSample.idle;
      this.lastCpuSample = { idle, total };

      if (totalDiff <= 0) return undefined;
      const usagePercent = Math.round(100 - (100 * idleDiff / totalDiff));
      return Math.min(100, Math.max(0, usagePercent));
    } catch {
      return undefined;
    }
  }

  private startApiPolling() {
    if (this.pollInterval) clearInterval(this.pollInterval);

    this.pollInterval = setInterval(async () => {
      if (!this.isMining || this.isPaused) return;

      try {
        const summary = await this.fetchLocalhostApiSummary();
        const measuredCpu = this.measureRealCpuUsage();

        if (summary) {
          this.currentTelemetry = {
            hashrate: summary.hashrate?.total?.[0] || 0,
            hashrate10s: summary.hashrate?.total?.[0] || 0,
            hashrate60s: summary.hashrate?.total?.[1] || 0,
            hashrate15m: summary.hashrate?.total?.[2] || 0,
            acceptedShares: summary.results?.shares_good || 0,
            rejectedShares: (summary.results?.shares_total || 0) - (summary.results?.shares_good || 0),
            difficulty: summary.results?.diff_current || 0,
            uptimeSeconds: summary.uptime || 0,
            threads: summary.cpu?.threads || this.options.configOptions.threads || 2,
            cpuUsage: measuredCpu, // Actual measured CPU usage or undefined
            connectionStatus: summary.connection?.pool ? 'connected' : 'connecting'
          };

          if (this.options.onTelemetry) {
            this.options.onTelemetry(this.currentTelemetry);
          }
        }
      } catch (err: any) {
        this.currentTelemetry.connectionStatus = 'error';
        this.currentTelemetry.lastPoolError = err.message;
        if (this.options.onError) {
          this.options.onError(err);
        }
      }
    }, this.options.pollingIntervalMs || 2000);
  }

  private async fetchLocalhostApiSummary(): Promise<any> {
    const url = `http://127.0.0.1:${this.activeApiPort}/1/summary`;
    try {
      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${this.activeApiToken}`
        },
        signal: AbortSignal.timeout(1500)
      });

      if (!response.ok) {
        return null;
      }
      return await response.json();
    } catch {
      return null;
    }
  }

  /**
   * Kills the XMRig process and its entire process tree.
   * On Windows: uses taskkill /pid <pid> /T /F
   * On POSIX: sends SIGTERM, then SIGKILL
   */
  private async killProcessTree(): Promise<void> {
    const proc = this.process;
    if (!proc || !proc.pid) {
      this.process = null;
      return;
    }

    const pid = proc.pid;
    return new Promise((resolve) => {
      // Destroy stdio stream pipes to prevent file handle leaks
      try {
        if (proc.stdout && !proc.stdout.destroyed) proc.stdout.destroy();
        if (proc.stderr && !proc.stderr.destroyed) proc.stderr.destroy();
      } catch {}

      if (process.platform === 'win32') {
        exec(`taskkill /pid ${pid} /T /F`, (_err) => {
          try {
            if (proc && !proc.killed) {
              proc.kill('SIGKILL');
            }
          } catch {}
          this.process = null;
          resolve();
        });
      } else {
        try {
          proc.kill('SIGTERM');
          setTimeout(() => {
            if (proc && !proc.killed) {
              try {
                proc.kill('SIGKILL');
              } catch {}
            }
            this.process = null;
            resolve();
          }, 300);
        } catch {
          this.process = null;
          resolve();
        }
      }
    });
  }

  /**
   * Simulation for automated testing environments only.
   */
  private startSimulatedMining() {
    this.isMining = true;
    this.isPaused = false;
    this.currentTelemetry.connectionStatus = 'connected';
    let uptime = 0;
    let shares = 0;

    this.simulationTimer = setInterval(() => {
      if (!this.isMining) return;
      if (this.isPaused) {
        this.currentTelemetry.hashrate = 0;
        return;
      }

      uptime += 2;
      const baseHashrate = 420;
      const variation = Math.floor((Math.random() - 0.5) * 40);
      const reportedHash = baseHashrate + variation;

      if (uptime % 10 === 0) {
        shares += 1;
      }

      this.currentTelemetry = {
        hashrate: reportedHash,
        hashrate10s: reportedHash,
        hashrate60s: reportedHash - 5,
        hashrate15m: reportedHash - 2,
        acceptedShares: shares,
        rejectedShares: 0,
        uptimeSeconds: uptime,
        threads: this.options.configOptions.threads || 2,
        cpuUsage: this.measureRealCpuUsage(),
        connectionStatus: 'connected'
      };

      if (this.options.onTelemetry) {
        this.options.onTelemetry(this.currentTelemetry);
      }
    }, this.options.pollingIntervalMs || 2000);
  }

  private cleanupProcessState() {
    this.isMining = false;
    this.isPaused = false;
    this.process = null;
    this.currentTelemetry.connectionStatus = 'disconnected';
    this.currentTelemetry.hashrate = 0;
    this.currentTelemetry.cpuUsage = undefined;

    if (this.boundExitHandler) {
      process.removeListener('exit', this.boundExitHandler);
      process.removeListener('SIGINT', this.boundExitHandler);
      process.removeListener('SIGTERM', this.boundExitHandler);
      this.boundExitHandler = null;
    }

    if (this.activeConfigPath) {
      try {
        if (fs.existsSync(this.activeConfigPath)) {
          fs.unlinkSync(this.activeConfigPath);
        }
      } catch {}
      this.activeConfigPath = null;
    }
  }
}
