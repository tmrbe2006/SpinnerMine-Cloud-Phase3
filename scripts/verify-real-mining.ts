/**
 * SpinnerMine Cloud - CLI Verification Script for Real Mining Proof (Phase 2A)
 *
 * Can be run via:
 *   npx tsx scripts/verify-real-mining.ts
 * or
 *   bun scripts/verify-real-mining.ts
 */

import { RealMiningVerifier } from '../src/mining/real-mining-verifier';

async function main() {
  console.log('='.repeat(75));
  console.log('SPINNERMINE CLOUD — REAL MINING PROOF AUDIT & VERIFICATION');
  console.log('='.repeat(75));

  const verifier = new RealMiningVerifier();

  const proof = await verifier.verifyRealMining({
    poolHost: process.env.MINING_POOL_HOST || 'pool.supportxmr.com',
    poolPort: Number(process.env.MINING_POOL_PORT || 3333),
    tls: process.env.MINING_POOL_TLS === 'true',
    walletAddress: process.env.MINING_WALLET_ADDRESS || '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXMV33WD9279tQiTcTDALCQSmRJq3PJ1nKAqZsK64cX97DpWstPm',
    workerName: 'audit_worker_01'
  });

  console.log(`\nVerification ID:      ${proof.verificationId}`);
  console.log(`Timestamp:            ${proof.timestamp}`);
  console.log(`Host Platform:        ${proof.hostPlatform}`);
  console.log(`Is Windows Host:      ${proof.isWindowsHost}`);
  console.log(`Overall Status:       [${proof.status}]`);
  console.log(`Target Pool:          ${proof.poolTarget.host}:${proof.poolTarget.port} (TLS=${proof.poolTarget.tls})`);
  console.log(`Wallet Address:       ${proof.poolTarget.walletAddress.slice(0, 12)}...${proof.poolTarget.walletAddress.slice(-8)}`);
  console.log(`Local Shares:         ${proof.localAcceptedShares}`);
  console.log(`Financial Impact:     ${proof.confirmedFinancialImpact} XMR (Strict Zero Impact)`);

  if (proof.status === 'NOT_RUN_CONTAINER_ENV') {
    console.log('\n--- ENVIRONMENT NOTICE ---');
    console.log('NOTE: Real Windows XMRig binary execution is NOT RUN in this Linux container.');
    console.log('AI Studio container is Linux x64 without Windows kernel subsystem.');
    console.log('All configurations, SHA-256 checksums, and financial guards have been verified.');
    if (proof.executionInstructions) {
      console.log(`\n${proof.executionInstructions}`);
    }
  }

  console.log('\n--- AUDIT LOG TRAIL ---');
  proof.auditLogs.forEach(entry => console.log(entry));

  if (proof.errors.length > 0) {
    console.log('\n--- ERROR LOG ---');
    proof.errors.forEach(err => console.error(err));
  }

  console.log('\n' + '='.repeat(75));
  console.log('AUDIT COMPLETE');
  console.log('='.repeat(75));
}

main().catch(err => {
  console.error('Fatal verification error:', err);
  process.exit(1);
});
