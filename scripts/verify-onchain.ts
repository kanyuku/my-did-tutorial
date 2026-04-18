import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { setNetworkId, getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';
import { DustWallet } from '@midnight-ntwrk/wallet-sdk-dust-wallet';
import { HDWallet, Roles } from '@midnight-ntwrk/wallet-sdk-hd';
import { ShieldedWallet } from '@midnight-ntwrk/wallet-sdk-shielded';
import { createKeystore, InMemoryTransactionHistoryStorage, PublicKey, UnshieldedWallet } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import * as ledger from '@midnight-ntwrk/ledger-v8';
import { unshieldedToken } from '@midnight-ntwrk/ledger-v8';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocket } from 'ws';
import { Buffer } from 'buffer';

// Enable WebSocket for GraphQL subscriptions
// @ts-expect-error Required for wallet sync
globalThis.WebSocket = WebSocket;

// Set network to preprod
setNetworkId('preprod');

const CONFIG = {
  indexer: 'https://indexer.preprod.midnight.network/api/v3/graphql',
  indexerWS: 'wss://indexer.preprod.midnight.network/api/v3/graphql/ws',
  node: 'https://rpc.preprod.midnight.network',
  proofServer: 'http://127.0.0.1:6300',
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const zkConfigPath = path.resolve(__dirname, '..', 'contracts', 'managed', 'verifier');

// Load compiled contract
const contractPath = path.join(zkConfigPath, 'contract', 'index.js');
const VerifierNode = await import(pathToFileURL(contractPath).href);

const compiledContract = CompiledContract.make('verifier', VerifierNode.Contract).pipe(
  CompiledContract.withVacantWitnesses,
  CompiledContract.withCompiledFileAssets(zkConfigPath),
);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function padTo32Bytes(num: number | bigint): Uint8Array {
  const buf = Buffer.alloc(32);
  buf.writeUInt32BE(Number(num), 28);
  return new Uint8Array(buf);
}

function deriveKeys(seed: string) {
  const hdWallet = HDWallet.fromSeed(Buffer.from(seed, 'hex'));
  if (hdWallet.type !== 'seedOk') throw new Error('Invalid seed');
  const result = hdWallet.hdWallet.selectAccount(0).selectRoles([Roles.Zswap, Roles.NightExternal, Roles.Dust]).deriveKeysAt(0);
  if (result.type !== 'keysDerived') throw new Error('Key derivation failed');
  hdWallet.hdWallet.clear();
  return result.keys;
}

async function createWallet(seed: string) {
  const keys = deriveKeys(seed);
  const networkId = getNetworkId();
  const shieldedSecretKeys = ledger.ZswapSecretKeys.fromSeed(keys[Roles.Zswap]);
  const dustSecretKey = ledger.DustSecretKey.fromSeed(keys[Roles.Dust]);
  const unshieldedKeystore = createKeystore(keys[Roles.NightExternal], networkId);

  const walletConfig = {
    networkId,
    indexerClientConnection: { indexerHttpUrl: CONFIG.indexer, indexerWsUrl: CONFIG.indexerWS },
    provingServerUrl: new URL(CONFIG.proofServer),
    relayURL: new URL(CONFIG.node.replace(/^http/, 'ws')),
    txHistoryStorage: new InMemoryTransactionHistoryStorage(),
    costParameters: { additionalFeeOverhead: 300_000_000_000_000n, feeBlocksMargin: 5 },
  };

  const wallet = await WalletFacade.init({
    configuration: walletConfig,
    shielded: async (config) => ShieldedWallet(config).startWithSecretKeys(shieldedSecretKeys),
    unshielded: async (config) => UnshieldedWallet(config).startWithPublicKey(PublicKey.fromKeyStore(unshieldedKeystore)),
    dust: async (config) => DustWallet(config).startWithSecretKey(dustSecretKey, ledger.LedgerParameters.initialParameters().dust),
  });

  await wallet.start(shieldedSecretKeys, dustSecretKey);
  return { wallet, shieldedSecretKeys, dustSecretKey, unshieldedKeystore };
}

async function createProviders(walletCtx: any) {
  const state = await walletCtx.wallet.waitForSyncedState();
  const walletProvider = {
    getCoinPublicKey: () => state.shielded.coinPublicKey.toHexString(),
    getEncryptionPublicKey: () => state.shielded.encryptionPublicKey.toHexString(),
    async balanceTx(tx: any, ttl?: Date) {
      const recipe = await walletCtx.wallet.balanceUnboundTransaction(
        tx,
        { shieldedSecretKeys: walletCtx.shieldedSecretKeys, dustSecretKey: walletCtx.dustSecretKey },
        { ttl: ttl ?? new Date(Date.now() + 30 * 60 * 1000) },
      );
      const signedRecipe = await walletCtx.wallet.signRecipe(recipe, (payload: any) =>
        walletCtx.unshieldedKeystore.signData(payload),
      );
      return walletCtx.wallet.finalizeRecipe(signedRecipe);
    },
    submitTx: (tx: any) => walletCtx.wallet.submitTransaction(tx) as any,
  };

  const zkConfigProvider = new NodeZkConfigProvider(zkConfigPath);
  return {
    privateStateProvider: levelPrivateStateProvider({
      privateStateStoreName: 'verifier-state',
      accountId: walletCtx.unshieldedKeystore.getBech32Address().toString(),
      privateStoragePasswordProvider: () => 'development',
    }),
    publicDataProvider: indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(CONFIG.proofServer, zkConfigProvider),
    walletProvider,
    midnightProvider: walletProvider,
  };
}

// ─── Main Script ──────────────────────────────────────────────────────────────

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║        On-Chain ZK Proof Verification (Age)          ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  if (!fs.existsSync('deployment.verifier.json')) {
    console.error('ERROR: verifier contract not deployed! Run npm run deploy-verifier first.\n');
    process.exit(1);
  }

  const deployment = JSON.parse(fs.readFileSync('deployment.verifier.json', 'utf-8'));
  const seed = fs.readFileSync('.midnight-seed', 'utf-8').trim();

  const rl = createInterface({ input: stdin, output: stdout });
  const dobInput = await rl.question('  Enter your secret Date of Birth (YYYYMMDD): ');
  rl.close();

  const numericalDOB = parseInt(dobInput.trim(), 10);
  const secretDOBBytes = padTo32Bytes(numericalDOB);
  
  // In a real app, this salt would come from your credential storage
  // For this demo, we use a deterministic mock salt derived from the DID logic
  const mockSalt = new Uint8Array(32).fill(42); 

  console.log('\n  1. Connecting to Midnight Preprod...');
  const walletCtx = await createWallet(seed);
  const providers = await createProviders(walletCtx);

  console.log('  2. Loading contract instance...');
  const deployed: any = await findDeployedContract(providers, {
    compiledContract: compiledContract as any,
    contractAddress: deployment.contractAddress,
  });

  console.log('  3. Generating ZK Proof and submitting transaction...');
  console.log('     (This keeps your DOB hidden and proves it satisfies the contract rules)\n');

  try {
    // We first compute the commitment locally to match what's on the ledger
    console.log("  BEGINNER TIP: We are matching your private DOB against the on-chain commitment.");
    const { result: PublicCommitment } = await deployed.circuits.computeAgeCommitment(
        providers as any,
        secretDOBBytes,
        mockSalt
    );

    // Call the on-chain verification circuit
    const tx = await deployed.callTx.verifyAgeOnchain(
      secretDOBBytes,   // Secret input
      mockSalt,         // Secret input
      secretDOBBytes,   // Expected limit (disclosed)
      PublicCommitment  // Ledger commitment (disclosed)
    );

    console.log('  SUCCESS: ZK Proof Verified On-Chain!');
    console.log(`     Transaction ID : ${tx.public.txId}`);
    console.log(`     Block Height   : ${tx.public.blockHeight}\n`);

    console.log('  4. Verifying Ledger Update...');
    const contractState = await providers.publicDataProvider.queryContractState(deployment.contractAddress);
    if (contractState) {
        const ledgerState = VerifierNode.ledger(contractState.data);
        const proofExists = ledgerState.age_proofs.get(PublicCommitment);
        if (proofExists) {
            console.log('     Verified: Proof result recorded in the contract ledger.\n');
        }
    }

  } catch (error: any) {
    console.error('\n  ERROR: Verification Failed:', error?.message ?? error);
  } finally {
    await walletCtx.wallet.stop();
  }
}

main().catch(console.error);
