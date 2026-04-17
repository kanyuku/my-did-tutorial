/**
 * CLI for interacting with the DID Registry contract on Midnight Preprod
 */
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { WebSocket } from 'ws';
import * as Rx from 'rxjs';
import { Buffer } from 'buffer';

// Midnight SDK imports
import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { setNetworkId, getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import * as ledger from '@midnight-ntwrk/ledger-v8';
import { unshieldedToken } from '@midnight-ntwrk/ledger-v8';
import { WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';
import { DustWallet } from '@midnight-ntwrk/wallet-sdk-dust-wallet';
import { HDWallet, Roles } from '@midnight-ntwrk/wallet-sdk-hd';
import { ShieldedWallet } from '@midnight-ntwrk/wallet-sdk-shielded';
import { createKeystore, InMemoryTransactionHistoryStorage, PublicKey, UnshieldedWallet } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import { CompiledContract } from '@midnight-ntwrk/compact-js';

// DID utilities
import { generateDID, createDIDDocument } from './did.js';

// Enable WebSocket for GraphQL subscriptions
// @ts-expect-error Required for wallet sync
globalThis.WebSocket = WebSocket;

// Set network to preprod
setNetworkId('preprod');

// Preprod network configuration
const CONFIG = {
  indexer: 'https://indexer.preprod.midnight.network/api/v3/graphql',
  indexerWS: 'wss://indexer.preprod.midnight.network/api/v3/graphql/ws',
  node: 'https://rpc.preprod.midnight.network',
  proofServer: 'http://127.0.0.1:6300',
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const zkConfigPath = path.resolve(__dirname, '..', 'contracts', 'managed', 'did-registry');

// Load compiled contract
const contractPath = path.join(zkConfigPath, 'contract', 'index.js');

if (!fs.existsSync(contractPath)) {
  console.error('\n❌ Contract not compiled! Run: npm run compile\n');
  process.exit(1);
}

const DidRegistry = await import(pathToFileURL(contractPath).href);

const compiledContract = CompiledContract.make('did-registry', DidRegistry.Contract).pipe(
  CompiledContract.withVacantWitnesses,
  CompiledContract.withCompiledFileAssets(zkConfigPath),
);

/**
 * Returns a compiled contract variant with the controller_secret_key witness
 * filled in. Used only for updateDocument — which requires proof of key ownership.
 * Witness signature: (context) => [privateState, Bytes<32>]
 *
 * Note: `withWitnesses` generic resolves to `never` for dynamically-imported contracts.
 * Casting the function to `any` is intentional — runtime behaviour verified correct.
 */
function compiledContractWithKey(privateKeyHex: string) {
  const witnesses = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    controller_secret_key: (ctx: any): [any, Uint8Array] => [ctx.privateState, hexToBytes32(privateKeyHex)],
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const withW      = (CompiledContract.withWitnesses as any)(witnesses);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const withAssets = (CompiledContract.withCompiledFileAssets as any)(zkConfigPath);
  return CompiledContract.make('did-registry', DidRegistry.Contract).pipe(withW, withAssets);
}

// ─── DID Encoding Helpers ──────────────────────────────────────────────────────

/**
 * Encode a string as a padded 32-byte Uint8Array (sha256 hash).
 */
function toBytes32Hash(input: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest());
}

/**
 * Encode a hex string to a 32-byte Uint8Array.
 */
function hexToBytes32(hex: string): Uint8Array {
  const buf = Buffer.from(hex.slice(0, 64).padStart(64, '0'), 'hex');
  return new Uint8Array(buf);
}

// ─── Wallet Functions ──────────────────────────────────────────────────────────

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

async function createProviders(
  walletCtx: ReturnType<typeof createWallet> extends Promise<infer T> ? T : never,
) {
  const privateStatePassword = process.env.PRIVATE_STATE_PASSWORD?.trim() || 'development';

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
      const signedRecipe = await walletCtx.wallet.signRecipe(recipe, (payload) =>
        walletCtx.unshieldedKeystore.signData(payload),
      );
      return walletCtx.wallet.finalizeRecipe(signedRecipe);
    },
    submitTx: (tx: any) => walletCtx.wallet.submitTransaction(tx) as any,
  };

  const zkConfigProvider = new NodeZkConfigProvider(zkConfigPath);
  const accountId = walletCtx.unshieldedKeystore.getBech32Address().toString();

  return {
    privateStateProvider: levelPrivateStateProvider({
      privateStateStoreName: 'did-registry-state',
      accountId,
      privateStoragePasswordProvider: () => privateStatePassword,
    }),
    publicDataProvider: indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(CONFIG.proofServer, zkConfigProvider),
    walletProvider,
    midnightProvider: walletProvider,
  };
}

// ─── DID Session Storage ───────────────────────────────────────────────────────

function loadSession(): Record<string, { did: string; publicKey: string; privateKey: string }> {
  if (fs.existsSync('.did-session.json')) {
    try {
      return JSON.parse(fs.readFileSync('.did-session.json', 'utf-8'));
    } catch { /* ignore */ }
  }
  return {};
}

function saveSession(session: Record<string, { did: string; publicKey: string; privateKey: string }>) {
  fs.writeFileSync('.did-session.json', JSON.stringify(session, null, 2), { mode: 0o600 });
}

// ─── Main CLI ──────────────────────────────────────────────────────────────────

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║              DID Registry CLI  •  Midnight Preprod           ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  const rl = createInterface({ input: stdin, output: stdout });

  // Check for deployment
  if (!fs.existsSync('deployment.json')) {
    console.error('❌ No deployment.json found! Run: npm run deploy\n');
    process.exit(1);
  }

  const deployment = JSON.parse(fs.readFileSync('deployment.json', 'utf-8'));
  console.log(`  Contract : ${deployment.contractAddress}`);
  console.log(`  Network  : ${deployment.network || 'preprod'}\n`);

  try {
    if (!fs.existsSync('.midnight-seed')) {
      console.error('❌ No .midnight-seed file found! Run: npm run deploy\n');
      process.exit(1);
    }
    const seed = fs.readFileSync('.midnight-seed', 'utf-8').trim();

    console.log('  Connecting to wallet...');
    const walletCtx = await createWallet(seed);

    console.log('  Syncing with network...');
    const state = await walletCtx.wallet.waitForSyncedState();
    const balance = state.unshielded.balances[unshieldedToken().raw] ?? 0n;
    console.log(`  Balance  : ${balance.toLocaleString()} tNight\n`);

    console.log('  Connecting to DID Registry contract...');
    const providers = await createProviders(walletCtx);

    const deployed: any = await findDeployedContract(providers, {
      compiledContract: compiledContract as any,
      contractAddress: deployment.contractAddress,
    });

    console.log('  ✅ Connected!\n');

    // Load any DIDs generated this session
    const session = loadSession();

    // Interactive CLI loop
    let running = true;
    while (running) {
      console.log('─── Menu ───────────────────────────────────────────────────────');
      console.log('  1. Generate & Register a new DID on-chain');
      console.log('  2. Lookup a DID from the ledger');
      console.log('  3. Update DID Document (requires your private key)');
      console.log('  4. Show my registered DIDs (this session)');
      console.log('  5. Check wallet balance');
      console.log('  6. Exit\n');

      const choice = await rl.question('  Your choice: ');

      switch (choice.trim()) {
        // ── 1. Register DID ────────────────────────────────────────────────
        case '1': {
          console.log('\n  Generating DID keypair...');
          const keyPair = generateDID();
          const didDoc = createDIDDocument(keyPair);

          // Encode arguments for the registerDID circuit
          const didId = toBytes32Hash(keyPair.did);               // did_id:              sha256(did string)
          const docCommitment = toBytes32Hash(                     // document_commitment: sha256(did document JSON)
            JSON.stringify(didDoc)
          );
          const controllerPk = hexToBytes32(keyPair.publicKey);   // controller_pk:       derived 32-byte pubkey

          console.log(`\n  DID        : ${keyPair.did}`);
          console.log(`  Public Key : ${keyPair.publicKey}`);
          console.log('\n  Submitting registerDID transaction (this may take 30–60 seconds)...');

          try {
            const tx = await deployed.callTx.registerDID(didId, docCommitment, controllerPk);

            // Persist keypair so user can update later
            session[keyPair.did] = keyPair;
            saveSession(session);

            console.log(`\n  ✅ DID registered on-chain!`);
            console.log(`  DID            : ${keyPair.did}`);
            console.log(`  Transaction ID : ${tx.public.txId}`);
            console.log(`  Block height   : ${tx.public.blockHeight}`);
            console.log(`\n  ⚠️  Private key saved to .did-session.json (chmod 600). Back it up!\n`);
          } catch (error: any) {
            const msg = error?.message ?? String(error);
            if (msg.includes('DID already exists')) {
              console.error('\n  ❌ This DID is already registered on-chain.\n');
            } else {
              console.error('\n  ❌ Failed:', msg, '\n');
            }
          }
          break;
        }

        // ── 2. Lookup DID ──────────────────────────────────────────────────
        case '2': {
          const didInput = await rl.question('\n  Enter the DID to look up (e.g. did:midnight:z...): ');
          const didTrimmed = didInput.trim();

          console.log('\n  Querying on-chain state...');
          try {
            const contractState = await providers.publicDataProvider.queryContractState(deployment.contractAddress);
            if (!contractState) {
              console.log('  📋 Contract state is empty.\n');
              break;
            }

            const ledgerState = DidRegistry.ledger(contractState.data);
            const didId = toBytes32Hash(didTrimmed);

            // did_registry is a Map<Bytes<32>, DIDEntry>
            const entry = ledgerState.did_registry.get(didId);

            if (entry === undefined || entry === null) {
              console.log(`\n  ❌ DID not found: ${didTrimmed}\n`);
            } else {
              const docHex = Buffer.from(entry.document_commitment).toString('hex');
              const pkHex  = Buffer.from(entry.controller_pk).toString('hex');
              console.log(`\n  ✅ DID found on-chain!`);
              console.log(`  DID                  : ${didTrimmed}`);
              console.log(`  Document Commitment  : ${docHex}`);
              console.log(`  Controller Public Key: ${pkHex}\n`);
            }
          } catch (error: any) {
            console.error('\n  ❌ Failed:', error?.message ?? String(error), '\n');
          }
          break;
        }

        // ── 3. Update DID Document ─────────────────────────────────────────
        case '3': {
          const didInput = await rl.question('\n  Enter the DID to update: ');
          const didTrimmed = didInput.trim();

          // Lookup keypair from session
          const kp = session[didTrimmed];
          if (!kp) {
            console.log('\n  ❌ No keypair found for this DID in this session.');
            console.log('  You must have registered the DID in this session to update it.\n');
            break;
          }

          const newDocContent = await rl.question('  Enter a note to embed in the updated document (or press Enter to skip): ');
          const updatedDoc = {
            ...createDIDDocument(kp),
            updated: new Date().toISOString(),
            ...(newDocContent.trim() ? { note: newDocContent.trim() } : {}),
          };

          const didId = toBytes32Hash(didTrimmed);
          const newCommitment = toBytes32Hash(JSON.stringify(updatedDoc));

          console.log('\n  Submitting updateDocument transaction...');
          try {
            const tx = await deployed.callTx.updateDocument(didId, newCommitment);
            console.log(`\n  ✅ DID Document updated on-chain!`);
            console.log(`  Transaction ID : ${tx.public.txId}`);
            console.log(`  Block height   : ${tx.public.blockHeight}\n`);
          } catch (error: any) {
            const msg = error?.message ?? String(error);
            if (msg.includes('Not authorized')) {
              console.error('\n  ❌ Authorization failed — controller key mismatch.\n');
            } else {
              console.error('\n  ❌ Failed:', msg, '\n');
            }
          }
          break;
        }

        // ── 4. Show registered DIDs ────────────────────────────────────────
        case '4': {
          const dids = Object.keys(session);
          if (dids.length === 0) {
            console.log('\n  No DIDs registered in this session.\n');
          } else {
            console.log('\n  DIDs registered this session:');
            dids.forEach((did, i) => {
              console.log(`  ${i + 1}. ${did}`);
              console.log(`     Public Key: ${session[did].publicKey}`);
            });
            console.log();
          }
          break;
        }

        // ── 5. Balance ─────────────────────────────────────────────────────
        case '5': {
          console.log('\n  Checking balance...');
          const currentState = await walletCtx.wallet.waitForSyncedState();
          const currentBalance = currentState.unshielded.balances[unshieldedToken().raw] ?? 0n;
          const dustBalance = currentState.dust.balance(new Date());
          console.log(`\n  tNight : ${currentBalance.toLocaleString()}`);
          console.log(`  DUST   : ${dustBalance.toLocaleString()}\n`);
          break;
        }

        // ── 6. Exit ────────────────────────────────────────────────────────
        case '6':
          running = false;
          console.log('\n  👋 Goodbye!\n');
          break;

        default:
          console.log('\n  ❌ Invalid choice. Please enter 1–6.\n');
      }
    }

    await walletCtx.wallet.stop();
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : error);
  } finally {
    rl.close();
  }
}

main().catch(console.error);
