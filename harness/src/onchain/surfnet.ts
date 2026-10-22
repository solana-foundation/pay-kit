/**
 * On-chain test harness: boots a surfpool instance that FORKS mainnet-beta and
 * streams the live payment-channels (+ subscriptions) programs, so settlement
 * transactions actually EXECUTE the deployed program. This is what the
 * structural harness (`start-surfnet-proxy.mjs`) does not do - it only seeds
 * mints and inspects transaction bytes, so on-chain validations (treasury ATA,
 * voucher expiry, ALT guard) are never exercised. Forking makes those real,
 * which is how settlement-class regressions (e.g. the `TreasuryAccountMismatch`
 * that silently 402'd `upto`) get caught.
 */
import { getAddressDecoder } from "@solana/kit";
import { Surfnet } from "@solana/surfpool";

/** Live mainnet deployment the playground/clients settle against. */
export const PAYMENT_CHANNELS_PROGRAM = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX";
export const SUBSCRIPTIONS_PROGRAM = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44";
/** Mainnet USDC (present on the fork). */
export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/** Treasury owner baked into the deployed program - `distribute` credits its ATA. */
export const TREASURY_OWNER = "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP";

// The datasource RPC surfpool forks/streams mainnet account state from - the
// same SURFPOOL_DATASOURCE_RPC_URL the rest of the surfpool CI/tests use. The
// test talks to the surfpool instance (surfnet.rpcUrl), NOT this RPC; surfpool
// only reads from it to clone the program + mint state. Public mainnet is the
// last-resort fallback for local runs without the env set.
const PUBLIC_MAINNET_RPC_URL = "https://api.mainnet-beta.solana.com";

export function resolveDatasourceRpc(value?: string): string {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : PUBLIC_MAINNET_RPC_URL;
}

const DATASOURCE_RPC = resolveDatasourceRpc(process.env.SURFPOOL_DATASOURCE_RPC_URL);

export interface OnchainSurfnet {
  readonly rpcUrl: string;
  readonly surfnet: Surfnet;
  fundSol(address: string, lamports: number): void;
  fundUsdc(owner: string, amount: number): void;
  /** Poll until the program account resolves from the remote fork. */
  awaitProgram(programId: string, timeoutMs?: number): Promise<void>;
  stop(): void;
}

interface AccountInfo {
  executable?: boolean;
  owner?: string;
  data?: [string, string];
}

async function getAccount(rpcUrl: string, pubkey: string, withData = false): Promise<AccountInfo | null> {
  const config = withData ? { encoding: "base64" } : { encoding: "base64", dataSlice: { offset: 0, length: 0 } };
  const r = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getAccountInfo", params: [pubkey, config] }),
  });
  return (await r.json())?.result?.value ?? null;
}

const UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";

/**
 * The ProgramData account of an upgradeable-loader program: its `Program`
 * state is a u32 tag (2) followed by the ProgramData address. `null` for a
 * program that keeps its code in its own account.
 */
function programDataAddress(program: AccountInfo): string | null {
  if (program.owner !== UPGRADEABLE_LOADER || !program.data) return null;
  const bytes = Buffer.from(program.data[0], "base64");
  if (bytes.length < 36 || bytes.readUInt32LE(0) !== 2) return null;
  return getAddressDecoder().decode(bytes.subarray(4, 36));
}

/**
 * Start a mainnet-forking surfnet, stream the program accounts so they execute,
 * pre-create the treasury ATA, and fund the operator. Callers fund their own
 * client/operator wallets via {@link OnchainSurfnet.fundSol}/`fundUsdc`.
 */
export async function startOnchainSurfnet(opts?: {
  datasourceRpc?: string;
  programs?: string[];
}): Promise<OnchainSurfnet> {
  const datasourceRpc =
    opts?.datasourceRpc === undefined ? DATASOURCE_RPC : resolveDatasourceRpc(opts.datasourceRpc);
  const programs = opts?.programs ?? [PAYMENT_CHANNELS_PROGRAM, SUBSCRIPTIONS_PROGRAM];
  const surfnet = Surfnet.startWithConfig({ remoteRpcUrl: datasourceRpc, offline: false });
  const rpcUrl = surfnet.rpcUrl;

  for (const p of programs) surfnet.streamAccount(p);
  // The treasury ATA must exist for `distribute` to credit residuals; pre-create
  // it on the fork (amount 0) so settlement never fails on a missing account.
  surfnet.fundToken(TREASURY_OWNER, USDC_MINT, 0, TOKEN_PROGRAM);

  const api: OnchainSurfnet = {
    rpcUrl,
    surfnet,
    fundSol: (address, lamports) => surfnet.fundSol(address, lamports),
    fundUsdc: (owner, amount) => surfnet.fundToken(owner, USDC_MINT, amount, TOKEN_PROGRAM),
    // An upgradeable program executes only once its ProgramData account (the
    // code) is on the fork too; the program account alone resolving made the
    // first settlement fail with InvalidProgramForExecution.
    async awaitProgram(programId, timeoutMs = 15_000) {
      const deadline = Date.now() + timeoutMs;
      const wait = async (what: string, ready: () => Promise<boolean>) => {
        for (;;) {
          surfnet.drainEvents();
          if (await ready()) return;
          if (Date.now() >= deadline) throw new Error(`${what} not resolved from datasource ${datasourceRpc}`);
          await new Promise((r) => setTimeout(r, 500));
        }
      };
      let program: AccountInfo | null = null;
      await wait(`program ${programId}`, async () => {
        program = await getAccount(rpcUrl, programId, true);
        return program?.executable === true;
      });
      const programData = programDataAddress(program!);
      if (programData === null) return;
      surfnet.streamAccount(programData);
      await wait(`program data ${programData} of ${programId}`, async () => {
        // Past the 45-byte ProgramData header, there is code to run.
        const data = await getAccount(rpcUrl, programData, true);
        return data?.data !== undefined && Buffer.from(data.data[0], "base64").length > 45;
      });
    },
    stop: () => surfnet.stop(),
  };

  return api;
}
