// Records live Jupiter Swap API V2 /build responses as fixtures for the swap vectors (docs/SWAPS.md).
// Network access: run by hand, rarely, then commit the fixtures. Vectors are generated from the files offline.
// Run: node scripts/record-jupiter.ts
//
// Quotes are anonymous: the taker is the public test-vector vault and the fee owner the public "other" test key,
// so nothing about a real user is sent. Keyless rate limit is 0.5 requests/second, hence the pause.
import { mkdirSync, writeFileSync } from "node:fs";
import { address, base58Encode } from "../src/base58.ts";
import { associatedTokenAddress, TOKEN_2022_PROGRAM, TOKEN_PROGRAM } from "../src/solana.ts";

const TAKER = "4DKubqYmFiXNbWDWMersXVVoynoHpvtuXAunLSrBc1ek"; // common.json vault_address
const FEE_OWNER = "HVmg11y3Sm6N1aMyCK54Q2mWZCggP4WrVPqgnFvRjuHL"; // common.json other_address

const MINTS = {
  SOL: { mint: "So11111111111111111111111111111111111111112", program: TOKEN_PROGRAM },
  USDC: { mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", program: TOKEN_PROGRAM },
  JUP: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", program: TOKEN_PROGRAM },
  PYUSD: { mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", program: TOKEN_2022_PROGRAM },
  POMPOMPURIN: { mint: "EyscKnGPbxVjGx4AgJqpYqtWmtnw2PpzRpvqShBQpump", program: TOKEN_2022_PROGRAM }, // Pump.fun AMM only
} as const;
type Sym = keyof typeof MINTS;

const feeAccount = (sym: Sym) =>
  base58Encode(associatedTokenAddress(address(FEE_OWNER), address(MINTS[sym].mint), MINTS[sym].program));

/** maxAccounts 20 fits a legacy transaction; v1 transactions (SIMD-0385, 4096 bytes) take bigger routes. */
type Case = { name: string; from: Sym; to: Sym; amount: string; feeBps: number; feeIn?: Sym; v1?: boolean; shared?: boolean };
/** Jupiter's instruction discriminators: route_v2 and shared_accounts_route_v2. */
const ROUTE_V2 = "bb64facc31c4af14";
const SHARED_ROUTE_V2 = "d19853937cfed8e9";
const CASES: Case[] = [
  { name: "sol_to_usdc_fee", from: "SOL", to: "USDC", amount: "10000000", feeBps: 50, feeIn: "USDC" },
  { name: "sol_to_usdc_no_fee", from: "SOL", to: "USDC", amount: "10000000", feeBps: 0 },
  { name: "usdc_to_sol_fee_in_input", from: "USDC", to: "SOL", amount: "1000000", feeBps: 50, feeIn: "USDC" },
  { name: "usdc_to_jup_fee", from: "USDC", to: "JUP", amount: "1000000", feeBps: 50, feeIn: "USDC" },
  { name: "sol_to_pyusd_token_2022", from: "SOL", to: "PYUSD", amount: "10000000", feeBps: 50, feeIn: "SOL" },
  { name: "v1_sol_to_pompompurin", from: "SOL", to: "POMPOMPURIN", amount: "10000000", feeBps: 50, feeIn: "SOL", v1: true },
  { name: "v1_pompompurin_to_sol", from: "POMPOMPURIN", to: "SOL", amount: "100000000000", feeBps: 50, feeIn: "SOL", v1: true },
  { name: "v1_sol_to_usdc", from: "SOL", to: "USDC", amount: "10000000", feeBps: 50, feeIn: "USDC", v1: true },
  // Multi-hop routes often come back as shared_accounts_route_v2 (retried until one does).
  { name: "v1_shared_sol_to_jup", from: "SOL", to: "JUP", amount: "10000000", feeBps: 50, feeIn: "SOL", v1: true, shared: true },
  { name: "v1_shared_jup_to_sol", from: "JUP", to: "SOL", amount: "5000000", feeBps: 50, feeIn: "SOL", v1: true, shared: true },
  { name: "v1_shared_sol_to_jup_no_fee", from: "SOL", to: "JUP", amount: "10000000", feeBps: 0, v1: true, shared: true },
];
const only = process.argv.slice(2);

const dir = new URL("../fixtures/jupiter/", import.meta.url);
mkdirSync(dir, { recursive: true });

for (const c of CASES.filter((x) => only.length === 0 || only.includes(x.name))) {
  const query: Record<string, string> = {
    inputMint: MINTS[c.from].mint,
    outputMint: MINTS[c.to].mint,
    amount: c.amount,
    taker: TAKER,
    slippageBps: "50",
    maxAccounts: c.v1 ? "40" : "20",
    transactionVersion: "1",
  };
  if (c.feeBps > 0 && c.feeIn) {
    query.platformFeeBps = String(c.feeBps);
    query.feeAccount = feeAccount(c.feeIn);
  }
  const url = "https://api.jup.ag/swap/v2/build?" + new URLSearchParams(query);
  const want = c.shared ? SHARED_ROUTE_V2 : ROUTE_V2;
  let body: Record<string, unknown> = {};
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    body = (await res.json()) as Record<string, unknown>;
    if (!res.ok || !body.swapInstruction) {
      console.error(`${c.name}: ${res.status} ${JSON.stringify(body).slice(0, 300)}`);
      process.exit(1);
    }
    const data = (body.swapInstruction as { data: string }).data;
    if (Buffer.from(data, "base64").subarray(0, 8).toString("hex") === want) break;
    if (attempt === 10) {
      console.error(`${c.name}: Jupiter didn't return ${c.shared ? "shared_accounts_route_v2" : "route_v2"} in 10 tries`);
      process.exit(1);
    }
    await new Promise((r) => setTimeout(r, 2500));
  }
  delete body.blockhashWithMetadata; // replaced by our durable nonce
  const fixture = {
    recorded_at: new Date().toISOString(),
    source: "GET https://api.jup.ag/swap/v2/build",
    query,
    transaction: c.v1 ? "v1" : "legacy",
    fee: c.feeBps > 0 ? { bps: c.feeBps, owner: FEE_OWNER, mint: MINTS[c.feeIn!].mint, account: query.feeAccount } : null,
    response: body,
  };
  writeFileSync(new URL(`${c.name}.json`, dir), JSON.stringify(fixture, null, 2) + "\n");
  console.log(`recorded fixtures/jupiter/${c.name}.json (${(body.routePlan as unknown[]).length} route steps)`);
  await new Promise((r) => setTimeout(r, 2500));
}
