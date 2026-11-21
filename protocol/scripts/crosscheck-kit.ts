// Cross-checks the dependency-free implementation against @solana/kit, an independent implementation.
// Run: npm install --no-save @solana/kit && npm run crosscheck
// (or KIT=/path/to/@solana/kit/dist/index.node.mjs npm run crosscheck, for a copy installed elsewhere).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { base58Encode } from "../src/base58.ts";
import { fromHex, toHex } from "../src/bytes.ts";
import { APPLICATION_DOMAIN, offchainMessageV0 } from "../src/pairing.ts";
import { ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM, TOKEN_2022_PROGRAM, associatedTokenAddress, createWithSeed } from "../src/solana.ts";

const kitPath = process.env.KIT
  ? new URL(process.env.KIT, "file:///").href
  : new URL("../node_modules/@solana/kit/dist/index.node.mjs", import.meta.url).href;
const kit = await import(kitPath);
const load = (file: string) => JSON.parse(readFileSync(new URL(`../vectors/${file}`, import.meta.url), "utf8"));
const common = load("common.json");
let checks = 0;

// 1. Off-chain message bytes for the pairing statement.
const pairing = load("pairing.json");
const kitOffchain = kit.getOffchainMessageV0Encoder().encode({
  version: 0,
  applicationDomain: base58Encode(APPLICATION_DOMAIN),
  requiredSignatories: [{ address: common.vault_address }],
  content: { format: 0, text: pairing.statement },
});
assert.equal(toHex(new Uint8Array(kitOffchain)), pairing.offchain_message_hex);
assert.equal(toHex(offchainMessageV0(pairing.statement, fromHex(common.vault_pubkey_hex))), pairing.offchain_message_hex);
checks++;

// 2. Every compiled message decodes with kit and re-encodes to identical bytes.
const decoder = kit.getCompiledTransactionMessageDecoder();
const encoder = kit.getCompiledTransactionMessageEncoder();
for (const c of load("transactions.json")) {
  if (c.name.startsWith("decline_malformed")) continue; // deliberately invalid bytes
  const bytes = fromHex(c.message_hex);
  const decoded = decoder.decode(bytes);
  assert.equal(toHex(new Uint8Array(encoder.encode(decoded))), c.message_hex, c.name);
  assert.equal(decoded.staticAccounts[0], c.request.signer, `${c.name}: fee payer first`);
  if (c.name === "decline_lookup_tables") assert.equal(decoded.addressTableLookups?.length, 1, c.name);
  checks++;
}

// 3. Associated token addresses (PDAs) match kit.
const owners = [common.vault_address, common.recipient_address];
const mints: [string, Uint8Array][] = [[common.mint_address, TOKEN_PROGRAM], [common.token_2022_mint_address, TOKEN_2022_PROGRAM]];
const enc = kit.getAddressEncoder();
for (const owner of owners) {
  for (const [mint, program] of mints) {
    const [pda] = await kit.getProgramDerivedAddress({
      programAddress: base58Encode(ASSOCIATED_TOKEN_PROGRAM),
      seeds: [enc.encode(owner), program, enc.encode(mint)],
    });
    assert.equal(base58Encode(associatedTokenAddress(fromHex(toHex(new Uint8Array(enc.encode(owner)))), fromHex(toHex(new Uint8Array(enc.encode(mint)))), program)), pda);
    checks++;
  }
}

// 4. Nonce account address from createAccountWithSeed.
const withSeed = await kit.createAddressWithSeed({
  baseAddress: common.vault_address,
  programAddress: base58Encode(SYSTEM_PROGRAM),
  seed: common.nonce_account.seed,
});
assert.equal(withSeed, common.nonce_account.address);
assert.equal(base58Encode(createWithSeed(fromHex(common.vault_pubkey_hex), common.nonce_account.seed, SYSTEM_PROGRAM)), withSeed);
checks++;

console.log(`crosscheck against @solana/kit: ${checks} checks passed`);
