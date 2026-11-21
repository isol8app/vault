// Writes the test vectors to protocol/vectors/. Run: npm run vectors
import { mkdirSync, writeFileSync } from "node:fs";
import { buildVectors } from "../src/vectors.ts";

const dir = new URL("../vectors/", import.meta.url);
mkdirSync(dir, { recursive: true });
for (const [file, data] of Object.entries(buildVectors())) {
  writeFileSync(new URL(file, dir), JSON.stringify(data, null, 2) + "\n");
  console.log(`wrote vectors/${file}`);
}
