import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";
import { NoctweaveOQSWasmAdapter } from "../src/index.js";

const wasmModulePath = new URL("../wasm/dist/noctweave_oqs.js", import.meta.url);
const hasBuiltWasm = existsSync(wasmModulePath);

test("built liboqs wasm module performs ML-KEM and ML-DSA operations", { skip: !hasBuiltWasm }, async () => {
  const oqsFactory = (await import(wasmModulePath)).default;
  const adapter = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);

  const profile = adapter.profile();
  assert.equal(profile.kem.algorithm, "ML-KEM-768");
  assert.equal(profile.signature.algorithm, "ML-DSA-65");

  const result = adapter.selfTest();
  assert.equal(result.kemSharedSecretsMatch, true);
  assert.equal(result.signatureVerified, true);
});
