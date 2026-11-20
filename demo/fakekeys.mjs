// Offline stand-ins for Concordium account keys: a real ed25519 key per demo account and the on-chain
// account info a node would return for it, so the key proof is signed and checked with the real SDK code.
import crypto from "node:crypto";
import { AccountAddress, buildAccountSigner } from "@concordium/web-sdk";

const keys = new Map();
export function keyFor(address) {
  if (!keys.has(address)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const priv = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
    const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    keys.set(address, { priv, pub, signer: buildAccountSigner(priv) });
  }
  return keys.get(address);
}
// What getAccountInfo would answer: one credential, one Ed25519 key, thresholds 1.
export async function fakeAccountInfo(addr) {
  const a = AccountAddress.toBase58(addr);
  return { accountAddress: AccountAddress.fromBase58(a), accountThreshold: 1,
    accountCredentials: { 0: { value: { contents: { credentialPublicKeys: { threshold: 1, keys: { 0: { schemeId: "Ed25519", verifyKey: keyFor(a).pub } } } } } } } };
}
