// Signs and submits Agent Registry (CIS-8004) updates. The hosted registry MCP builds the exact contract call
// (receive name + parameter bytes + energy); we sign it with our own key and send it to a Concordium node.
import { credentials } from "@grpc/grpc-js";
import { ConcordiumGRPCNodeClient } from "@concordium/web-sdk/nodejs";
import { AccountAddress, AccountTransactionType, CcdAmount, ContractAddress, Energy, Parameter, ReceiveName, TransactionExpiry, TransactionHash, signTransaction } from "@concordium/web-sdk";
import { mcpCall, NETWORK } from "./registry.mjs";

export function nodeClient(url = process.env.GG_CCD_GRPC || (NETWORK === "mainnet" ? "grpc.mainnet.concordium.software:20000" : "grpc.testnet.concordium.com:20000")) {
  const [host, port] = url.replace(/^https?:\/\//, "").split(":");
  return new ConcordiumGRPCNodeClient(host, Number(port || 20000), credentials.createSsl(), { timeout: 30000 });
}

// built = output of a build_* registry tool. Returns {tx, explorer, outcome}.
export async function submitBuilt(built, account, client = nodeClient()) {
  const sender = AccountAddress.fromBase58(account.address);
  const { nonce } = await client.getNextAccountNonce(sender);
  const tx = {
    type: AccountTransactionType.Update,
    header: { sender, nonce, expiry: TransactionExpiry.futureMinutes(5) },
    payload: {
      amount: CcdAmount.zero(),
      address: ContractAddress.create(built.contract_address.index, built.contract_address.subindex),
      receiveName: ReceiveName.fromString(built.receive_name),
      message: Parameter.fromHexString(built.parameter_hex),
      // GG_CCD_MAX_ENERGY caps the energy: the node checks max energy x price against the balance up front (30000 NRG ~ 218 test CCD),
      // while a registry update really uses ~2-2.5k NRG.
      maxContractExecutionEnergy: Energy.create(Number(process.env.GG_CCD_MAX_ENERGY) || built.suggested_energy || 30000),
    },
  };
  const sig = await signTransaction(tx, account.signer);
  const hash = await client.sendAccountTransaction(tx, sig);
  const hex = TransactionHash.toHexString(hash);
  const out = await client.waitForTransactionFinalization(hash, 120000);
  const s = out.summary;
  const ok = s?.type === "accountTransaction" && s?.transactionType !== "failed";
  return { tx: hex, ok, explorer: `https://ccdexplorer.io/${NETWORK}/transaction/${hex}`, summary: s };
}

export const build = (tool, args) => mcpCall(tool, { network: NETWORK, ...args });
