import { hexFrom, Transaction, SignerCkbPrivateKey, ClientPublicMainnet, WitnessArgs, hashCkb } from "@ckb-ccc/core";
import { readFileSync } from "fs";
import {
  Resource,
  UnitTestClient,
  Verifier,
} from "mohanson-unittest";

async function main() {
  const prikey = new SignerCkbPrivateKey(new ClientPublicMainnet(), "0x0000000000000000000000000000000000000000000000000000000000000001");
  const pubkey = prikey.publicKey;

  const resource = Resource.default();
  const tx = Transaction.default();

  const cellMetaJsExec = resource.deployCell(
    hexFrom(readFileSync('/home/ubuntu/src/ckb-js-vm/build/ckb-js-vm')), tx, false
  );
  resource.deployCell(
    hexFrom(readFileSync('/home/ubuntu/src/ckb-js-vm/packages/examples/dist/secp256k1_blake160_lock.js')), tx, false
  );
  const dataHash = hashCkb(resource.cells.get(tx.cellDeps.at(-1)!.outPoint)!.outputData);
  cellMetaJsExec.args = hexFrom("0x0000" + dataHash.slice(2) + "00" + hashCkb(pubkey).slice(2, 42))
  const inputCell = resource.mockCell(cellMetaJsExec);
  tx.inputs.push(Resource.createCellInput(inputCell));
  tx.witnesses.push(hexFrom(new WitnessArgs(hexFrom(new Uint8Array(65)), undefined, undefined).toBytes()))

  let mh = await tx.getSignHashInfo(cellMetaJsExec, new UnitTestClient(resource))!;
  let sg = await prikey._signMessage(mh!.message);
  tx.witnesses[0] = hexFrom(new WitnessArgs(sg, undefined, undefined).toBytes())
  const verifier = Verifier.from(resource, tx);
  for (let e of verifier.verify()) {
    console.log(e.stdout.toString())
  }
}

main()
