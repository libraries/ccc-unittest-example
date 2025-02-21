import { hexFrom, numFrom, Transaction, SignerCkbPrivateKey, ClientPublicMainnet, WitnessArgs, hashCkb } from "@ckb-ccc/core";
import { numToBytes } from "ckb-ccc";
import { readFileSync } from "fs";
import {
  Resource,
  Verifier,
} from "mohanson-unittest";

function hash_sighash_all(tx: Transaction, major: number, other: number[]) {
  let b = tx.hash();
  let w = tx.witnesses[major];
  let l = (w.length - 2) / 2;
  b = b + hexFrom(numToBytes(l, 8)).slice(2);
  b = b + hexFrom(w).slice(2);
  for (const e of other.filter((e) => { e < tx.witnesses.length })) {
    const w = tx.witnesses[e];
    const l = (w.length - 2) / 2;
    b = b + hexFrom(numToBytes(l, 8)).slice(2);
    b = b + hexFrom(w).slice(2);
  }
  for (const e of tx.witnesses.slice(tx.inputs.length)) {
    const l = (e.length - 2) / 2;
    b = b + hexFrom(numToBytes(l, 8)).slice(2);
    b = b + hexFrom(e).slice(2);
  }
  return hashCkb(b)
}

async function main() {
  const prikey = new SignerCkbPrivateKey(new ClientPublicMainnet(), "0x0000000000000000000000000000000000000000000000000000000000000001");
  const pubkey = prikey.publicKey;

  const resource = Resource.default();
  const tx = Transaction.default();

  const cellMetaJsExec = resource.deployCell(
    hexFrom(readFileSync('/home/ubuntu/src/ckb-js-vm/build/ckb-js-vm')),
  );
  const cellMetaJsMain = resource.deployCell(
    hexFrom(readFileSync('/home/ubuntu/src/ckb-js-vm/packages/examples/dist/secp256k1_blake160_lock.js')),
  );
  const cellMetaIArgs = hexFrom("0x0000" + cellMetaJsMain.dataHash.slice(2) + "00" + hashCkb(pubkey).slice(2, 42))
  const cellMetaI = resource.createCell(
    numFrom(0),
    resource.createScriptByData(cellMetaJsExec, cellMetaIArgs),
    "0x",
  );

  tx.cellDeps.push(resource.createCellDep(cellMetaJsExec, "code"));
  tx.cellDeps.push(resource.createCellDep(cellMetaJsMain, "code"));
  tx.inputs.push(resource.createCellInput(cellMetaI));
  tx.witnesses.push(hexFrom(new WitnessArgs(hexFrom(new Uint8Array(65)), undefined, undefined).toBytes()))

  const mh = hash_sighash_all(tx, 0, [])
  const sg = await prikey._signMessage(mh)
  tx.witnesses[0] = hexFrom(new WitnessArgs(sg, undefined, undefined).toBytes())
  const verifier = Verifier.from(resource, tx);
  for (let e of verifier.verify()) {
    console.log(e.stdout.toString())
  }
}

main()
