import { createPrivateKey, sign } from "node:crypto";
import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const output = args.find((arg) => !arg.startsWith("--"));
const twoSignatures = args.includes("--two-signatures");
const payloadType = "application/vnd.in-toto+json";
const statement = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [
    {
      name: "artifact.bin",
      digest: {
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      },
    },
  ],
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {
    buildDefinition: {
      externalParameters: {
        repository: { url: "https://github.com/example/project" },
      },
    },
    runDetails: { builder: { id: "https://builder.example/id" } },
  },
};
const payload = Buffer.from(JSON.stringify(statement), "utf8");
const pae = Buffer.from(
  `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} ${payload.toString("utf8")}`,
  "utf8",
);
const seed = Buffer.from(
  "9d61b19def fd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".replaceAll(" ", ""),
  "hex",
);
const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = createPrivateKey({
  key: Buffer.concat([pkcs8Prefix, seed]),
  format: "der",
  type: "pkcs8",
});
const secondSeed = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const secondPrivateKey = createPrivateKey({
  key: Buffer.concat([pkcs8Prefix, secondSeed]),
  format: "der",
  type: "pkcs8",
});
const envelope = {
  payloadType,
  payload: payload.toString("base64"),
  signatures: [
    { keyid: "release-key", sig: sign(null, pae, privateKey).toString("base64") },
  ],
};
if (twoSignatures) {
  envelope.signatures.push({
    keyid: "backup-key",
    sig: sign(null, pae, secondPrivateKey).toString("base64"),
  });
}
const text = JSON.stringify(envelope, null, 2) + "\n";
if (output) {
  writeFileSync(output, text, "utf8");
} else {
  process.stdout.write(text);
}
