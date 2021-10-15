import { ZkIdentity } from "../../identity/src";
import { Identity, MerkleProof, IProof } from "../../types";
import { genSignalHash, genExternalNullifier, generateMerkleProof } from "../src/utils";
import * as path from "path";
import * as fs from "fs";

import { Semaphore } from "../src";

const identityCommitments: Array<bigint> = [];

beforeAll(() => {
    const leafIndex = 3;

    for (let i=0; i<leafIndex;i++) {
      const tmpIdentity = ZkIdentity.genIdentity();
      const tmpIdentitySecret: bigint[] = ZkIdentity.genSecretFromIdentity(tmpIdentity);
      const tmpCommitment: bigint = ZkIdentity.genIdentityCommitment(tmpIdentitySecret);
      identityCommitments.push(tmpCommitment);
    }
})

describe("Semaphore", () => {
    describe("Generate and verify proof", () => {
        it("Should generate semaphore witness", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const externalNullifier: string = genExternalNullifier("voting_1");
            const signal: string = '0x111';
            const identitySecret: bigint[] = ZkIdentity.genSecretFromIdentity(identity);
            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identitySecret);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const merkleProof: MerkleProof = generateMerkleProof(20, BigInt(0), 5, commitments, identityCommitment);
            const witness: IProof = Semaphore.genWitness(identity, merkleProof, externalNullifier, signal);

            expect(typeof witness).toBe("object");
        })
        it("Should generate semaphore full proof", async () => {
            /**
             * Compiled semaphore circuits are needed to run this test
             */
            const identity: Identity = ZkIdentity.genIdentity();
            const externalNullifier: string = genExternalNullifier("voting_1");
            const signal: string = '0x111';
            const nullifierHash: bigint = Semaphore.genNullifierHash(externalNullifier, identity.identityNullifier, 20);
            const identitySecret: bigint[] = ZkIdentity.genSecretFromIdentity(identity);
            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identitySecret);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const merkleProof: MerkleProof = generateMerkleProof(20, BigInt(0), 5, commitments, identityCommitment);
            const witness: IProof = Semaphore.genWitness(identity, merkleProof, externalNullifier, signal);

            const publicSignals: Array<bigint | string> = [merkleProof.root, nullifierHash, genSignalHash(signal), externalNullifier];

            const vkeyPath: string = path.join('./zkeyFiles', 'semaphore', 'verification_key.json');
            const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
        
            const wasmFilePath: string = path.join('./zkeyFiles', 'semaphore', 'semaphore.wasm');
            const finalZkeyPath: string = path.join('./zkeyFiles', 'semaphore', 'semaphore_final.zkey');

            const fullProof: IProof = await Semaphore.genProof(witness, wasmFilePath, finalZkeyPath);
            const res: boolean = await Semaphore.verifyProof(vKey, { proof: fullProof.proof, publicSignals });

            expect(res).toBe(true);
        })
    })
})