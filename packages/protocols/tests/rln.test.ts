import * as bigintConversion from 'bigint-conversion';
import { Rln } from "../src";
import { ZkIdentity } from "../../identity/src";
import { Identity, MerkleProof, IProof } from "../../types";
import { genSignalHash, genExternalNullifier, generateMerkleProof } from "../src/utils";
import * as path from "path";
import * as fs from "fs";

const identityCommitments: Array<bigint> = [];

beforeAll(() => {
    const leafIndex = 3;

    for (let i=0; i<leafIndex;i++) {
      const tmpIdentity = ZkIdentity.genIdentity();
      const tmpCommitment: any = ZkIdentity.genIdentityCommitment(tmpIdentity);
      identityCommitments.push(tmpCommitment);
    }
})

describe("Rln", () => {
    describe("Rln functionalities", () => {
        it("Generate rln witness", () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const identitySecret: bigint = ZkIdentity.genSecret(identity);
            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identity);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const signal = 'hey hey';
            const epoch: string = genExternalNullifier('test-epoch');
            const rlnIdentifier: bigint = Rln.genIdentifier();

            const merkleProof: MerkleProof = generateMerkleProof(15, BigInt(0), 5, commitments, identityCommitment);
            const witness: IProof = Rln.genWitness(identitySecret, merkleProof, epoch, signal, rlnIdentifier);

            expect(typeof witness).toBe("object");
        })
        it("Generate rln proof and verify it", async () => {
            /**
             * Compiled RLN circuits are needed to run this test
             */
            const identity: Identity = ZkIdentity.genIdentity();
            const identitySecret: bigint = ZkIdentity.genSecret(identity);

            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identity);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const signal = 'hey hey';
            const signalHash = genSignalHash(signal);
            const epoch: string = genExternalNullifier('test-epoch');
            const rlnIdentifier: bigint = Rln.genIdentifier();


            const merkleProof: MerkleProof = generateMerkleProof(15, BigInt(0), 2, commitments, identityCommitment);
            const witness: IProof = Rln.genWitness(identitySecret, merkleProof, epoch, signal, rlnIdentifier);

            const [y, nullifier] = Rln.calculateOutput(identitySecret, epoch, rlnIdentifier, signalHash);
            const publicSignals = [y, merkleProof.root, nullifier, signalHash, epoch, rlnIdentifier];

            const vkeyPath: string = path.join('./zkeyFiles', 'rln', 'verification_key.json');
            const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
        
            const wasmFilePath: string = path.join('./zkeyFiles', 'rln', 'rln.wasm');
            const finalZkeyPath: string = path.join('./zkeyFiles', 'rln', 'rln_final.zkey');

            const fullProof: IProof = await Rln.genProof(witness, wasmFilePath, finalZkeyPath);
            const res: boolean = await Rln.verifyProof(vKey, { proof: fullProof.proof, publicSignals });

            expect(res).toBe(true);
        })
    })
})