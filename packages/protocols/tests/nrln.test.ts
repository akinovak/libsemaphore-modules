import * as bigintConversion from 'bigint-conversion';
import { NRln } from "../src/";
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

describe("NRLn", () => {
    describe("NRln functionalities", () => {
        it("Generate nrln witness", () => {
            const limit = 2;
            const identity: Identity = ZkIdentity.genIdentity();

            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identity);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const signal = 'hey hey';
            const epoch: string = genExternalNullifier('test-epoch');

            const merkleProof: MerkleProof = generateMerkleProof(20, BigInt(0), 5, commitments, identityCommitment);
            const witness: IProof = NRln.genWitness(identity, merkleProof, epoch, signal);

            expect(typeof witness).toBe("object");
        })
        it("Generate nrln proof and verify it", async () => {
            /**
             * Compiled semaphore circuits are needed to run this test
             */
            const limit = 2;
            const identity: Identity = ZkIdentity.genIdentity();

            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identity);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const signal = 'hey hey';
            const signalHash = genSignalHash(signal);
            const epoch: string = genExternalNullifier('test-epoch');

            const merkleProof: MerkleProof = generateMerkleProof(20, BigInt(0), 5, commitments, identityCommitment);
            const witness: IProof = NRln.genWitness(identity, merkleProof, epoch, signal);

            const [y, nullifier] = NRln.calculateOutput([identity.identityTrapdoor, identity.identityNullifier], bigintConversion.hexToBigint(epoch.slice(2)), signalHash, limit);
            const publicSignals = [y, merkleProof.root, nullifier, signalHash, epoch];

            const vkeyPath: string = path.join('./zkeyFiles', 'nrln', 'verification_key.json');
            const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));
        
            const wasmFilePath: string = path.join('./zkeyFiles', 'nrln', 'rln.wasm');
            const finalZkeyPath: string = path.join('./zkeyFiles', 'nrln', 'rln_final.zkey');

            const fullProof: IProof = await NRln.genProof(witness, wasmFilePath, finalZkeyPath);
            const res: boolean = await NRln.verifyProof(vKey, { proof: fullProof.proof, publicSignals });

            expect(res).toBe(true);
        })
    })
})