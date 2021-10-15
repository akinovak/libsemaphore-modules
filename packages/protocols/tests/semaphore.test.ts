import { ZkIdentity } from "../../identity/src";
import { Identity, MerkleProof, IProof } from "../../types";
import { genSignalHash, generateMerkleProof } from "../src/utils";

import { Semaphore } from "../src";

const identityCommitments: Array<bigint> = [];

beforeAll(() => {
    const leafIndex = 3;

    for (let i=0; i<leafIndex;i++) {
      const tmpIdentity = ZkIdentity.genIdentity();
      const tmpCommitment: any = ZkIdentity.genIdentityCommitment(tmpIdentity);
      identityCommitments.push(tmpCommitment);
    }
})

describe("Semaphore", () => {
    describe("Generate and verify proof", () => {
        it("Should generate semaphore proof", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const externalNullifier: string = Semaphore.genExternalNullifier("voting_1");
            const signal: string = '0x111';
            const nullifierHash: bigint = Semaphore.genNullifierHash(externalNullifier, identity.identityNullifier, 20);
            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identity);

            const commitments: Array<bigint> = Object.assign([], identityCommitments);
            commitments.push(identityCommitment);

            const merkleProof: MerkleProof = generateMerkleProof(20, BigInt(0), 5, commitments, identityCommitment);
            const witness: IProof = Semaphore.genWitness(identity, merkleProof, externalNullifier, signal);

            const publicSignals: Array<bigint | string> = [merkleProof.root, nullifierHash, genSignalHash(signal), externalNullifier]
            expect(typeof witness).toBe("object");
        })
    })
})