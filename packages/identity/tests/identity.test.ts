import { ZkIdentity } from "../src";
import { Identity } from "../../types";

describe("Semaphore identity", () => {
    describe("Create identity", () => {
        it("Should create a Semaphore identity", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            expect(typeof identity).toEqual("object")
        })
        it("Should generate identity secret", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const identitySecret: bigint = ZkIdentity.genSecret(identity);
            expect(typeof identitySecret).toEqual("bigint")
        })
        it("Should generate identity commitment", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const identityCommitment: bigint = ZkIdentity.genIdentityCommitment(identity);
            expect(typeof identityCommitment).toEqual("bigint")
        })
        it("Should serialize identity", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const serialized: string = ZkIdentity.serializeIdentity(identity);
            expect(typeof serialized).toEqual("string")
        })
        it("Should unserialize identity", async () => {
            const identity: Identity = ZkIdentity.genIdentity();
            const serialized: string = ZkIdentity.serializeIdentity(identity);
            const unserialized: Identity = ZkIdentity.unSerializeIdentity(serialized);
            expect(unserialized).toStrictEqual(identity)
        })
    })
})