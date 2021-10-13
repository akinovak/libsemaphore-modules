import * as crypto from 'crypto';
import * as bigintConversion from 'bigint-conversion';
import { sha256 as _sha256 } from "js-sha256";

interface identity {
    identityNullifier: bigint,
    identityTrapdoor: bigint,
}

const genRandomIdentity = (): identity => {
    const genRandomBuffer = (numBytes: number = 32): Buffer => {
        return crypto.randomBytes(numBytes)
    }

    return {
        identityNullifier: bigintConversion.bufToBigint(genRandomBuffer(31)),
        identityTrapdoor: bigintConversion.bufToBigint(genRandomBuffer(31)),
    }
}

const genIdentityFromSignedMessage = (metadata: any): identity => {
    const sha256 = (message: string): string => {
        const hash = _sha256.create()
        hash.update(message)
        return hash.hex()
    }

    const { signedMessage } = metadata;

    const messageHash = sha256(signedMessage)
    const identityNullifier = bigintConversion.hexToBigint(sha256(`${messageHash}identity_nullifier`))
    const identityTrapdoor = bigintConversion.hexToBigint(sha256(`${messageHash}identity_trapdoor`))

    return {
        identityTrapdoor,
        identityNullifier
    }
}

export {
    genRandomIdentity, 
    genIdentityFromSignedMessage
}