import { genRandomIdentity, genIdentityFromSignedMessage, genRandomNumber } from './strategies';
import * as bigintConversion from 'bigint-conversion';
import { sha256 as _sha256 } from "js-sha256";
import * as ciromlibjs from 'circomlibjs';
import { Identity } from '../../types';


const poseidonHash = (data: Array<bigint>): bigint => {
    return ciromlibjs.poseidon(data);
}

class ZkIdentity {
    genIdentity(strategy: string = 'random', metadata: any = {}): Identity {
        if(strategy === 'random') return genRandomIdentity();
        else if (strategy === 'signedMessage') return genIdentityFromSignedMessage(metadata)

        throw new Error('provided strategy is not supported');
    }

    genSecretFromIdentity(identity: Identity): bigint[] {
        return [identity.identityNullifier, identity.identityTrapdoor];
    }

    genRandomSecret(parts: number = 2): bigint[] {
        const secret: bigint[] = [];
        for(let i = 0; i< parts; i++) {
            secret.push(genRandomNumber());
        }
        return secret
    }

    genIdentityCommitment(secret: bigint[]): bigint {
        const secretHash = poseidonHash(secret);
        return poseidonHash([secretHash]);
    }


    serializeIdentity(identity: Identity): string {
        const data = [
            identity.identityNullifier.toString(16),
            identity.identityTrapdoor.toString(16),
        ]
        return JSON.stringify(data)
    }
    
    unSerializeIdentity(serialisedIdentity: string): Identity {
        const data = JSON.parse(serialisedIdentity)
        return {
            identityNullifier: bigintConversion.hexToBigint(data[0]),
            identityTrapdoor: bigintConversion.hexToBigint(data[1]),
        }
    }
}

export default new ZkIdentity();