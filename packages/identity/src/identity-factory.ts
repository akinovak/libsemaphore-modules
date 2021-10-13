import { genRandomIdentity, genIdentityFromSignedMessage } from './strategies';
import * as bigintConversion from 'bigint-conversion';
import { sha256 as _sha256 } from "js-sha256";
import * as ciromlibjs from 'circomlibjs';


const poseidonHash = (data: Array<bigint>): bigint => {
    return ciromlibjs.poseidon(data);
}

export interface identity {
    identityNullifier: bigint,
    identityTrapdoor: bigint,
}

class Identity {
    genIdentity(strategy: string = 'random', metadata: any = {}): identity {
        if(strategy === 'random') return genRandomIdentity();
        else if (strategy === 'signedMessage') return genIdentityFromSignedMessage(metadata)

        throw new Error('provided strategy is not supported');
    }

    genSecret(identity: identity): bigint {
        const secret = [identity.identityNullifier, identity.identityTrapdoor];
        return poseidonHash(secret);
    }

    genIdentityCommitment(identity: identity): bigint {
        const secret = [this.genSecret(identity)];
        return poseidonHash(secret);
    }

    serializeIdentity(identity: identity): string {
        const data = [
            identity.identityNullifier.toString(16),
            identity.identityTrapdoor.toString(16),
        ]
        return JSON.stringify(data)
    }
    
    unSerializeIdentity(serialisedIdentity: string): identity {
        const data = JSON.parse(serialisedIdentity)
        return {
            identityNullifier: bigintConversion.hexToBigint(data[0]),
            identityTrapdoor: bigintConversion.hexToBigint(data[1]),
        }
    }
}

export default new Identity();