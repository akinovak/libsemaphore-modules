import { genRandomIdentity, genIdentityFromSignedMessage } from './strategies';
import * as bigintConversion from 'bigint-conversion';
import { sha256 as _sha256 } from "js-sha256";
import * as ciromlibjs from 'circomlibjs';
import { Identity as _Identity } from '../../types';


const poseidonHash = (data: Array<bigint>): bigint => {
    return ciromlibjs.poseidon(data);
}

class Identity {
    genIdentity(strategy: string = 'random', metadata: any = {}): _Identity {
        if(strategy === 'random') return genRandomIdentity();
        else if (strategy === 'signedMessage') return genIdentityFromSignedMessage(metadata)

        throw new Error('provided strategy is not supported');
    }

    genSecret(identity: _Identity): bigint {
        const secret = [identity.identityNullifier, identity.identityTrapdoor];
        return poseidonHash(secret);
    }

    genIdentityCommitment(identity: _Identity): bigint {
        const secret = [this.genSecret(identity)];
        return poseidonHash(secret);
    }

    serializeIdentity(identity: _Identity): string {
        const data = [
            identity.identityNullifier.toString(16),
            identity.identityTrapdoor.toString(16),
        ]
        return JSON.stringify(data)
    }
    
    unSerializeIdentity(serialisedIdentity: string): _Identity {
        const data = JSON.parse(serialisedIdentity)
        return {
            identityNullifier: bigintConversion.hexToBigint(data[0]),
            identityTrapdoor: bigintConversion.hexToBigint(data[1]),
        }
    }
}

export default new Identity();