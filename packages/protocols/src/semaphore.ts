import { ZkProtocol } from "./zk-protocol";
import { genSignalHash, poseidonHash } from "./utils";
import * as ethers from 'ethers';


//TODO create new module just for types
export interface identity {
    identityNullifier: bigint,
    identityTrapdoor: bigint,
}

class Semaphore extends ZkProtocol {
    generateGrothInput(identity: identity, merkleProof: any, externalNullifier: string | bigint, signal: string, shouldHash: boolean = true): any {
        return {
            identity_nullifier: identity.identityNullifier,
            identity_trapdoor: identity.identityTrapdoor,
            identity_path_index: merkleProof.indices,
            path_elements: merkleProof.pathElements,
            external_nullifier: externalNullifier,
            signal_hash: shouldHash ? genSignalHash(signal): signal,
        }
    }

    genNullifierHash(externalNullifier: string | bigint, identityNullifier: string | bigint, nLevels: number): BigInt {
        return poseidonHash([BigInt(externalNullifier), BigInt(identityNullifier), BigInt(nLevels)]);
    }

    genExternalNullifier(plaintext: string): string {
        const _cutOrExpandHexToBytes = (hexStr: string, bytes: number): string => {
            const len = bytes * 2
        
            const h = hexStr.slice(2, len + 2)
            return '0x' + h.padStart(len, '0')
        }
    
        const hashed = ethers.utils.solidityKeccak256(['string'], [plaintext])
        return _cutOrExpandHexToBytes(
            '0x' + hashed.slice(8),
            32,
        )
    }

}

export default new Semaphore();