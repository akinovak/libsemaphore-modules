import { ZkProtocol } from "./zk-protocol";
import { genSignalHash, poseidonHash } from "./utils";
import { SNARK_FIELD_SIZE } from "./utils";

const ZqField = require('ffjavascript').ZqField;
const Fq = new ZqField(SNARK_FIELD_SIZE);

//TODO create new module just for types
export interface identity {
    identityNullifier: bigint,
    identityTrapdoor: bigint,
}

class NRln extends ZkProtocol {
    generateGrothInput(identity: identity, merkleProof: any, epoch: string | bigint, signal: string, rlnIdentifier: bigint, shouldHash: boolean = true): any {
        return {
            identity_secret: poseidonHash([identity.identityTrapdoor, identity.identityNullifier]),
            path_elements: merkleProof.pathElements,
            identity_path_index: merkleProof.indices,
            x: shouldHash ? genSignalHash(signal): signal,
            epoch,
            rln_identifier: rlnIdentifier,
        }
    }

    //TODO add rln identifier
    calculateOutput(identitySecret: Array<bigint>, epoch: bigint, x:bigint, limit: number): Array<bigint> {
        const a0 = poseidonHash(identitySecret);

        const coeffs: Array<bigint> = [];
        let tmpX = x;

        coeffs.push(poseidonHash([identitySecret[0], epoch]));
        let y:bigint = Fq.add(Fq.mul(coeffs[0], tmpX), a0);

        for(let i = 1; i < limit; i++) {   
            tmpX = Fq.mul(x, tmpX);

            coeffs.push(poseidonHash([identitySecret[i], epoch]));
            y = Fq.add(y, Fq.mul(coeffs[i], tmpX));
        }

        const nullifier: bigint = this.genNullifier(coeffs);
        return [y, nullifier];
    }

    genNullifier(coeffs: Array<bigint>): bigint {
        return poseidonHash(coeffs);
    }

    retrievePrivateKey(xs: Array<bigint>, ys: Array<bigint>): bigint {
        if(xs.length !== ys.length) throw new Error('x and y arrays must be of same size');
        const numOfPoints: number = xs.length;
        let f0: bigint = BigInt(0);
        for(let i = 0; i < numOfPoints; i++) {
            let p: bigint = BigInt(1);
            for(let j = 0; j < numOfPoints; j++) {
                if(j !== i) {
                    p = Fq.mul(p, Fq.div(xs[j], Fq.sub(xs[j], xs[i])))
                }
            }
            f0 = Fq.add(f0, Fq.mul(ys[i], p));
        } 
        return f0;
    }

}

export default new NRln();