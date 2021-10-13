const { groth16 } = require('snarkjs');
import { SNARK_FIELD_SIZE } from "./utils";

export interface IProof {
    proof: any, 
    publicSignals: Array<bigint | string>,
}

export class ZkProtocol {

    genWitnessAndProof(grothInput: any, wasmFilePath: string, finalZkeyPath: string): Promise<IProof> {
        return groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath);
    }

    verifyProof(vKey: string, fullProof: IProof): Promise<boolean> {
        const { proof, publicSignals } = fullProof;
        return groth16.verify(vKey, publicSignals, proof)
    }

    packToSolidityProof(fullProof: IProof) {
        const { proof, publicSignals } = fullProof;
    
        return {
            a: proof.pi_a.slice(0, 2),
            b: proof.pi_b
                .map((x:any) => x.reverse())
                .slice(0, 2),
            c: proof.pi_c.slice(0, 2),
            inputs: publicSignals.map((x:any) => {
                x = BigInt(x);
                return (x % SNARK_FIELD_SIZE).toString()
            })
        };
    }
    
}