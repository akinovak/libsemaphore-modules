export interface Identity {
    identityNullifier: bigint,
    identityTrapdoor: bigint,
}

export interface IProof {
    proof: any, 
    publicSignals: Array<bigint | string>,
}