const Tree = require('incrementalquintree/build/IncrementalQuinTree');
import * as ciromlibjs from 'circomlibjs';
import * as ethers from 'ethers';
import { MerkleProof } from '../../types';

export const SNARK_FIELD_SIZE: bigint = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const ZqField = require('ffjavascript').ZqField;
export const Fq = new ZqField(SNARK_FIELD_SIZE);

type IncrementalQuinTree = any;


export const poseidonHash = (data: Array<bigint>): bigint => {
    return ciromlibjs.poseidon(data);
}

export const genSignalHash = (signal: string): bigint => {
    const converted = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(signal));
    return BigInt(ethers.utils.solidityKeccak256(['bytes'], [converted])) >> BigInt(8);
}

export const genExternalNullifier = (plaintext: string): string => {
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

export const createTree = (depth: number, zeroValue: number | BigInt, leavesPerNode: number): IncrementalQuinTree => {
    return new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, poseidonHash); 
}

export const generateMerkleProof = (depth: number, zeroValue: number | BigInt, leavesPerNode: number, leaves: Array<bigint | string>, leaf: bigint | string): MerkleProof => {
    const tree: IncrementalQuinTree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, poseidonHash);
    const leafIndex = leaves.indexOf(leaf);
    if(leafIndex === -1) throw new Error('Leaf does not exists');
    
    for(const leaf of leaves) {
        tree.insert(leaf);
    }

    const merkleProof = tree.genMerklePath(leafIndex);
    return {
        root: tree.root,
        ...merkleProof
    }
}