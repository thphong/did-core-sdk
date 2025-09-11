import { NotImplementedError } from "../utils/errors";

export interface VP {
    "@context": string[];
    type: string[];
    verifiableCredential: any[];
    proof?: any;
}

export async function createVP(_vcs: any[], _holderDid: string): Promise<VP> {
    throw new NotImplementedError("createVP");
}
export async function verifyVP(_vp: VP): Promise<boolean> {
    throw new NotImplementedError("verifyVP");
}
