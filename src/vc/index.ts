import { NotImplementedError } from "../utils/errors";

export type VC<T = any> = {
    "@context": string[];
    type: string[];
    issuer: string;
    issuanceDate: string;
    credentialSubject: T;
    proof?: any;
};

export interface CreateVCParams<T = any> {
    subjectDid: string;
    claims: T;
    issuerDid?: string;
}

export async function createVC<T = any>(_p: CreateVCParams<T>): Promise<VC<T>> {
    throw new NotImplementedError("createVC");
}
export async function createDelegatedVC<T = any>(_parent: VC, _claims: T): Promise<VC<T>> {
    throw new NotImplementedError("createDelegatedVC");
}
export async function revokeVC(_vcId: string): Promise<void> {
    throw new NotImplementedError("revokeVC");
}
