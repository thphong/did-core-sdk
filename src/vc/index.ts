import { NotImplementedError } from "../utils/errors";

import { sign, type KeyAlgorithm } from "../crypto/index"; // <-- you implement or wrap jose library

export type VC = {
    context: string[];
    type: string[];
    issuer: string;
    subject: string;
    issuanceDate: Date;
    credentialSubject: Record<string, any>; // claim(s)
    proof?: any;
    expirationDate?: Date;          // optional expiry
    algorithm?: KeyAlgorithm;             // e.g. "Ed25519"
};

/*
const vc = await createVC({
            issuer: 'did:web:abc.com:identity',
            subject: 'did:web:identity.hcmut.edu.vn:user:phong',
            credentialSubject: {
                degree: 'master',
                major: 'computer science'
            }
        }, privateKeyJwk);
*/
export async function createVC(params: VC, issuerPrivateKeyJwk: JsonWebKey): Promise<VC> {
    const {
        issuer,
        subject,
        type = ["VerifiableCredential"],
        context = ["https://www.w3.org/2018/credentials/v1"],
        issuanceDate = new Date(),
        expirationDate,
        credentialSubject,
        algorithm = "Ed25519",
    } = params;

    //Build credential payload (W3C standard)
    const vc: any = {
        "@context": context,
        type,
        issuer: issuer,
        issuanceDate: issuanceDate.toISOString(),
        credentialSubject: {
            id: subject,
            ...credentialSubject,
        },
        ...(expirationDate && { expirationDate: expirationDate.toISOString() }),
    };

    //Serialize VC to bytes for signing
    const vcBytes = new TextEncoder().encode(JSON.stringify(vc));

    //Sign with vc
    const sigBuf = await sign(vcBytes.buffer, issuerPrivateKeyJwk, algorithm);

    const sigB64 = btoa(
        String.fromCharCode(...new Uint8Array(sigBuf))
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    //Build proof section
    vc.proof = {
        type: algorithm === "Ed25519" ? "Ed25519Signature2020" : algorithm,
        created: vc.issuanceDate,
        proofPurpose: "assertionMethod",
        verificationMethod: `${issuer}#keys-1`,
        jws: sigB64,
    };

    return vc;
}

export async function createDelegatedVC(_parent: VC, _claims: Record<string, any>): Promise<VC> {
    throw new NotImplementedError("createDelegatedVC");
}

export async function revokeVC(_vcId: string): Promise<void> {
    throw new NotImplementedError("revokeVC");
}
