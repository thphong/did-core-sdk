import { NotImplementedError } from "../utils/errors";

import { sign, type KeyAlgorithm, base64url } from "../crypto/index"; // <-- you implement or wrap jose library

export type VC = {
    context: string[];
    type: string[];
    issuer: string;
    subject: string;
    issuanceDate: string;
    credentialSubject: Record<string, any>; // claim(s)
    proof?: any;
    expirationDate?: string;          // optional expiry
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
        issuanceDate = new Date().toISOString(),
        expirationDate,
        credentialSubject,
        algorithm = "Ed25519",
    } = params;

    //Build credential payload (W3C standard)
    const vc: VC = {
        context,
        type,
        issuer: issuer,
        issuanceDate: issuanceDate,
        subject: subject,
        credentialSubject: {
            id: subject,
            ...credentialSubject,
        },
        ...(expirationDate && { expirationDate: expirationDate }),
    };

    //Serialize VC to bytes for signing
    const vcBytes = new TextEncoder().encode(JSON.stringify(vc));

    //Sign with vc
    const sigBuf = await sign(vcBytes.buffer, issuerPrivateKeyJwk, algorithm);

    const sigB64 = base64url(sigBuf);

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


/**
 * Create a *delegated* VC derived from a parent VC.
 
const delegateVC = await createDelegatedVC(vc, 'did:web:identity.momo.vn:did', { roles: ["ACCESS_BANK"] }, privateKeyJwk)
*/
export async function createDelegatedVC(parentVC: VC, childSubject: string, claims: Record<string, any>,
    delegatorPrivKey: JsonWebKey): Promise<VC> {
    if (!parentVC) throw new Error("Parent VC is required");
    if (!parentVC.proof) {
        throw new Error("Parent VC must have a proof to allow delegation");
    }

    //TODO
    //Check claims belongs to parentVC.credentialSubject
    //Proof chain from parentVC also

    // VC con do B cấp cho C
    const childVC: VC = {
        context: [...new Set([...parentVC.context, "https://www.w3.org/2018/credentials/v1"])],
        type: [...new Set([...parentVC.type, "DelegatedCredential"])],
        issuer: parentVC.subject,        // B chính là issuer của VC2
        subject: childSubject,              // C là subject mới
        issuanceDate: new Date().toISOString(),
        ...(parentVC.expirationDate && { expirationDate: parentVC.expirationDate }),
        credentialSubject: {
            id: childSubject,
            ...claims,
            delegatedFrom: parentVC.issuer,   // A
        },
    };

    // Serialize và ký bằng private key của B
    const vcBytes = new TextEncoder().encode(JSON.stringify(childVC));
    const sigBuf = await sign(vcBytes.buffer, delegatorPrivKey, childVC.algorithm);
    const sigB64 = base64url(sigBuf);

    // Gắn proof trực tiếp
    childVC.proof = {
        type: (parentVC.algorithm || "Ed25519") === "Ed25519" ? "Ed25519Signature2020" : childVC.algorithm,
        created: childVC.issuanceDate,
        proofPurpose: "delegation",
        verificationMethod: `${parentVC.subject}#keys-1`,  // B's key
        jws: sigB64,
        evidence: {
            delegatedBy: parentVC.issuer,   // A
            delegatedTo: childVC.subject,   // C
        }
    };

    return childVC;
}

export async function verifyVC(_vcId: string): Promise<Boolean> {
    throw new NotImplementedError("verifyVC for both normal VC and DelegatedVC");
}

export async function revokeVC(_vcId: string): Promise<void> {
    throw new NotImplementedError("revokeVC");
}


