import { NotImplementedError } from "../utils/errors";

import { sign, verify, type KeyAlgorithm, base64url, b64urlToArrayBuffer, algFromProofType, canonicalize } from "../crypto/index"; // <-- you implement or wrap jose library
import { resolveDid } from "../did/index";

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
const now = new Date();
        const nextMonth = new Date(now);
        nextMonth.setMonth(nextMonth.getMonth() + 1);

        const vc = await createVC({
            issuer: 'did:web:localhost:5173:did:bank',
            subject: 'did:web:localhost:5173:did:phong',
            expirationDate: nextMonth.toISOString(),
            credentialSubject: {
                roles: ['READ_BANK_ACCOUNT', 'MAKE_TRANSACTION']
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
    const vcBytes = new TextEncoder().encode(canonicalize(vc));

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
 
const delegatedVC = await createDelegatedVC(vc, 'did:web:localhost:5173:did:momo', { roles: ['READ_BANK_ACCOUNT'] }, privateKeyJwk, newExpirationDate)
*/
export async function createDelegatedVC(parentVC: VC, childSubject: string, claims: Record<string, any>,
    delegatorPrivKey: JsonWebKey, expirationDate?: string): Promise<VC> {
    if (!parentVC) throw new Error("Parent VC is required");
    if (!parentVC.proof) {
        throw new Error("Parent VC must have a proof to allow delegation");
    }

    //TODO
    //Check claims belongs to parentVC.credentialSubject

    // VC con do B cấp cho C
    const childVC: VC = {
        context: [...new Set([...parentVC.context, "https://www.w3.org/2018/credentials/v1"])],
        type: [...new Set([...parentVC.type, "DelegatedCredential"])],
        issuer: parentVC.subject,
        subject: childSubject,
        issuanceDate: new Date().toISOString(),
        ...((expirationDate || parentVC.expirationDate) && { expirationDate: expirationDate || parentVC.expirationDate }),
        credentialSubject: {
            id: childSubject,
            ...claims,
            parentVC: parentVC,
        },
    };

    // Serialize và ký bằng private key của B
    const vcBytes = new TextEncoder().encode(canonicalize(childVC));

    const sigBuf = await sign(vcBytes.buffer, delegatorPrivKey, childVC.algorithm);
    const sigB64 = base64url(sigBuf);

    // Gắn proof trực tiếp
    childVC.proof = {
        type: (parentVC.algorithm || "Ed25519") === "Ed25519" ? "Ed25519Signature2020" : childVC.algorithm,
        created: childVC.issuanceDate,
        proofPurpose: "delegation",
        verificationMethod: `${parentVC.subject}#keys-1`,  // B's key
        jws: sigB64
    };

    return childVC;
}
/*
const res = await verifyVC(vc)
*/
export async function verifyVC(vc: VC): Promise<boolean> {
    try {
        if (!vc || !vc.proof) return false;

        const { proof } = vc;

        // Resolve issuer DID Document
        const didDoc = await resolveDid(vc.issuer, { protocol: 'http' });
        if (!didDoc) return false;

        // Locate verification method
        const vm = didDoc.verificationMethod?.find(
            (m: any) => m.id === proof.verificationMethod
        );

        if (!vm || !vm.publicKeyJwk) return false;

        const publicKeyJwk = vm.publicKeyJwk;

        // Rebuild payload (exclude proof)
        const payload: VC = {
            context: vc.context,
            type: vc.type,
            issuer: vc.issuer,
            issuanceDate: vc.issuanceDate,
            subject: vc.subject,
            credentialSubject: vc.credentialSubject,
            ...(vc.expirationDate && { expirationDate: vc.expirationDate })
        };
        const data = new TextEncoder().encode(canonicalize(payload)).buffer;

        // 4. Extract signature
        const sig = b64urlToArrayBuffer(proof.jws);

        // 5. Verify signature
        const alg = algFromProofType(proof.type);
        const valid = await verify(data, sig, publicKeyJwk, alg);
        if (!valid) return false;

        // 6. Metadata checks
        const now = Date.now();
        if (vc.expirationDate && new Date(vc.expirationDate).getTime() < now) {
            return false; // expired
        }
        if (new Date(vc.issuanceDate).getTime() > now) {
            return false; // issued in the future
        }

        //Check parent VC if any
        const parentVC = vc.credentialSubject.parentVC;
        if (parentVC) {
            const verParent = await verifyVC(parentVC);
            if (!verParent) return false;
            if (parentVC.subject != vc.issuer) return false;

            //TODO: Check in scope, roles in vc.credentialSubject.roles should be subset of parentVC.credentialSubject.roles
        }

        return true;
    } catch (err) {
        console.error("verifyVC error:", err);
        return false;
    }
}

export async function revokeVC(_vcId: string): Promise<void> {
    throw new NotImplementedError("revokeVC");
}


