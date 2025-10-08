import { NotImplementedError } from "../utils/errors";

import { sign, verify, type KeyAlgorithm, arrBuftobase64u, b64uToArrBuf, algFromProofType, canonicalize } from "../crypto/index"; // <-- you implement or wrap jose library
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
                roles: {
                    READ_BANK_ACCOUNT: 'Allow to read account balance',
                    MAKE_TRANSACTION: 'Allow to make a transaction'
                }
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

    const sigB64 = arrBuftobase64u(sigBuf);

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

function checkSubObject(parentObj: any, childObj: any): boolean {
    if (typeof parentObj !== "object" || typeof childObj !== "object" || parentObj === null || childObj === null) {
        return false;
    }

    for (const key of Object.keys(childObj)) {
        if (!(key in parentObj)) {
            return false; // key missing in parent
        }
        if (parentObj[key] !== childObj[key]) {
            return false; // value mismatch
        }
    }

    return true;
}

/**
 * Create a *delegated* VC derived from a parent VC.
const res = await createDelegatedVC(vc, 'did:web:localhost:5173:did:momo', {
            roles: {
                READ_BANK_ACCOUNT: 'Allow to read account balance'
            }
        }, privateKeyJwk, newExpirationDate);
*/
export async function createDelegatedVC(parentVC: VC, childSubject: string, claims: Record<string, any>,
    delegatorPrivKey: JsonWebKey, expirationDate?: string): Promise<VC> {
    if (!parentVC) throw new Error("Parent VC is required");
    if (!parentVC.proof) {
        throw new Error("Parent VC must have a proof to allow delegation");
    }

    for (const key of Object.keys(claims)) {
        if (!checkSubObject(parentVC.credentialSubject[key], claims[key])) {
            throw new Error("Parent VC's credentialSubject must contains all info for claims");
        }
    }

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
    const sigB64 = arrBuftobase64u(sigBuf);

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
const res = await verifyVC(vc, {protocol: 'http'})
*/
export async function verifyVC(vc: VC): Promise<boolean> {
    if (!vc || !vc.proof) {
        throw new Error("Verify Credential: Proof is empty");
    }

    const { proof } = vc;

    // Resolve issuer DID Document
    const didDoc = await resolveDid(vc.issuer);
    if (!didDoc) {
        throw new Error("Verify Credential: Can't resolve issuer did");
    }

    // Locate verification method
    const vm = didDoc.verificationMethod?.find(
        (m: any) => m.id === proof.verificationMethod
    );

    if (!vm || !vm.publicKeyJwk) {
        throw new Error("Verify Credential: Can't find public key from verification method");
    }

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
    const sig = b64uToArrBuf(proof.jws);

    // 5. Verify signature
    const alg = algFromProofType(proof.type);
    const valid = await verify(data, sig, publicKeyJwk, alg);
    if (!valid) {
        throw new Error("Verify Credential: Proof is invalid");
    }

    // 6. Metadata checks
    const now = Date.now();
    if (vc.expirationDate && new Date(vc.expirationDate).getTime() < now) {
        throw new Error("Verify Credential: Credential is expired");
    }
    if (new Date(vc.issuanceDate).getTime() > now) {
        throw new Error("Verify Credential: Credential is valid in future");
    }

    //Check parent VC if any
    const parentVC = vc.credentialSubject.parentVC;
    if (parentVC) {
        const verParent = await verifyVC(parentVC);
        if (!verParent) {
            throw new Error("Verify Credential: Parent Credential is invalid");
        }

        if (parentVC.subject != vc.issuer) {
            throw new Error("Verify Credential: Parent Credential is not issued for holder");
        }

        for (const key of Object.keys(vc.credentialSubject)) {
            if (key != "id" && key != "parentVC") {
                if (!checkSubObject(parentVC.credentialSubject[key], vc.credentialSubject[key])) {
                    throw new Error("Parent VC's credentialSubject must contains all info for claims");
                }
            }
        }
    }

    return true;
}

export async function revokeVC(vc: VC): Promise<void> {
    throw new NotImplementedError("revokeVC");
}


