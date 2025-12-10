import { sign, verify, type KeyAlgorithm, arrBuftobase64u, b64uToArrBuf, algFromProofType, canonicalize } from "../crypto/index"; // <-- you implement or wrap jose library
import { DidDocument, resolveDid, revokeVCFromIssuer } from "../did/index";
import { isRevokedFromServiceEndpoint } from "./revoke";

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
    credentialStatus?: { id: string, type: string, revocationBitmapIndex: number };
    revocationBitmapIndex?: number;
};

const REVOCATION_FRAGMENT = "#revocation";
const REVOCATION_TYPE = "RevocationBitmap2022";
function revocationStatus(
    issuerDid: string,
    index: number,
): { id: string, type: string, revocationBitmapIndex: number } {
    const serviceDidUrl = `${issuerDid}${REVOCATION_FRAGMENT}`;

    // Theo spec: id là DID URL, type là "RevocationBitmap2022",
    // revocationBitmapIndex là string. :contentReference[oaicite:2]{index=2}
    return {
        id: serviceDidUrl.toString(),
        type: REVOCATION_TYPE,
        revocationBitmapIndex: index,
    };
}

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
        revocationBitmapIndex
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
        ...(revocationBitmapIndex != undefined && revocationBitmapIndex >= 0 && { credentialStatus: revocationStatus(issuer, revocationBitmapIndex) }),
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
        return parentObj === childObj;
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
    delegatorPrivKey: JsonWebKey, expirationDate?: string, revocationBitmapIndex?: number): Promise<VC> {
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
        ...(revocationBitmapIndex != undefined && revocationBitmapIndex >= 0 && { credentialStatus: revocationStatus(parentVC.subject, revocationBitmapIndex) }),
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

export async function isVcRevoked(
    didDocJson: DidDocument,
    credential: VC,
): Promise<boolean> {
    const status = credential.credentialStatus;
    if (!status) {
        return false;
    }
    if (status.type !== REVOCATION_TYPE) {
        throw new Error("VC không dùng RevocationBitmap2022");
    }

    const index = status.revocationBitmapIndex;
    if (!Number.isInteger(index) || index < 0) {
        throw new Error("revocationBitmapIndex không hợp lệ");
    }

    const serviceId = status.id; // bỏ query index nếu có
    const service = (didDocJson.service || []).find(
        (s: any) => s.id === serviceId && s.type === REVOCATION_TYPE,
    );
    if (!service) {
        throw new Error(`Không tìm thấy RevocationBitmap service ${serviceId}`);
    }

    return isRevokedFromServiceEndpoint(service.serviceEndpoint.toString(), index);
}

async function verifySingleVC(
    vc: VC,
    options: { withMetaChecks: boolean }
): Promise<{ didSubject: string, publicKeyJwkIssuer: JsonWebKey }> {
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

    //6. Check revoke
    const isRevoke = await isVcRevoked(didDoc, vc);
    if (isRevoke) {
        throw new Error("Verify Credential: VC is revoked");
    }


    // 7. Metadata checks
    if (options.withMetaChecks) {
        const now = Date.now();
        if (vc.expirationDate && new Date(vc.expirationDate).getTime() < now) {
            throw new Error("Verify Credential: Credential is expired");
        }
        if (new Date(vc.issuanceDate).getTime() > now) {
            throw new Error("Verify Credential: Credential is valid in future");
        }
    }

    return { didSubject: vc.subject, publicKeyJwkIssuer: publicKeyJwk };
}

function validateParentVC(parentVC: VC, vc: VC) {
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

/*
const res = await verifyVC(vc, {protocol: 'http'})
*/
export async function verifyVC(vc: VC): Promise<boolean> {

    await verifySingleVC(vc, { withMetaChecks: true });

    //Check parent VC if any
    const parentVC = vc.credentialSubject.parentVC;
    if (parentVC) {
        const verParent = await verifyVC(parentVC);
        if (!verParent) {
            throw new Error("Verify Credential: Parent Credential is invalid");
        }
        validateParentVC(parentVC, vc);
    }

    return true;
}

export async function getPublickeyIssuerFromVC(vc: VC):
    Promise<{ didSubject: string, publicKeyJwkIssuer: JsonWebKey | null, didOri: string, parentPublicKeyJwkIssuer: JsonWebKey | null }> {
    // verify VC hiện tại nhưng KHÔNG check metadata (y như code cũ)
    const { didSubject, publicKeyJwkIssuer } = await verifySingleVC(vc, { withMetaChecks: false });
    let parentPublicKeyJwkIssuer: JsonWebKey | null = null;
    let didOri = didSubject;

    // Check parent VC nếu có (logic giữ nguyên, vẫn dùng getPublickeyIssuerFromVC đệ quy)
    const parentVC = vc.credentialSubject.parentVC;
    if (parentVC) {
        const parentInfo = await getPublickeyIssuerFromVC(parentVC);
        didOri = parentInfo.didSubject;
        parentPublicKeyJwkIssuer = parentInfo.publicKeyJwkIssuer;
        if (!parentPublicKeyJwkIssuer || !didOri) {
            throw new Error("Verify Credential: Parent Credential is invalid");
        }

        validateParentVC(parentVC, vc);
    }

    return { didSubject, publicKeyJwkIssuer, didOri, parentPublicKeyJwkIssuer };
}

export async function revokeVC(vc: VC, privateKey: JsonWebKey): Promise<DidDocument> {

    if (!vc.credentialStatus) {
        throw new Error("Revoke VC: VC doesn't have credentialStatus");
    }
    
    const index = vc.credentialStatus.revocationBitmapIndex;
    return await revokeVCFromIssuer(vc.issuer, index, privateKey);

    //TODO
    //Must revoke here
}


