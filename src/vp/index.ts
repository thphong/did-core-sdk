import { sign, verify, type KeyAlgorithm, base64url, b64urlToArrayBuffer, algFromProofType, canonicalize } from "../crypto/index";
import { resolveDid } from "../did/index";
import { verifyVC } from "../vc/index";

export interface VP {
    context: string[];
    type: string[];
    verifiableCredential: any[];
    challenge?: string;
    holder: string;       // the DID of the presenter    
    proof?: {
        type: string;                 // e.g., "Ed25519Signature2020"
        created: string;
        proofPurpose: string;         // e.g., "authentication"
        verificationMethod: string;
        challenge?: string;           // nonce
        jws: string;                  // base64url signature over payload+nonce
    };
}

/*
const nonce = crypto.getRandomValues(new Uint32Array(1))[0].toString();
const vp = await createVP([vc], 'did:web:localhost:5173:did:phong', privateKeyJwk, nonce)
*/
export async function createVP(
    vcs: any[],
    holderDid: string,
    holderPrivateKeyJwk: JsonWebKey,
    nonce: string,
    algorithm: KeyAlgorithm = "Ed25519"
): Promise<VP> {
    // Build the VP payload    
    nonce = nonce ?? "";

    const vp: VP = {
        context: ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiablePresentation"],
        verifiableCredential: vcs,
        holder: holderDid,
        challenge: nonce
    };

    //Canonicalize / serialize for signing
    const vpBytes = new TextEncoder().encode(canonicalize(vp));

    const sigBuf = await sign(vpBytes.buffer, holderPrivateKeyJwk, algorithm);

    const sigB64 = base64url(sigBuf);

    vp.proof = {
        type: algorithm + "Signature2020",
        created: new Date().toISOString(),
        proofPurpose: "authentication",
        verificationMethod: `${holderDid}#keys-1`,
        challenge: nonce,
        jws: sigB64,
    };

    return vp;
}

/*
const nonce = '1937849724';
const res = await verifyVP(vp, 'did:web:localhost:5173:did:phong', 'did:web:localhost:5173:did:bank', nonce)

const nonce = '3265573931';
const res = await verifyVP(vp, 'did:web:localhost:5173:did:momo', 'did:web:localhost:5173:did:phong', nonce, 'did:web:localhost:5173:did:bank')
*/
export async function verifyVP(vp: VP, holderDid: string, issuerDid: string, nonce: string, parentIssuerDid?: string): Promise<boolean> {
    try {
        if (!vp?.proof?.jws) return false;
        const alg = algFromProofType(vp.proof.type);
        const didDoc = await resolveDid(vp.holder, { protocol: 'http' });
        if (!didDoc) return false;

        const publicKeyJwk = didDoc.verificationMethod?.[0]?.publicKeyJwk;
        if (!publicKeyJwk) return false;

        // Rebuild the EXACT payload that was signed
        const payload: VP = {
            context: vp.context,
            type: vp.type,
            verifiableCredential: vp.verifiableCredential,
            holder: holderDid,
            challenge: nonce ?? "",
        };
        const data = new TextEncoder().encode(canonicalize(payload)).buffer; // Uint8Array

        const sig = b64urlToArrayBuffer(vp.proof.jws); // ArrayBuffer

        const ok = await verify(data, sig, publicKeyJwk, alg);
        if (!ok) return false;

        if (!vp.verifiableCredential?.length) return false;

        for (const vc of vp.verifiableCredential) {
            const okVC = await verifyVC(vc);
            if (!okVC) return false;
            if (vc.subject != holderDid) return false;
            if (vc.issuer != issuerDid) return false;
            const parentVC = vc.credentialSubject.parentVC;
            if (parentVC) {
                if (parentVC.issuer != parentIssuerDid) return false;
            }
        }
        return true;
    } catch {
        return false;
    }
}