import { sign, verify, type KeyAlgorithm, base64url } from "../crypto/index";
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
    const vpBytes = new TextEncoder().encode(JSON.stringify({ ...vp, nonce }));

    const sigBuf = await sign(vpBytes.buffer, holderPrivateKeyJwk, algorithm);

    const sigB64 = base64url(sigBuf);

    vp.proof = {
        type: algorithm + "Signature2020",
        created: new Date().toISOString(),
        proofPurpose: "authentication",
        verificationMethod: `${holderDid}#key-1`,
        challenge: nonce,
        jws: sigB64,
    };

    return vp;
}

function b64urlToU8(b64url: string): Uint8Array {
    const pad = (s: string) => s + "===".slice((s.length + 3) % 4);
    const b64 = pad(b64url.replace(/-/g, "+").replace(/_/g, "/"));
    const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

/*
"verificationMethod": [
        {
            "id": "did:web:localhost:5173:did#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:localhost:5173:did",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "dndYUDi2-EmghxLqvTmvWXJeXALhA4xKwo1vE8NYIiE"
            }
        }
    ],
*/
function algFromProofType(proofType: string): KeyAlgorithm {
    // We produced types like "Ed25519Signature2020"
    if (/^Ed25519Signature2020$/i.test(proofType) || !proofType) return "Ed25519";
    const res = 'ES256' // extend here for ES256K, etc.
    return res;
}

export async function verifyVP(vp: VP): Promise<boolean> {
    try {
        // Basic structural checks
        if (!vp?.proof) return false;
        const { proof } = vp;
        if (!proof.jws) return false;

        // Accept only the flow we signed with
        const alg = algFromProofType(proof.type);

        // Resolve DID Document from holder DID
        const didDoc = await resolveDid(vp.holder!);
        if (!didDoc) return false;

        // Resolve the public key JWK
        const publicKeyJwk = didDoc.verificationMethod?.[0]?.publicKeyJwk;
        if (!publicKeyJwk) return false;

        // Rebuild the exact payload used for signing: VP fields + nonce (challenge)
        const payload: VP = {
            context: vp.context,
            type: vp.type,
            verifiableCredential: vp.verifiableCredential,
            holder: vp.holder,
            challenge: proof.challenge ?? "",
        };
        const data = new TextEncoder().encode(JSON.stringify(payload));

        const sig = b64urlToU8(proof.jws);
        const ok = await verify(data, sig, publicKeyJwk, alg);
        if (!ok) return false;

        if (vp.verifiableCredential.length === 0) return false;

        for (const vc of vp.verifiableCredential) {
            const ok = await verifyVC(vc);
            if (!ok) return false;
        }

        return true;
    } catch {
        return false;
    }
}
