import { NotImplementedError } from "../utils/errors";

export type KeyAlgorithm = "Ed25519" | "ES256";

export interface KeyPair {
    algorithm: KeyAlgorithm;
    publicKeyJwk: JsonWebKey;
    privateKeyJwk?: JsonWebKey;
}

function toArrayBuffer(data: BufferSource): ArrayBuffer {
    if (data instanceof ArrayBuffer) return data;

    // Covers all ArrayBufferView types (TypedArrays, DataView)
    if (ArrayBuffer.isView(data)) {
        const u8 =
            data instanceof Uint8Array
                ? data
                : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        // Always copy into a fresh ArrayBuffer (avoids SharedArrayBuffer + typing issues)
        const ab = new ArrayBuffer(u8.byteLength);
        new Uint8Array(ab).set(u8);
        return ab;
    }

    // Last resort: try to construct a Uint8Array and copy
    const u8 = new Uint8Array(data as ArrayBufferLike);
    const ab = new ArrayBuffer(u8.byteLength);
    new Uint8Array(ab).set(u8);
    return ab;
}

async function getSubtle(): Promise<SubtleCrypto> {
    if (typeof globalThis !== "undefined" && (globalThis as any).crypto?.subtle) {
        return (globalThis as any).crypto.subtle as SubtleCrypto;
    }
    try {
        const nodeCrypto: typeof import("node:crypto") = await import("node:crypto");
        if (nodeCrypto.webcrypto?.subtle) return nodeCrypto.webcrypto.subtle as SubtleCrypto;
    } catch { /* ignore */ }
    throw new Error("WebCrypto SubtleCrypto is not available in this runtime.");
}

//Sample call: await createKeyPair();
export async function createKeyPair(_alg: KeyAlgorithm = "Ed25519"): Promise<KeyPair> {
    const alg = _alg ?? "Ed25519";

    // Get a SubtleCrypto instance for browser or Node
    const subtle = await getSubtle();

    switch (alg) {
        case "Ed25519": {
            // Note: Ed25519 support requires modern runtimes (Chromium-based browsers, Node 20+).
            const keyPair = await subtle.generateKey(
                { name: "Ed25519" },
        /* extractable */ true,         // set to false if you do not want JWK export
                ["sign", "verify"]
            );

            const publicKeyJwk = await subtle.exportKey("jwk", keyPair.publicKey);
            const privateKeyJwk = await subtle.exportKey("jwk", keyPair.privateKey!);

            return {
                algorithm: alg,
                publicKeyJwk,
                privateKeyJwk,
            };
        }

        default:
            throw new NotImplementedError(`Unsupported algorithm: ${alg}`);
    }
}

/*Sample call: 
const privateKeyJwk = {   
    "key_ops": [ "sign" ], 
    "ext": true, 
    "crv": "Ed25519", 
    "d": "MbOljBwnJVYewUprjUnGeDlOgZhdne2HiyqR3Fo3q8M", 
    "x": "dndYUDi2-EmghxLqvTmvWXJeXALhA4xKwo1vE8NYIiE", 
    "kty": "OKP", 
    "alg": "Ed25519" 
}
const message = new TextEncoder().encode("Hello world").buffer;
const sig = await sign(message, privateKeyJwk);
*/

export async function sign(
    _data: ArrayBuffer,
    _priv: JsonWebKey,
    _alg?: KeyAlgorithm
): Promise<ArrayBuffer> {
    const alg = _alg ?? "Ed25519";

    // Get a SubtleCrypto instance for browser or Node
    const subtle = await getSubtle();

    // Basic sanity checks for the JWK
    if (!_priv || typeof _priv !== "object" || !_priv.kty) {
        throw new Error("Invalid private JWK.");
    }
    if (alg === "Ed25519") {
        if (_priv.kty !== "OKP" || _priv.crv !== "Ed25519" || !_priv.d) {
            throw new Error("Private JWK must be an OKP/Ed25519 key with 'd'.");
        }

        const privateKey = await subtle.importKey(
            "jwk",
            _priv,
            { name: "Ed25519" },
            false,
            ["sign"]
        );

        const msg = toArrayBuffer(_data);

        const sigBuf = await subtle.sign({ name: "Ed25519" }, privateKey, msg);

        return sigBuf;
    }

    throw new NotImplementedError(`Unsupported algorithm: ${alg}`);
}

/*Sample call: 
const publicKeyJwk = {
    "key_ops": ["verify"],
    "ext": true,
    "crv": "Ed25519",
    "x": "dndYUDi2-EmghxLqvTmvWXJeXALhA4xKwo1vE8NYIiE",
    "kty": "OKP",
    "alg": "Ed25519"
}
const ver = await verify(message, sig, publicKeyJwk);
*/
export async function verify(
    _data: ArrayBuffer,
    _sig: ArrayBuffer,
    _pub: JsonWebKey,
    _alg: KeyAlgorithm
): Promise<boolean> {

    const alg = _alg ?? "Ed25519";

    if (alg === "Ed25519") {
        // Basic JWK sanity checks
        if (!_pub || _pub.kty !== "OKP" || _pub.crv !== "Ed25519" || !_pub.x) {
            throw new Error("Invalid Ed25519 public JWK: must contain kty='OKP', crv='Ed25519', and 'x'.");
        }

        const subtle = await getSubtle();

        // Import public key for verification
        const publicKey = await subtle.importKey(
            "jwk",
            _pub,
            { name: "Ed25519" },
            false,
            ["verify"]
        );

        // Verify and return boolean
        const resVer = await subtle.verify({ name: "Ed25519" }, publicKey, _sig, _data);

        return resVer;
    }
    throw new NotImplementedError(`Unsupported algorithm: ${alg}`);
}
