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
    const subtle = globalThis?.crypto?.subtle as SubtleCrypto | undefined;
    if (!subtle) throw new Error("WebCrypto SubtleCrypto is not available in this runtime.");
    return subtle;
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

// utils: canonicalize JSON (stable key order) → string
// chuẩn hóa JSON thành dạng duy nhất để mọi lần hash/ký số đều ra cùng kết quả, bất kể môi trường hay cách serialize.
export function canonicalize(obj: any): string {
    const seen = new WeakSet();
    const sorter = (value: any): any => {
        if (value && typeof value === "object") {
            if (seen.has(value)) throw new Error("Circular reference");
            seen.add(value);
            if (Array.isArray(value)) return value.map(sorter);
            const keys = Object.keys(value).sort();
            const out: any = {};
            for (const k of keys) out[k] = sorter(value[k]);
            return out;
        }
        return value;
    };
    return JSON.stringify(sorter(obj));
}

// utils: base64url(ArrayBuffer) → string
export function base64url(buf: ArrayBuffer): string {
    const bin = String.fromCharCode(...new Uint8Array(buf));
    const b64 = btoa(bin);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlToArrayBuffer(b64url: string): ArrayBuffer {
    const pad = (s: string) => s + "===".slice((s.length + 3) % 4);
    const b64 = pad(b64url.replace(/-/g, "+").replace(/_/g, "/"));
    if (typeof atob !== "function") {
        // tiny fallback: pure JS base64 decoder (no Buffer). Hoặc yêu cầu env cung cấp atob.
        throw new Error("Base64 decoder (atob) not available in this runtime.");
    }
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

// utils: sha-256(ArrayBuffer) → ArrayBuffer
export async function sha256(ab: ArrayBuffer): Promise<ArrayBuffer> {
    const subtle = await getSubtle();
    return subtle.digest("SHA-256", ab);
}

export function algFromProofType(proofType: string): KeyAlgorithm {
    // We produced types like "Ed25519Signature2020"
    if (/^Ed25519Signature2020$/i.test(proofType) || !proofType) return "Ed25519";
    const res = 'ES256' // extend here for ES256K, etc.
    return res;
}