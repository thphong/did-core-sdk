// Minimal did:key (Ed25519) support with zero deps.
// Build DID from an Ed25519 public JWK { kty:"OKP", crv:"Ed25519", x: <base64url> }.
import { b64uToArrayBuffer } from "../crypto/index"
import type { DidDocument, DidMethod } from "./types";

// Base58BTC alphabet
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Base58BTC encode
function base58btc(bytes: Uint8Array): string {
    if (bytes.length === 0) return "";
    // Count leading zeros
    let zeros = 0;
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) { zeros++; i++; }

    // Base58 encoding
    const encoded: number[] = [];
    const b = bytes.slice(); // mutable copy
    let start = i;
    while (start < b.length) {
        let carry = 0;
        for (let j = start; j < b.length; j++) {
            const x = (carry << 8) + b[j];
            b[j] = x / 58 | 0;
            carry = x % 58;
        }
        encoded.push(carry);
        while (start < b.length && b[start] === 0) start++;
    }

    // Leading zeros become '1'
    let out = "1".repeat(zeros);
    for (let k = encoded.length - 1; k >= 0; k--) out += ALPHABET[encoded[k]];
    return out;
}


/**
 * Build a did:key (Ed25519) from an Ed25519 public JWK.
 * DID = "did:key:z" + base58btc(multicodec(0xED) varint + publicKeyRaw)
 * Ed25519 multicodec prefix is 0xED (varint-encoded as [0xED, 0x01])
 */
function didFromEd25519Jwk(pubJwk: JsonWebKey): string {
    if (!pubJwk || pubJwk.kty !== "OKP" || pubJwk.crv !== "Ed25519" || !pubJwk.x) {
        throw new Error("Expected Ed25519 public JWK with 'x'");
    }
    const x = new Uint8Array(b64uToArrayBuffer(pubJwk.x)); // 32 bytes
    const prefix = new Uint8Array([0xed, 0x01]); // multicodec varint for Ed25519-pub
    const multi = new Uint8Array(prefix.length + x.length);
    multi.set(prefix, 0);
    multi.set(x, prefix.length);
    const mb58 = base58btc(multi);
    return `did:key:z${mb58}`;
}

/**
 * Create a DID Document for did:key with Ed25519VerificationKey2020 and publicKeyMultibase.
 */
function docForDidKey(did: string): DidDocument {
    // multibase string is the DID suffix after "did:key:"
    const vmId = `${did}#keys-1`;
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            // Context for 2020/Multikey—many verifiers accept either;
            // you can switch to "https://w3id.org/security/multikey/v1" if you prefer Multikey type
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        id: did,
        verificationMethod: [{
            id: vmId,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: did.slice("did:key:".length)
        }],
        authentication: [vmId],
        assertionMethod: [vmId],
        capabilityInvocation: [vmId],
        capabilityDelegation: [vmId]
    };
}

/*
const objDoc = await didKey.create(publicKeyJwk)
const doc = await didKey.resolve(objDoc.did)
*/
export const didKey: DidMethod = {
    method: "key",
    async resolve(did: string): Promise<DidDocument> {
        if (!did.startsWith("did:key:")) throw new Error("Not a did:key DID");
        // We cannot recover the JWK x value purely from DID without decoding—keep it simple:
        // Build a DID doc that uses publicKeyMultibase only.
        const vmId = `${did}#keys-1`;
        return docForDidKey(did);
    },
    async create(publicKeyJwk: JsonWebKey): Promise<{ did: string; doc: DidDocument }> {
        const did = didFromEd25519Jwk(publicKeyJwk);
        const doc = docForDidKey(did);
        return { did, doc };
    }
};
