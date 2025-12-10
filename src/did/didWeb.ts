// src/did/didWeb.ts
// Minimal did:web resolver with cache, timeout, and injectable fetch.

import type { DidDocument, DidMethod } from "./types";
import { DidCache } from "./didCache";

const didCache = new DidCache();

/**
 * Convert a did:web to its did.json URL.
 *
 * Rules per spec:
 * - did:web:example.com                -> https://example.com/.well-known/did.json
 * - did:web:example.com:users:alice   -> https://example.com/users/alice/did.json
 * - Port is percent-encoded: did:web:example.com%3A3000 -> https://example.com:3000/.well-known/did.json
 * - Path segments are separated by ":" and may be percent-encoded.
 */
function didWebToUrl(did: string, opts?: { protocol: string }): string {
    if (!did.startsWith("did:web:")) throw new Error("Not a did:web DID");
    const encoded = did.slice("did:web:".length);
    if (!encoded) throw new Error("Invalid did:web (empty identifier)");

    const parts = encoded.split(":");
    if (!parts[0]) throw new Error("Invalid did:web (missing host)");

    const protocol = opts?.protocol ?? "https";

    let host: string;
    let pathParts: string[];
    if (parts.length > 1 && /^\d+$/.test(parts[1])) {
        host = `${decodeURIComponent(parts[0])}:${parts[1]}`;
        pathParts = parts.slice(2);
    } else {
        host = decodeURIComponent(parts[0]);
        pathParts = parts.slice(1);
    }

    const path = pathParts.map(decodeURIComponent).join("/");

    return path
        ? `${protocol}://${host}/${path}/did.json`
        : `${protocol}://${host}/.well-known/did.json`;
}

async function fetchWithTimeout(
    fetchFn: typeof fetch,
    url: string,
    timeoutMs: number
): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetchFn(url, { signal: controller.signal, headers: { accept: "application/did+json, application/json" } });
    } finally {
        clearTimeout(timer);
    }
}

/**
 * did:web method implementation
 * const doc = await didWeb.resolve("did:web:localhost:5173:did", { protocol:'http' })
 */
export const didWeb: DidMethod = {
    method: "web",
    async resolve(did: string): Promise<DidDocument> {

        const fetchFn = (globalThis as any).fetch as typeof fetch | undefined;
        const timeoutMs = 8000;
        const cacheTtlMs = 5 * 60 * 1000;

        if (!fetchFn) {
            throw new Error(
                "Global fetch is not available. Provide a fetch polyfill or call resolveWithOptions with fetchFn."
            );
        }

        // Cache
        const hit = didCache.get(did);
        if (hit) return hit;

        let res: Response;
        let url = '';

        try {
            url = didWebToUrl(did, { protocol: "https" });
            res = await fetchWithTimeout(fetchFn, url, timeoutMs);
        }
        catch {
            url = didWebToUrl(did, { protocol: "http" });
            res = await fetchWithTimeout(fetchFn, url, timeoutMs);
        }
        if (!res.ok) {
            throw new Error(`did:web resolve failed (${res.status}) for ${url}`);
        }

        const doc = (await res.json()) as DidDocument;

        // Minimal validation
        if (!doc || typeof doc !== "object" || typeof (doc as any).id !== "string") {
            throw new Error("Invalid DID Document payload");
        }
        // Some issuers omit exact id matching in dev; keep soft but helpful:
        // If mismatch is critical for your flow, uncomment the strict check:
        if (doc.id !== did) throw new Error(`DID doc id mismatch: expected ${did}, got ${doc.id}`);

        didCache.set(did, doc, cacheTtlMs);
        return doc;
    },
    async create(publicKeyJwk: JsonWebKey, opts: { didWeb: string }): Promise<{ did: string; doc: DidDocument }> {

        if (!opts.didWeb) {
            throw new Error("Expected your given did");
        }

        const vmId = `${opts.didWeb}#keys-1`;
        const doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: opts.didWeb,
            verificationMethod: [
                {
                    id: vmId,
                    type: "Ed25519VerificationKey2020",
                    controller: opts.didWeb,
                    publicKeyJwk: publicKeyJwk
                }
            ],
            authentication: [vmId],
            assertionMethod: [vmId],
            capabilityInvocation: [vmId],
            capabilityDelegation: [vmId]
        }

        return { did: opts.didWeb, doc };
    },
    async revoke(issuer: string, index: number, privateKey: JsonWebKey): Promise<DidDocument> {
        throw new Error("You must revoke vc in your DID Document");
    }
};


