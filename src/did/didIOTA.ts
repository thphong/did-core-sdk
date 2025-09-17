// src/did/didIOTA.ts
// Minimal did:iota resolver with cache, timeout, and configurable resolver base URL.
// NOTE: did:iota DIDs are anchored on the Tangle. To resolve, you typically call
// an HTTP "resolver" service. This module lets you inject that base URL + fetch.
//
// Examples of resolver base URLs (you must provide one appropriate for your network):
//   - Mainnet resolver:        "https://<your-resolver>/api/v1"
//   - Devnet/Shimmer resolver: "https://<your-resolver>/api/v1"
// The final resolve URL will be: `${resolverBaseUrl.replace(/\/+$/, "")}/identities/${encodeURIComponent(did)}`

import type { DidDocument, DidMethod } from "./types";
import { DidCache } from "./didCache";

const didCache = new DidCache();

export interface DidIOTAResolveOptions {
    /** Base URL of the resolver service, e.g. "https://resolver.example.org/api/v1" */
    resolverBaseUrl?: string;
    /** Override fetch implementation (node-fetch, RN polyfill, etc.) */
    fetchFn?: typeof fetch;
    /** Request timeout in ms (default: 8000) */
    timeoutMs?: number;
    /** TTL for cache in ms (default: 5 minutes) */
    cacheTtlMs?: number;
}

/** Module-level defaults (can be updated via setDidIOTAResolverDefaults) */
const defaults: Required<DidIOTAResolveOptions> = {
    resolverBaseUrl: "",     // must be provided by caller or via setter
    fetchFn: (globalThis as any).fetch as typeof fetch,
    timeoutMs: 8000,
    cacheTtlMs: 5 * 60 * 1000,
};

/** Update module defaults (e.g., once during app boot) */
export function setDidIOTAResolverDefaults(opts: Partial<DidIOTAResolveOptions>) {
    if (typeof opts.resolverBaseUrl === "string") defaults.resolverBaseUrl = opts.resolverBaseUrl;
    if (opts.fetchFn) defaults.fetchFn = opts.fetchFn;
    if (typeof opts.timeoutMs === "number") defaults.timeoutMs = opts.timeoutMs;
    if (typeof opts.cacheTtlMs === "number") defaults.cacheTtlMs = opts.cacheTtlMs;
}

/** Quick check */
function isIotaDid(did: string): boolean {
    return typeof did === "string" && did.startsWith("did:iota:");
}

/** Build resolver URL for a given did:iota using a base like ".../api/v1" */
function didIotaToUrl(did: string, resolverBaseUrl: string): string {
    if (!isIotaDid(did)) throw new Error("Not a did:iota DID");
    if (!resolverBaseUrl) {
        throw new Error("resolverBaseUrl is required for did:iota resolution");
    }
    const base = resolverBaseUrl.replace(/\/+$/, "");
    return `${base}/identities/${encodeURIComponent(did)}`;
}

async function fetchWithTimeout(
    fetchFn: typeof fetch,
    url: string,
    timeoutMs: number
): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetchFn(url, {
            signal: controller.signal,
            headers: { accept: "application/did+json, application/json" },
        });
    } finally {
        clearTimeout(timer);
    }
}

/**
 * did:iota method implementation (resolver-based).
 * You must set a resolver base URL either once via setDidIOTAResolverDefaults(...)
 */
export const didIOTA: DidMethod = {
    method: "iota",
    async resolve(did: string, options: DidIOTAResolveOptions = {}): Promise<DidDocument> {
        if (!isIotaDid(did)) throw new Error("Not a did:iota DID");

        const hit = didCache.get(did);
        if (hit) return hit;

        const {
            resolverBaseUrl = defaults.resolverBaseUrl,
            fetchFn = defaults.fetchFn,
            timeoutMs = defaults.timeoutMs,
            cacheTtlMs = defaults.cacheTtlMs,
        } = options;

        if (!fetchFn) throw new Error("Global fetch is not available. Provide a fetch polyfill or pass fetchFn.");

        const url = didIotaToUrl(did, resolverBaseUrl);
        const res = await fetchWithTimeout(fetchFn, url, timeoutMs);

        if (!res.ok) throw new Error(`did:iota resolve failed (${res.status}) for ${url}`);

        // Resolver payloads commonly include the DID Document either at the top-level
        // or under a property such as "document" / "doc".
        const payload = await res.json();
        const doc = (payload?.document ?? payload?.doc ?? payload) as DidDocument;

        if (!doc || typeof doc !== "object" || typeof (doc as any).id !== "string") {
            throw new Error("Invalid DID Document payload from resolver");
        }

        didCache.set(did, doc, cacheTtlMs);
        return doc;
    },
    /**
     * Helper: produce a local DID Document template from an Ed25519 public JWK.
     * NOTE: did:iota identifiers are derived from state anchored on the Tangle.
     * This helper does NOT create or publish a DID; it just builds a doc structure
     * you might sign or later publish via an IOTA Identity flow.
     */
    async create(publicKeyJwk: JsonWebKey): Promise<{ did: string; doc: DidDocument }> {
        if (!publicKeyJwk || publicKeyJwk.kty !== "OKP" || publicKeyJwk.crv !== "Ed25519" || !publicKeyJwk.x) {
            throw new Error("Expected Ed25519 public JWK with 'x'");
        }

        const did = "UNPUBLISHED"; // replace with actual DID after publishing
        const didPlaceholder = `did:iota:${did}`;

        const vmId = `${didPlaceholder}#keys-1`;
        const doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            id: didPlaceholder,
            verificationMethod: [{
                id: vmId,
                type: "Ed25519VerificationKey2020",
                controller: didPlaceholder,
                publicKeyJwk, // iota DID docs frequently use JWK form; multibase is also possible.
            }],
            authentication: [vmId],
            assertionMethod: [vmId],
            capabilityInvocation: [vmId],
            capabilityDelegation: [vmId],
            // You can add DID services later (OID4VCI, DIDComm, etc.)
        };
        return {
            did, doc
        }
    }
};