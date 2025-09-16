// src/did/didWeb.ts
// Minimal did:web resolver with cache, timeout, and injectable fetch.

import type { DidDocument, DidMethod } from "./types";

export interface DidWebResolveOptions {
    /** Protocol to use when building the URL (default: https) */
    protocol?: "https" | "http";
    /** Override fetch implementation (e.g., node-fetch, RN polyfill) */
    fetchFn?: typeof fetch;
    /** Request timeout in ms (default: 8000) */
    timeoutMs?: number;
    /** TTL for cache in ms (default: 5 minutes) */
    cacheTtlMs?: number;
}

/** Simple in-memory cache */
const cache = new Map<string, { expires: number; doc: DidDocument }>();

/**
 * Convert a did:web to its did.json URL.
 *
 * Rules per spec:
 * - did:web:example.com                -> https://example.com/.well-known/did.json
 * - did:web:example.com:users:alice   -> https://example.com/users/alice/did.json
 * - Port is percent-encoded: did:web:example.com%3A3000 -> https://example.com:3000/.well-known/did.json
 * - Path segments are separated by ":" and may be percent-encoded.
 */
export function didWebToUrl(did: string, opts?: Pick<DidWebResolveOptions, "protocol">): string {
    if (!did.startsWith("did:web:")) throw new Error("Not a did:web DID");
    const encoded = did.slice("did:web:".length);
    if (!encoded) throw new Error("Invalid did:web (empty identifier)");

    const parts = encoded.split(":");
    if (!parts[0]) throw new Error("Invalid did:web (missing host)");

    const protocol = opts?.protocol ?? "https";
    const host = decodeURIComponent(parts[0]); // handles %3A for port, punycode left as-is
    const path = parts.slice(1).map(decodeURIComponent).join("/");

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

function getCached(did: string): DidDocument | null {
    const entry = cache.get(did);
    if (!entry) return null;
    if (Date.now() > entry.expires) {
        cache.delete(did);
        return null;
    }
    return entry.doc;
}

function setCached(did: string, doc: DidDocument, ttlMs: number) {
    cache.set(did, { doc, expires: Date.now() + ttlMs });
}

/**
 * did:web method implementation
 */
export const didWeb: DidMethod = {
    method: "web",
    async resolve(did: string): Promise<DidDocument> {
        // Defaults
        const protocol: "https" | "http" = "https";
        const fetchFn = (globalThis as any).fetch as typeof fetch | undefined;
        const timeoutMs = 8000;
        const cacheTtlMs = 5 * 60 * 1000;

        if (!fetchFn) {
            throw new Error(
                "Global fetch is not available. Provide a fetch polyfill or call resolveWithOptions with fetchFn."
            );
        }

        // Cache
        const hit = getCached(did);
        if (hit) return hit;

        const url = didWebToUrl(did, { protocol });

        const res = await fetchWithTimeout(fetchFn, url, timeoutMs);
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
        // if (doc.id !== did) throw new Error(`DID doc id mismatch: expected ${did}, got ${doc.id}`);

        setCached(did, doc, cacheTtlMs);
        return doc;
    },
};

/**
 * Resolve with explicit options (override protocol, fetch, timeouts, cache TTL).
 */
export async function resolveDidWeb(
    did: string,
    options: DidWebResolveOptions = {}
): Promise<DidDocument> {
    const {
        protocol = "https",
        fetchFn = (globalThis as any).fetch as typeof fetch | undefined,
        timeoutMs = 8000,
        cacheTtlMs = 5 * 60 * 1000,
    } = options;

    if (!did.startsWith("did:web:")) throw new Error("Not a did:web DID");

    if (!fetchFn) {
        throw new Error("Global fetch is not available. Provide options.fetchFn.");
    }

    const hit = getCached(did);
    if (hit) return hit;

    const url = didWebToUrl(did, { protocol });
    const res = await fetchWithTimeout(fetchFn, url, timeoutMs);
    if (!res.ok) throw new Error(`did:web resolve failed (${res.status}) for ${url}`);

    const doc = (await res.json()) as DidDocument;
    if (!doc || typeof doc.id !== "string") throw new Error("Invalid DID Document payload");
    setCached(did, doc, cacheTtlMs);
    return doc;
}
