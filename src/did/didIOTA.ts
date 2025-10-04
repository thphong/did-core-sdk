// src/did/didIOTA.ts
// Minimal did:iota resolver with cache, timeout, and configurable resolver base URL.
// NOTE: did:iota DIDs are anchored on the Tangle. To resolve, you typically call
// an HTTP "resolver" service. This module lets you inject that base URL + fetch.
//
// Examples of resolver base URLs (you must provide one appropriate for your network):
//   - Mainnet resolver:        "https://<your-resolver>/api/v1"
//   - Devnet/Shimmer resolver: "https://<your-resolver>/api/v1"

import type { DidDocument, DidMethod } from "./types";
import { DidCache } from "./didCache";
import { createIOTADocument, resolveIOTADocument, generateMnemonic } from "../iota/iota-utils";

const didCache = new DidCache();


/** Quick check */
function isIotaDid(did: string): boolean {
    return typeof did === "string" && did.startsWith("did:iota:");
}

/**
 * did:iota method implementation (resolver-based).
 */
export const didIOTA: DidMethod = {
    method: "iota",
    async resolve(did: string): Promise<DidDocument> {
        if (!isIotaDid(did)) throw new Error("Not a did:iota DID");

        const hit = didCache.get(did);
        if (hit) return hit;

        const cacheTtlMs = 5 * 60 * 1000;
        const doc: any = await resolveIOTADocument(did)

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

        const mnemonic = await generateMnemonic();

        const doc: any = await createIOTADocument(mnemonic, publicKeyJwk);
        return {
            did: doc.did, doc
        }
    }
};