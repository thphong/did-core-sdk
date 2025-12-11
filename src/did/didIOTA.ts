// src/did/didIOTA.ts
import type { DidDocument, DidMethod } from "./types";
import { DidCache } from "./didCache";
import { createIOTADocument, resolveIOTADocument, revokeVcOnDocument } from "../iota/iota-utils";
import { IotaDocument } from "@iota/identity-wasm/web";
//import { IotaDocument } from "@iota/identity-wasm/node/index.js";

const didCache = new DidCache();
const cacheTtlMs = 0 * 60 * 1000;

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

        const iotaDoc = await resolveIOTADocument(did);
        const doc: any = iotaDoc.toJSON()

        if (!doc || typeof doc.doc !== "object" || typeof (doc.doc as any).id !== "string") {
            throw new Error("Invalid DID Document payload from resolver");
        }

        didCache.set(did, doc.doc, cacheTtlMs);
        return doc.doc;
    },
    /**
     * Helper: produce a local DID Document template from an Ed25519 public JWK.
     * NOTE: did:iota identifiers are derived from state anchored on the Tangle.
     * This helper does NOT create or publish a DID; it just builds a doc structure
     * you might sign or later publish via an IOTA Identity flow.
     */
    async create(publicKeyJwk: JsonWebKey, opts: { privateKey: JsonWebKey, service?: any[] }): Promise<{ did: string; doc: DidDocument }> {
        if (!publicKeyJwk || publicKeyJwk.kty !== "OKP" || publicKeyJwk.crv !== "Ed25519" || !publicKeyJwk.x) {
            throw new Error("Expected Ed25519 public JWK with 'x'");
        }

        if (!opts.privateKey) {
            throw new Error("Expected privateKey");
        }

        const iotaDoc: IotaDocument = await createIOTADocument(publicKeyJwk, opts.privateKey, opts.service);
        const did = iotaDoc.id().toString();
        const doc: any = iotaDoc.toJSON();
        return {
            did, doc: doc.doc
        }
    },
    async revoke(issuer: string, index: number, privateKey: JsonWebKey): Promise<DidDocument> {
        const iotaDoc = await resolveIOTADocument(issuer);
        // Resolve issuer DID Document
        if (!iotaDoc) {
            throw new Error("Revoke VC: Can't resolve issuer did");
        }
        if (!Number.isInteger(index) || index === undefined || index < 0) {
            throw new Error("Revoke VC: Index is wrong format");
        }
        const iotaDocRevoked: IotaDocument = await revokeVcOnDocument(iotaDoc, index, privateKey);
        const doc: any = iotaDocRevoked.toJSON();
        return doc;
    }
};