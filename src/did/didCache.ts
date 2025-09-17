// didCache.ts
import type { DidDocument } from "./types";

export class DidCache {
    private cache = new Map<string, { expires: number; doc: DidDocument }>();

    get(did: string): DidDocument | null {
        const entry = this.cache.get(did);
        if (!entry) return null;

        if (Date.now() > entry.expires) {
            this.cache.delete(did);
            return null;
        }
        return entry.doc;
    }

    set(did: string, doc: DidDocument, ttlMs: number): void {
        this.cache.set(did, { doc, expires: Date.now() + ttlMs });
    }

    delete(did: string): void {
        this.cache.delete(did);
    }

    clear(): void {
        this.cache.clear();
    }
}
