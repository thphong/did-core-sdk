export interface StorageLike {
    get<T = any>(key: string): Promise<T | null>;
    set<T = any>(key: string, value: T): Promise<void>;
    remove(key: string): Promise<void>;
    clear(): Promise<void>;
}

export class MemoryStorage implements StorageLike {
    private store = new Map<string, any>();
    async get<T>(k: string) { return this.store.has(k) ? (this.store.get(k) as T) : null; }
    async set<T>(k: string, v: T) { this.store.set(k, v); }
    async remove(k: string) { this.store.delete(k); }
    async clear() { this.store.clear(); }
}
