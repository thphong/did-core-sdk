import type { DidDocument, DidMethod } from "./types";
import { didKey } from "./didKey";
import { didWeb } from "./didWeb";
import { didIOTA, setDidIOTAResolverDefaults } from "./didIOTA";

const registry = new Map<string, DidMethod>();
registry.set("key", didKey);
registry.set("web", didWeb);

setDidIOTAResolverDefaults({
    resolverBaseUrl: "https://<your-resolver-domain>/api/v1", // <-- set this
    // fetchFn: yourPolyfilledFetch, // if needed (Node/RN)
});

registry.set("iota", didIOTA);

// You can later: registry.set("web", didWeb); registry.set("ion", didIon); registry.set("iota", didIota) ...

export async function resolveDid(did: string): Promise<DidDocument> {
    const m = did.split(":")[1];
    const handler = registry.get(m);
    if (!handler) throw new Error(`No resolver registered for did:${m}`);
    return handler.resolve(did);
}

export function registerDidMethod(method: DidMethod) {
    registry.set(method.method, method);
}

export { didKey, didWeb, didIOTA }
export * from "./types";
