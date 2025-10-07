export interface VerificationMethod {
    id: string;
    type: string; // e.g., "Ed25519VerificationKey2020" or "Multikey"
    controller: string;
    publicKeyMultibase?: string; // for did:key
    publicKeyJwk?: JsonWebKey;   // for did:web/json
}

export interface Service {
    id: string;
    type: string | string[];
    serviceEndpoint: string | Record<string, any>;
}

export interface DidDocument {
    "@context": (string | Record<string, any>)[];
    id: string;
    verificationMethod?: VerificationMethod[];
    authentication?: (string | VerificationMethod)[];
    assertionMethod?: (string | VerificationMethod)[];
    keyAgreement?: (string | VerificationMethod)[];
    capabilityInvocation?: (string | VerificationMethod)[];
    capabilityDelegation?: (string | VerificationMethod)[];
    service?: Service[];
}

export interface DidMethod {
    method: string; // "key", "web", ...
    create(publicKeyJwk: JsonWebKey, opts?: { privateKey?: JsonWebKey, didWeb?: string }): Promise<{ did: string; doc: DidDocument }>;
    resolve(did: string): Promise<DidDocument>;
}
