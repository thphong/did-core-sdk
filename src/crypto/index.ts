import { NotImplementedError } from "../utils/errors";

export type KeyAlgorithm = "Ed25519" | "ES256";

export interface KeyPair {
    algorithm: KeyAlgorithm;
    publicKeyJwk: JsonWebKey;
    privateKeyJwk?: JsonWebKey;
}

export async function createKeyPair(_alg: KeyAlgorithm = "Ed25519"): Promise<KeyPair> {
    throw new NotImplementedError("createKeyPair");
}

export async function sign(_data: Uint8Array, _priv: JsonWebKey, _alg: KeyAlgorithm) {
    throw new NotImplementedError("sign");
}

export async function verify(_data: Uint8Array, _sig: Uint8Array, _pub: JsonWebKey, _alg: KeyAlgorithm) {
    throw new NotImplementedError("verify");
}
