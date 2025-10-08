
import {
    IotaDID, Storage, IotaDocument,
    IdentityClient, MethodScope, VerificationMethod, Jwk,
    IdentityClientReadOnly, StorageSigner,
    JwkMemStore, KeyIdMemStore, JwsAlgorithm
} from "@iota/identity-wasm/web";
import { getFaucetHost, requestIotaFromFaucetV0 } from "@iota/iota-sdk/faucet";
import { IotaClient } from "@iota/iota-sdk/client";
const NETWORK_NAME_FAUCET = 'testnet';
const NETWORK_URL = 'https://api.testnet.iota.cafe';


export async function createIOTADocument(publicKeyJwk: JsonWebKey, privateKey: JsonWebKey): Promise<IotaDocument> {
    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // create new unpublished document
    const document = await createDocumentForNetwork(publicKeyJwk, network);

    // create new client that offers identity related functions
    const identityClient = await getFundedClient(privateKey);

    const { output: identity } = await identityClient
        .createIdentity(document)
        .finish()
        .buildAndExecute(identityClient);

    return identity.didDocument();
}

export async function resolveIOTADocument(iotadid: string): Promise<IotaDocument> {

    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const identityClientReadOnly = await IdentityClientReadOnly.create(iotaClient);

    // create signer from storage
    let signer = await createStorageSigner();
    const identityClient = await IdentityClient.create(identityClientReadOnly, signer);
    const resolvedDoc = await identityClient.resolveDid(IotaDID.parse(iotadid));

    return resolvedDoc;
}


async function createStorageSignerFromKeys(
    privateKey: JsonWebKey
): Promise<StorageSigner> {

    // Create in-memory storage
    const jwkStore = new JwkMemStore();
    const keyIdStore = new KeyIdMemStore();
    const storage = new Storage(jwkStore, keyIdStore);

    // Wrap into identity Jwk
    const jwk = Jwk.fromJSON({ ...privateKey, alg: "EdDSA" });

    // Insert into storage under chosen keyId
    const keyId = await storage.keyStorage().insert(jwk);

    // Create signer using the stored key
    const publicJwk = jwk.toPublic();
    if (typeof publicJwk === "undefined") {
        throw new Error("failed to derive public JWK from generated JWK");
    }
    const signer = new StorageSigner(storage, keyId, publicJwk);

    return signer;
}

async function createStorageSigner(
): Promise<StorageSigner> {

    // Create in-memory storage
    const jwkStore = new JwkMemStore();
    const keyIdStore = new KeyIdMemStore();
    const storage = new Storage(jwkStore, keyIdStore);

    let generate = await storage.keyStorage().generate("Ed25519", JwsAlgorithm.EdDSA);

    let publicKeyJwk = generate.jwk().toPublic();
    if (typeof publicKeyJwk === "undefined") {
        throw new Error("failed to derive public JWK from generated JWK");
    }
    let keyId = generate.keyId();

    // create signer from storage
    let signer = new StorageSigner(storage, keyId, publicKeyJwk);

    return signer;
}

async function createDocumentForNetwork(publicKeyJwk: JsonWebKey, network: string): Promise<IotaDocument> {
    // Create a new DID document with a placeholder DID.
    const document = new IotaDocument(network);

    const fragment = "#keys-1";
    const method = VerificationMethod.newFromJwk(document.id(), Jwk.fromJSON(publicKeyJwk), fragment);
    document.insertMethod(method, MethodScope.VerificationMethod());

    return document;
}

async function requestFunds(address: string) {
    await requestIotaFromFaucetV0({
        host: getFaucetHost(NETWORK_NAME_FAUCET),
        recipient: address,
    });
}

async function getFundedClient(privateKey: JsonWebKey): Promise<IdentityClient> {
    const iotaClient = new IotaClient({ url: NETWORK_URL });

    const identityClientReadOnly = await IdentityClientReadOnly.create(iotaClient);

    // create signer from storage
    let signer = await createStorageSignerFromKeys(privateKey);
    const identityClient = await IdentityClient.create(identityClientReadOnly, signer);

    const balance = await iotaClient.getBalance({ owner: identityClient.senderAddress() });
    if (balance.totalBalance == "0") {
        await requestFunds(identityClient.senderAddress());
    }

    return identityClient;
}
