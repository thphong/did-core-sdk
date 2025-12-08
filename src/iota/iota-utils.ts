
import {
    IotaDID, Storage, IotaDocument,
    IdentityClient, MethodScope, VerificationMethod, Jwk,
    IdentityClientReadOnly, StorageSigner,
    JwkMemStore, KeyIdMemStore, JwsAlgorithm,
    Service, IService
    //} from "@iota/identity-wasm/node/index.js";
} from "@iota/identity-wasm/web";
import { getFaucetHost, requestIotaFromFaucetV0 } from "@iota/iota-sdk/faucet";
import { IotaClient } from "@iota/iota-sdk/client";
const NETWORK_NAME_FAUCET = 'testnet';
const NETWORK_URL = 'https://api.testnet.iota.cafe';


export async function createIOTADocument(publicKeyJwk: JsonWebKey, privateKey: JsonWebKey, service?: any[]): Promise<IotaDocument> {
    // create new client to connect to IOTA network
    const iotaClient = new IotaClient({ url: NETWORK_URL });
    const network = await iotaClient.getChainIdentifier();

    // create new unpublished document
    const document = await createDocumentForNetwork(publicKeyJwk, network, service);

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

function isValidUrl(url: string): boolean {
    try {
        new URL(url);
        return true;
    } catch {
        throw new Error(`${url} is not valid url`);
    }
}

function isValidServiceEndpoint(endpoint: any): boolean {
    // string
    if (typeof endpoint === "string") {
        return isValidUrl(endpoint);
    }

    // array of strings
    if (Array.isArray(endpoint)) {
        return endpoint.every(x => typeof x === "string" && isValidUrl(x));
    }

    // record<string, string[]>
    if (typeof endpoint === "object") {
        return Object.entries(endpoint).every(([_, value]) => {
            if (!Array.isArray(value)) {
                throw new Error(`serviceEndpoint item value is not string array`);
            };
            return value.every(v => typeof v === "string" && isValidUrl(v));
        });
    }

    return false;
}

export function validateIServiceList(serviceLists: any): boolean {
    if (!Array.isArray(serviceLists))
        throw new Error(`object is not an array`);

    for (const item of serviceLists) {
        // must be object
        if (typeof item !== "object")
            throw new Error(`element of array is not an object`);

        // id
        if (typeof item.fragment !== "string") {
            throw new Error(`Invalid fragment: ${item.fragment}`);
        }

        // type: string | string[]
        if (!(typeof item.type === "string" || Array.isArray(item.type))) {
            throw new Error(`Invalid type: ${item.type}`);
        }

        // serviceEndpoint required
        if (!("serviceEndpoint" in item)) {
            throw new Error(`Missing serviceEndpoint: ${item}`);
        }

        if (!isValidServiceEndpoint(item.serviceEndpoint)) {
            throw new Error(`Invalid serviceEndpoint: ${item.serviceEndpoint}`);
        }
    }

    return true;
}

function convertService(did: string, json: any[]): IService[] {
    return json.map(item => {
        if (!item.fragment || typeof item.fragment !== "string") {
            throw new Error(`Missing or invalid fragment on ${JSON.stringify(item)}`);
        }

        const id = `${did}${item.fragment}`;

        const service: any = {
            id,
            type: item.type,
            serviceEndpoint: item.serviceEndpoint,
        };

        // Nếu có custom properties khác ngoài spec
        for (const key of Object.keys(item)) {
            if (!["fragment", "type", "serviceEndpoint"].includes(key)) {
                service[key] = item[key];
            }
        }

        return service;
    });
}

async function createDocumentForNetwork(publicKeyJwk: JsonWebKey, network: string, service?: any[]): Promise<IotaDocument> {
    // Create a new DID document with a placeholder DID.
    const document = new IotaDocument(network);

    const fragment = "#keys-1";
    const method = VerificationMethod.newFromJwk(
        document.id(),
        Jwk.fromJSON(publicKeyJwk),
        fragment);
    document.insertMethod(method, MethodScope.VerificationMethod());

    const keyAgreementFragment = "#key-agreement-1";
    const keyAgreementMethod = VerificationMethod.newFromJwk(
        document.id(),
        Jwk.fromJSON(publicKeyJwk),
        keyAgreementFragment,
    );
    document.insertMethod(keyAgreementMethod, MethodScope.KeyAgreement());

    if (service && service.length > 0) {
        if (validateIServiceList(service)) {
            const iServices = convertService(document.id().toString(), service);
            iServices.forEach(serv => {
                document.insertService(new Service(serv));
            })
        }
    }

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
