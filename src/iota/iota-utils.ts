import type { IotaDocument as TIotaDocument } from "@iota/identity-wasm/web/index.js";

const API_ENDPOINT = "https://api.testnet.shimmer.network";
const FAUCET_ENDPOINT = "https://faucet.testnet.shimmer.network/api/enqueue";

async function loadIdentity() {
    return await import("@iota/identity-wasm/web/index.js");
}

async function loadSdk() {
    return await import("@iota/sdk-wasm/web/lib/index.js");
}

let isLoadedWasm = false;
async function loadWasm() {
    if (!isLoadedWasm) {
        console.log('start init');
        const identity = await loadIdentity();
        await identity.init();
        isLoadedWasm = true;
        console.log('end init');
    }
}

export async function generateMnemonic(): Promise<string> {
    await loadWasm();

    const sdk = await loadSdk();
    const { Utils } = sdk as any;
    return Utils.generateMnemonic();
}

//Creates a DID Document and publishes it in a new Alias Output.
export async function createIOTADocument(
    mnemonic: string,
    publicKeyJwk: JsonWebKey
): Promise<TIotaDocument> {
    await loadWasm();

    const identity = await loadIdentity();
    const sdk = await loadSdk();

    const { IotaDocument, IotaIdentityClient, VerificationMethod, MethodScope } =
        identity as any;
    const { Client, SecretManager, Utils } = sdk as any;

    // 1) Tạo client
    const client = new Client({ primaryNode: API_ENDPOINT, localPow: true });
    const didClient = new IotaIdentityClient(client);
    const networkHrp: string = await didClient.getNetworkHrp();

    // 2) SecretManager từ mnemonic (để publish alias output)
    const secretManager = new SecretManager({ mnemonic });

    const addressBech32 = await deriveBech32Address(mnemonic);

    // 3) Đảm bảo address có token testnet (tùy bạn implement ensureAddressHasFunds)
    await ensureAddressHasFunds(client, addressBech32);

    // Parse Bech32 -> Address bytes
    const address = Utils.parseBech32Address(addressBech32);

    // 4) Tạo DID Document mới
    const document = new IotaDocument(networkHrp);

    // 5) Thêm publicKeyJwk vào document (vì bạn quản lý private key riêng)
    const method = VerificationMethod.newFromJwk(
        document.id(),
        publicKeyJwk,
        "#mykey"
    );
    document.insertMethod(method, MethodScope.AssertionMethod());

    // 6) Tạo Alias Output
    const aliasOutput = await didClient.newDidOutput(address, document);

    // 7) Publish DID Document
    const published = await didClient.publishDidOutput(secretManager, aliasOutput);

    return published;
}

export async function resolveIOTADocument(iotadid: string): Promise<TIotaDocument> {
    const identity = await loadIdentity();
    const sdk = await loadSdk();

    const { IotaIdentityClient } = identity as any;
    const { Client } = sdk as any;

    // 1. Tạo client kết nối IOTA node
    const client = new Client({ primaryNode: API_ENDPOINT, localPow: true });

    // 2. Tạo DID client
    const didClient = new IotaIdentityClient(client);

    // 3. Resolve DID -> DidDocument
    const resolvedDoc = await didClient.resolveDid(iotadid);

    return resolvedDoc;
}

async function deriveBech32Address(mnemonic: string): Promise<string> {
    await loadWasm();

    const sdk = await loadSdk();
    const identity = await loadIdentity();

    const { Client, SecretManager } = sdk as any;
    const { IotaIdentityClient } = identity as any;

    const client = new Client({ primaryNode: API_ENDPOINT, localPow: true });
    const didClient = new IotaIdentityClient(client);
    const networkHrp: string = await didClient.getNetworkHrp();

    const secretManager = new SecretManager({ mnemonic });
    const [bech32] = await secretManager.generateEd25519Addresses({
        accountIndex: 0,
        range: { start: 0, end: 1 },
        bech32Hrp: networkHrp,
    });

    return bech32;
}

/** Request funds from the faucet API, if needed, and wait for them to show in the wallet. */
async function ensureAddressHasFunds(client: any, addressBech32: string) {

    await loadWasm();

    let balance = await getAddressBalance(client, addressBech32);
    if (balance > BigInt(0)) {
        return;
    }

    await requestFundsFromFaucet(addressBech32);

    for (let i = 0; i < 9; i++) {
        // Wait for the funds to reflect.
        await new Promise(f => setTimeout(f, 5000));

        let balance = await getAddressBalance(client, addressBech32);
        if (balance > BigInt(0)) {
            break;
        }
    }
}

/** Returns the balance of the given Bech32-encoded address. */
async function getAddressBalance(client: any, addressBech32: string): Promise<bigint> {

    await loadWasm();

    const outputIds = await client.basicOutputIds([
        { address: addressBech32 },
        { hasExpiration: false },
        { hasTimelock: false },
        { hasStorageDepositReturn: false },
    ]);
    const outputs = await client.getOutputs(outputIds.items);

    let totalAmount = BigInt(0);
    for (const output of outputs) {
        totalAmount += output.output.getAmount();
    }

    return totalAmount;
}

/** Request tokens from the faucet API. */
async function requestFundsFromFaucet(addressBech32: string) {

    await loadWasm();

    const requestObj = JSON.stringify({ address: addressBech32 });
    let errorMessage, data;
    try {
        const response = await fetch(FAUCET_ENDPOINT, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
            body: requestObj,
        });
        if (response.status === 202) {
            errorMessage = "OK";
        } else if (response.status === 429) {
            errorMessage = "too many requests, please try again later.";
        } else {
            data = await response.json();
            // @ts-ignore
            errorMessage = data.error.message;
        }
    } catch (error) {
        errorMessage = error;
    }

    if (errorMessage != "OK") {
        throw new Error(`failed to get funds from faucet: ${errorMessage}`);
    }
}

// (async () => {
//     await loadWasm();
// })();