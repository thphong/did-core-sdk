import { IotaDocument, IotaIdentityClient, VerificationMethod, MethodScope, IotaDID, Jwk } from "@iota/identity-wasm/web";
import { Utils, Client, SecretManager } from "@iota/sdk-wasm/web";

const API_ENDPOINT = "https://api.testnet.shimmer.network";
const FAUCET_ENDPOINT = "https://faucet.testnet.shimmer.network/api/enqueue";

export async function generateMnemonic(): Promise<string> {
    return Utils.generateMnemonic();
}

//Creates a DID Document and publishes it in a new Alias Output.
export async function createIOTADocument(
    mnemonic: string,
    publicKeyJwk: JsonWebKey
): Promise<IotaDocument> {

    // 1) Tạo client
    const client = new Client({ primaryNode: API_ENDPOINT, localPow: true });
    const didClient = new IotaIdentityClient(client);
    const networkHrp: string = await didClient.getNetworkHrp();

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
        Jwk.fromJSON(publicKeyJwk),
        "#mykey"
    );
    document.insertMethod(method, MethodScope.AssertionMethod());

    // 6) Tạo Alias Output
    const aliasOutput = await didClient.newDidOutput(address, document);

    // 7) Publish DID Document
    const published = await didClient.publishDidOutput({ mnemonic }, aliasOutput);

    return published;
}

export async function resolveIOTADocument(iotadid: string): Promise<IotaDocument> {

    // 1. Tạo client kết nối IOTA node
    const client = new Client({ primaryNode: API_ENDPOINT, localPow: true });

    // 2. Tạo DID client
    const didClient = new IotaIdentityClient(client);

    // 3. Resolve DID -> DidDocument
    const resolvedDoc = await didClient.resolveDid(IotaDID.parse(iotadid));

    return resolvedDoc;
}

async function deriveBech32Address(mnemonic: string): Promise<string> {

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

//Load wasm in client
// (async () => {
//     await loadWasm();
// })();