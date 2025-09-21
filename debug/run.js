// scripts/after-build.js
import { verifyVC } from "../dist/index.cjs";


async function main() {
    try {

        const vc = {
            context: ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            issuer: 'did:web:localhost:5173:did:bank',
            issuanceDate: '2025-09-21T09:13:06.936Z',
            subject: 'did:web:localhost:5173:did:phong',
            credentialSubject: {
                id: 'did:web:localhost:5173:did:phong',
                roles: ['READ_BANK_ACCOUNT', 'MAKE_TRANSACTION']
            },
            expirationDate: '2025-10-21T09:13:06.934Z',
            proof: {
                type: 'Ed25519Signature2020',
                created: '2025-09-21T09:13:06.936Z',
                proofPurpose: 'assertionMethod',
                verificationMethod: 'did:web:localhost:5173:did:bank#keys-1',
                jws: 'OHfDDkFsV0r5uJevbLTyy-ILP8_qB57c6yKCryuBTHF4jqjlpxYDoy82_3PsnlnB6BcOHFCBU0Nc9XA9aB3nDg'
            }
        }

        const res = await verifyVC(vc)

        console.log("✅ Build OK\n", res);
    } catch (err) {
        // This will trigger until you implement createVC (your stub throws)
        console.error("❌ Build OK, but post-build call failed:", err?.message || err);
    }
}

main();
