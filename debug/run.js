// scripts/after-build.js
import { verifyVC } from "../dist/index.cjs";


async function main() {
    try {

        const delegatedVC = {
            context: ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'DelegatedCredential'],
            issuer: 'did:web:localhost:5173:did:phong',
            subject: 'did:web:localhost:5173:did:momo',
            issuanceDate: '2025-09-22T04:54:02.461Z',
            expirationDate: '2025-10-22T04:47:52.729Z',
            credentialSubject: {
                id: 'did:web:localhost:5173:did:momo',
                roles: ['READ_BANK_ACCOUNT'],
                parentVC:
                {
                    context: ['https://www.w3.org/2018/credentials/v1'],
                    type: ['VerifiableCredential'],
                    issuer: 'did:web:localhost:5173:did:bank',
                    issuanceDate: '2025-09-22T04:47:52.731Z',
                    subject: 'did:web:localhost:5173:did:phong',
                    credentialSubject: {
                        id: 'did:web:localhost:5173:did:phong',
                        roles: ['READ_BANK_ACCOUNT', 'MAKE_TRANSACTION']
                    },
                    expirationDate: '2025-10-22T04:47:52.729Z',
                    proof: {
                        type: 'Ed25519Signature2020',
                        created: '2025-09-22T04:47:52.731Z',
                        proofPurpose: 'assertionMethod',
                        verificationMethod: 'did:web:localhost:5173:did:bank#keys-1',
                        jws: '3CHyq_DtLsnXHNOyHvyOXlNaA0sx7u0BTR4h3Wr1dE3IdLDFgEMMrNRd3LeVSL0TmxRiUPb0X6JL5OQ_4JUzDQ'
                    }
                }
            },
            proof: {
                type: 'Ed25519Signature2020',
                created: '2025-09-22T04:54:02.461Z',
                proofPurpose: 'delegation',
                verificationMethod: 'did:web:localhost:5173:did:phong#keys-1',
                jws: 'xchvx8C8-p-pqwaNNPX9O9TiP7rcCmJUazw2InzgZwksiYB_49mEwvkRqGi1DOTk7TQmgWG-lwMQzsaf3Q8tAA'
            }
        }

        const res = await verifyVC(delegatedVC)

        console.log("✅ Build OK\n", res);
    } catch (err) {
        // This will trigger until you implement createVC (your stub throws)
        console.error("❌ Build OK, but post-build call failed:", err?.message || err);
    }
}

main();
