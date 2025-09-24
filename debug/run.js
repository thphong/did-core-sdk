// scripts/after-build.js
import { verifyVP, createVP, createVC, createDelegatedVC, verifyVC } from "../dist/index.cjs";


async function main() {
    try {
        const vp = {
            context: ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiablePresentation'],
            verifiableCredential: [
                {
                    context: ['https://www.w3.org/2018/credentials/v1'],
                    type: ['VerifiableCredential', 'DelegatedCredential'],
                    issuer: 'did:web:localhost:5173:did:phong',
                    subject: 'did:web:localhost:5173:did:momo',
                    issuanceDate: '2025-09-22T11:07:20.633Z',
                    expirationDate: '2025-10-22T10:58:02.688Z',
                    credentialSubject: {
                        id: 'did:web:localhost:5173:did:momo',
                        roles: { READ_BANK_ACCOUNT: 'Allow to read account balance' },
                        parentVC: {
                            context: ['https://www.w3.org/2018/credentials/v1'],
                            type: ['VerifiableCredential'],
                            issuer: 'did:web:localhost:5173:did:bank',
                            issuanceDate: '2025-09-22T10:58:02.689Z',
                            subject: 'did:web:localhost:5173:did:phong',
                            credentialSubject: {
                                id: 'did:web:localhost:5173:did:phong',
                                roles: {
                                    READ_BANK_ACCOUNT: 'Allow to read account balance',
                                    MAKE_TRANSACTION: 'Allow to make a transaction'
                                }
                            },
                            expirationDate: '2025-10-22T10:58:02.688Z',
                            proof: {
                                type: 'Ed25519Signature2020',
                                created: '2025-09-22T10:58:02.689Z',
                                proofPurpose: 'assertionMethod',
                                verificationMethod: 'did:web:localhost:5173:did:bank#keys-1',
                                jws: 'VFGgBbNcoB2l9-ROlKCUoWF7kxPjYjcthzXXmomdWpEnfAQ4X-AYDSwqXbpSIQ17jzLZsKLkodMMkWkxiykXCg'
                            }
                        }
                    },
                    proof: {
                        type: 'Ed25519Signature2020',
                        created: '2025-09-22T11:07:20.633Z',
                        proofPurpose: 'delegation',
                        verificationMethod: 'did:web:localhost:5173:did:phong#keys-1',
                        jws: 'zYyptVIlNAHEcK8HIfM1h9KywTjIgUHtaiaubkPwdadnMcJLMJ2VkXsxTYvhc8Lcu_rHJZvprTUQFwVuOeKDBA'
                    }
                }
            ],
            holder: 'did:web:localhost:5173:did:momo',
            challenge: '537363646',
            proof: {
                type: 'Ed25519Signature2020',
                created: '2025-09-22T11:16:25.268Z',
                proofPurpose: 'authentication',
                verificationMethod: 'did:web:localhost:5173:did:momo#keys-1',
                challenge: '537363646',
                jws: 'uVFDz_Gb1uPu76sSFs-mgwEO0LLHJvO5DFNcgnndEsgEHMPrO336dBqWdNU2re0Wtpep65f5aMBl2n2wzZ_LAA'
            }
        }

        const nonce = '5373636462';
        const res = await verifyVP(vp, 'did:web:localhost:5173:did:momo', 'did:web:localhost:5173:did:phong', nonce, 'did:web:localhost:5173:did:bank', { protocol: 'http' })

        console.log("✅ Build OK\n", res);
    } catch (err) {
        // This will trigger until you implement createVC (your stub throws)
        console.error("❌ Build OK, but post-build call failed:", err?.message || err);
    }
}

main();
