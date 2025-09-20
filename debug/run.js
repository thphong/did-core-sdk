// scripts/after-build.js
//import { didIOTA } from "../dist/index.cjs";


async function main() {
    try {
        const publicKeyJwk = {
            "key_ops": ["verify"],
            "ext": true,
            "crv": "Ed25519",
            "x": "dndYUDi2-EmghxLqvTmvWXJeXALhA4xKwo1vE8NYIiE",
            "kty": "OKP",
            "alg": "Ed25519"
        }

        const privateKeyJwk = {
            "key_ops": ["sign"],
            "ext": true,
            "crv": "Ed25519",
            "d": "MbOljBwnJVYewUprjUnGeDlOgZhdne2HiyqR3Fo3q8M",
            "x": "dndYUDi2-EmghxLqvTmvWXJeXALhA4xKwo1vE8NYIiE",
            "kty": "OKP",
            "alg": "Ed25519"
        }

        //const mnemonic = await generateMnemonic();
        // const doc = await didIOTA.create(publicKeyJwk)
        console.log("✅ Build OK. Sample doc:\n");
    } catch (err) {
        // This will trigger until you implement createVC (your stub throws)
        console.error("❌ Build OK, but post-build call failed:", err?.message || err);
    }
}

main();
