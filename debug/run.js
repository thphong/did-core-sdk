// scripts/after-build.js
import { createKeyPair, sign, verify } from "../dist/index.cjs";

async function main() {
    try {
        // const vc = await createVC({
        //     subjectDid: "did:example:123",
        //     issuerDid: "did:example:issuer",
        //     claims: { name: "Alice" }
        // });
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
        const message = new TextEncoder().encode("Hello world").buffer;
        const message2 = new TextEncoder().encode("Hello world ").buffer;
        console.log("message: \n", message);
        const sig = await sign(message2, privateKeyJwk);
        console.log("✅ Build OK. Sample result:\n", sig);
        const ver = await verify(message2, sig, publicKeyJwk);
        console.log("✅ Build OK. Sample result:\n", ver);
    } catch (err) {
        // This will trigger until you implement createVC (your stub throws)
        console.error("✅ Build OK, but post-build call failed:", err?.message || err);
    }
}

main();
