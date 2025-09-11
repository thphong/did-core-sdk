// scripts/after-build.js
import { createVC } from "../dist/index.cjs";

async function main() {
    try {
        const vc = await createVC({
            subjectDid: "did:example:123",
            issuerDid: "did:example:issuer",
            claims: { name: "Alice" }
        });
        console.log("✅ Build OK. Sample VC:\n", JSON.stringify(vc, null, 2));
    } catch (err) {
        // This will trigger until you implement createVC (your stub throws)
        console.error("✅ Build OK, but post-build call failed:", err?.message || err);
    }
}

main();
