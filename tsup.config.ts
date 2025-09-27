import { defineConfig } from "tsup";

export default defineConfig({
    entry: ["src/index.ts"],
    dts: true,
    sourcemap: true,
    clean: true,
    format: ["esm", "cjs"],
    outDir: "dist",
    minify: false,
    platform: "browser",   // isomorphic: avoids bundling node builtins
    target: "es2020",
    treeshake: true,
});

