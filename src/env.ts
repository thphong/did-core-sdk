export type Runtime = "web" | "react-native" | "node";

export const runtime: Runtime = (() => {
    // @ts-ignore
    if (typeof navigator !== "undefined" && navigator.product === "ReactNative") return "react-native";
    if (typeof window !== "undefined" && typeof document !== "undefined") return "web";
    return "node";
})();
