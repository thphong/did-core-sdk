import { inflate } from "pako";
import {
  RoaringBitmap32,
  roaringLibraryInitialize,
  SerializationFormat,
} from "roaring-wasm";

/**
 * Base64 string → Uint8Array
 * Chạy được cả browser (atob) và Node (Buffer).
 */
function base64ToUint8Array(base64: string): Uint8Array {
  if (typeof atob === "function") {
    // Browser / extension
    const binary = atob(base64);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } else {
    // Node
    // eslint-disable-next-line no-undef
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
}

/**
 * Đảm bảo roaring-wasm chỉ init 1 lần, tránh dùng top-level await.
 */
let roaringInitPromise: Promise<void> | null = null;

async function ensureRoaringInitialized(): Promise<void> {
  if (!roaringInitPromise) {
    roaringInitPromise = roaringLibraryInitialize();
  }
  return roaringInitPromise;
}

/**
 * Kiểm tra 1 index trong RevocationBitmap2022 có bị revoke không.
 *
 * @param serviceEndpoint Giá trị serviceEndpoint trong DID Document
 *   dạng: "data:application/octet-stream;base64,<...>"
 * @param index revocationBitmapIndex (number)
 * @returns true nếu VC bị revoke, false nếu chưa.
 */
export async function isRevokedFromServiceEndpoint(
  serviceEndpoint: string,
  index: number,
): Promise<boolean> {
  const prefix = "data:application/octet-stream;base64,";
  if (!serviceEndpoint.startsWith(prefix)) {
    throw new Error("serviceEndpoint không đúng format RevocationBitmap2022 (data:application/octet-stream;base64,...)");
  }

  // 1. Tách base64 phần payload
  const base64 = serviceEndpoint.slice(prefix.length);
  if (!base64) {
    throw new Error("serviceEndpoint không có payload base64");
  }

  // 2. Base64 decode → Uint8Array (compressed)
  const compressed = base64ToUint8Array(base64);

  // 3. Inflate bằng pako (chạy được cả Node và browser)
  const uncompressed: Uint8Array = inflate(compressed);

  // 4. Init roaring-wasm (một lần)
  await ensureRoaringInitialized();

  // 5. Deserialize roaring bitmap (format portable/standard)
  const bitmap = RoaringBitmap32.deserialize(
    uncompressed,
    SerializationFormat.portable,
  );

  try {
    // 6. Theo spec: bit = 1 ⇒ revoked, 0 ⇒ not revoked
    const revoked = bitmap.has(index);
    return revoked;
  } finally {
    bitmap.dispose?.();
  }
}