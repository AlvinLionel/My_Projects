import { decryptBytes, decryptBytesWithSharedSecret, encryptBytes, encryptBytesWithSharedSecret, type CryptoProgress, type EncryptionResult } from "./aes";
import { base64ToBytes, parsePackage } from "./package";
import type { SymmetricAlgorithm } from "./KeyDerivation";

export type ResourceType = "text" | "file" | "image" | "audio" | "video" | "folder";

export async function resourceToBytes(resource: string | File, resourceType: ResourceType): Promise<Uint8Array<ArrayBuffer>> {
    if (resourceType === "text")
        return new TextEncoder().encode(resource as string) as Uint8Array<ArrayBuffer>;

    if (resourceType === "file" || resourceType === "image" || resourceType === "audio" || resourceType === "video" || resourceType === "folder") {
        if (!(resource instanceof File))
            throw new Error("A file resource is required");

        const buffer = await resource.arrayBuffer();
        return new Uint8Array(buffer) as Uint8Array<ArrayBuffer>;
    }

    throw new Error(`Unsupported resource type: ${resourceType}`);
}
export async function encryptResource(resource: string | File, resourceType: ResourceType, password: string, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<EncryptionResult> {
    const bytes: Uint8Array<ArrayBuffer> = await resourceToBytes(resource, resourceType);

    return encryptBytes(bytes, password, undefined, algorithm);
}
export async function decryptResource(ciphertext: Uint8Array<ArrayBuffer>, password: string, salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, resourceType: ResourceType, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<string | Uint8Array> {
    const decryptedBytes = await decryptBytes(ciphertext, password, salt, iv, undefined, algorithm);
    if (resourceType === "text")
        return new TextDecoder().decode(decryptedBytes);

    return decryptedBytes;
}

export async function encryptFile(file: File, resourceType: ResourceType, password: string, onProgress?: CryptoProgress, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<{
    result: EncryptionResult;
    metadata: {
        resourceType: ResourceType;
        filename: string; mimeType:
        string
    };
}> {
    const bytes = await resourceToBytes(file, resourceType);
    const result = await encryptBytes(bytes, password, onProgress, algorithm);

    return {
        result,
        metadata: {
            resourceType,
            filename: file.name,
            mimeType: file.type || "application/octet-stream",
        }
    };
}

export async function encryptFileWithSharedSecret(file: File, resourceType: ResourceType, sharedSecret: string, onProgress?: CryptoProgress): Promise<{
    result: EncryptionResult;
    metadata: { resourceType: ResourceType; filename: string; mimeType: string };
}> {
    const bytes = await resourceToBytes(file, resourceType);
    const result = await encryptBytesWithSharedSecret(bytes, sharedSecret, onProgress);

    return {
        result,
        metadata: {
            resourceType,
            filename: file.name,
            mimeType: file.type || "application/octet-stream",
        },
    };
}

export async function decryptFile(packageString: string, password: string, onProgress?: CryptoProgress): Promise<File> {
    const packageData = parsePackage(packageString);
    if (!("salt" in packageData)) {
        throw new Error("RSA packages can only contain text resources.");
    }
    const salt = base64ToBytes(packageData.salt);
    const iv = base64ToBytes(packageData.iv);
    const ciphertext = base64ToBytes(packageData.ciphertext);
    const decryptedBytes = await decryptBytes(ciphertext, password, salt, iv, onProgress, packageData.algorithm);

    const decryptedBlob = new Blob(
        [decryptedBytes.buffer as ArrayBuffer],
        { type: packageData.mimeType || "application/octet-stream" }
    );

    return new File(
        [decryptedBlob],
        packageData.filename || "decrypted-file",
        { type: decryptedBlob.type }
    );
}

export async function decryptFileWithSharedSecret(packageString: string, sharedSecret: string, onProgress?: CryptoProgress): Promise<File> {
    const packageData = parsePackage(packageString);
    if (!("salt" in packageData)) throw new Error("RSA packages can only contain text resources.");

    const decryptedBytes = await decryptBytesWithSharedSecret(
        base64ToBytes(packageData.ciphertext),
        sharedSecret,
        base64ToBytes(packageData.salt),
        base64ToBytes(packageData.iv),
        onProgress
    );
    const decryptedBlob = new Blob(
        [decryptedBytes.buffer as ArrayBuffer],
        { type: packageData.mimeType || "application/octet-stream" }
    );

    return new File(
        [decryptedBlob],
        packageData.filename || "decrypted-file",
        { type: decryptedBlob.type }
    );
}

export function downloadFile(file: File): void {
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = file.name;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}
