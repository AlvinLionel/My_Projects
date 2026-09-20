import { CryptoError } from "./error";
import type { CryptoProgress } from "./aes";

export type RsaAlgorithm = "RSA-2048" | "RSA-3072" | "RSA-4096";

export interface RsaKeyPairPem {
    publicKey: string;
    privateKey: string;
}
export interface RsaEncryptionResult {
    algorithm: RsaAlgorithm;
    ciphertext: Uint8Array<ArrayBuffer>;
    iv: Uint8Array<ArrayBuffer>;
    wrappedKey: Uint8Array<ArrayBuffer>;
}

const RSA_HASH = "SHA-256";
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";

    for (const byte of bytes) binary += String.fromCharCode(byte);

    return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
    const binary = atob(value);
    const bytes = new Uint8Array(new ArrayBuffer(binary.length));

    for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);

    return bytes;
}

function toPem(bytes: ArrayBuffer, label: string): string {
    const base64 = bytesToBase64(new Uint8Array(bytes));
    const lines = base64.match(/.{1,64}/g)?.join("\n") ?? "";

    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function fromPem(pem: string, label: string): ArrayBuffer {
    const normalized = pem
        .replace(`-----BEGIN ${label}-----`, "")
        .replace(`-----END ${label}-----`, "")
        .replace(/\s/g, "");

    if (!normalized) throw new Error(`A ${label.toLowerCase()} is required.`);

    return base64ToBytes(normalized).buffer;
}

function rsaAlgorithm(modulusLength: number): RsaHashedKeyGenParams {
    return {
        name: "RSA-OAEP",
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: RSA_HASH,
    };
}

function modulusLength(algorithm: RsaAlgorithm): number {
    return Number(algorithm.slice(4));
}

export async function generateRsaKeyPair(algorithm: RsaAlgorithm): Promise<RsaKeyPairPem> {
    const keyPair = await crypto.subtle.generateKey(
        rsaAlgorithm(modulusLength(algorithm)),
        true,
        ["encrypt", "decrypt"]
    );
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
        publicKey: toPem(publicKey, "PUBLIC KEY"),
        privateKey: toPem(privateKey, "PRIVATE KEY"),
    };
}

async function importPublicKey(publicKey: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "spki",
        fromPem(publicKey, "PUBLIC KEY"),
        { name: "RSA-OAEP", hash: RSA_HASH },
        false,
        ["encrypt"]
    );
}

async function importPrivateKey(privateKey: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "pkcs8",
        fromPem(privateKey, "PRIVATE KEY"),
        { name: "RSA-OAEP", hash: RSA_HASH },
        false,
        ["decrypt"]
    );
}

export async function encryptRsaText(plaintext: string, publicKey: string, algorithm: RsaAlgorithm, onProgress?: CryptoProgress): Promise<RsaEncryptionResult> {
    try {
        onProgress?.(1);
        const key = await importPublicKey(publicKey);
        const contentKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: AES_KEY_LENGTH },
            true,
            ["encrypt", "decrypt"]
        );
        const rawContentKey = new Uint8Array(await crypto.subtle.exportKey("raw", contentKey));
        const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

        onProgress?.(2);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            contentKey,
            new TextEncoder().encode(plaintext)
        ));

        onProgress?.(3);
        const wrappedKey = new Uint8Array(await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            key,
            rawContentKey
        ));

        return { algorithm, ciphertext, iv, wrappedKey };
    } catch {
        throw new CryptoError("ENCRYPTION_FAILED", "The resource could not be encrypted with the supplied public key.");
    }
}

export async function decryptRsaText(ciphertext: Uint8Array<ArrayBuffer>, wrappedKey: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, privateKey: string, onProgress?: CryptoProgress): Promise<string> {
    try {
        onProgress?.(2);
        const key = await importPrivateKey(privateKey);
        const rawContentKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, wrappedKey);
        const contentKey = await crypto.subtle.importKey(
            "raw",
            rawContentKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        onProgress?.(3);
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, contentKey, ciphertext);

        return new TextDecoder().decode(plaintext);
    } catch {
        throw new CryptoError("AUTHENTICATION_FAILED", "The private key is incorrect or the encrypted resource has been modified.");
    }
}
