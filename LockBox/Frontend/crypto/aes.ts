import { CryptoError } from "./error";
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { deriveKey, deriveKeyBytes, type SymmetricAlgorithm } from "./KeyDerivation";
import { base64ToBytes } from "./package";

const SALT_LENGTH = 16;

export interface EncryptionResult {
    ciphertext: Uint8Array<ArrayBuffer>,
    salt: Uint8Array<ArrayBuffer>,
    iv: Uint8Array<ArrayBuffer>,
    algorithm: SymmetricAlgorithm,
}

export type CryptoProgress = (step: number) => void;

export async function encryptText(plaintext: string, password: string, onProgress?: CryptoProgress, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<EncryptionResult> {
    const data = new TextEncoder().encode(plaintext);

    return encryptBytes(data, password, onProgress, algorithm);
}

export async function decryptText(ciphertext: Uint8Array<ArrayBuffer>, password: string, salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, onProgress?: CryptoProgress, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<string> {
    const decryptedBytes = await decryptBytes(ciphertext, password, salt, iv, onProgress,algorithm);

    return new TextDecoder().decode(decryptedBytes);
}

export async function encryptBytes(data: Uint8Array<ArrayBuffer>, password: string, onProgress?: CryptoProgress, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<EncryptionResult> {
    onProgress?.(1);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(algorithm === "XChaCha20-Poly1305" ? 24 : 12));
    onProgress?.(2);

    try {
        onProgress?.(3);
        let encryptedBytes: Uint8Array<ArrayBuffer>;

        if (algorithm === "ChaCha20-Poly1305") {
            const key = await deriveKeyBytes(password, salt, algorithm);
            encryptedBytes = chacha20poly1305(key, iv).encrypt(data) as Uint8Array<ArrayBuffer>;
        } else if (algorithm === "XChaCha20-Poly1305") {
            const key = await deriveKeyBytes(password, salt, algorithm);
            encryptedBytes = xchacha20poly1305(key, iv).encrypt(data) as Uint8Array<ArrayBuffer>;
        } else {
            const key = await deriveKey(password, salt, algorithm);
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                key,
                data
            );
            encryptedBytes = new Uint8Array(encryptedBuffer) as Uint8Array<ArrayBuffer>;
        }

        return { ciphertext: encryptedBytes, salt, iv, algorithm };
    } catch {
        throw new CryptoError("ENCRYPTION_FAILED", "The resource could not be encrypted.");
    }
}

export async function encryptBytesWithSharedSecret(data: Uint8Array<ArrayBuffer>, sharedSecret:string, onProgress?:CryptoProgress): Promise<EncryptionResult>{
    onProgress?.(1);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    onProgress?.(2);

    try{
        onProgress?.(3);
        const encryptionKey = await deriveSharedSecretKey(sharedSecret, salt, ["encrypt"]);
        const encryptedBuffer= await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            encryptionKey,
            data
        );
        const encryptedBytes = new Uint8Array(encryptedBuffer) as Uint8Array<ArrayBuffer>;

        return {
            ciphertext: encryptedBytes,
            salt,
            iv,
            algorithm: "AES-256-GCM"
        };
    }catch{
        throw new CryptoError("ENCRYPTION_FAILED", "The resource could not be encrypted");
    }
}

export async function encryptTextWithSharedSecret(text:string,sharedSecret:string,onProgress?:CryptoProgress): Promise<EncryptionResult>{
    const encoder = new TextEncoder();

    return encryptBytesWithSharedSecret(
        encoder.encode(text),
        sharedSecret,
        onProgress
    );
}

async function deriveSharedSecretKey(sharedSecret: string, salt: Uint8Array<ArrayBuffer>, usages: KeyUsage[]): Promise<CryptoKey> {
    const hkdfKey = await crypto.subtle.importKey(
        "raw",
        base64ToBytes(sharedSecret),
        "HKDF",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt,
            info: new TextEncoder().encode("LockBox key-exchange encryption key"),
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        usages
    );
}

export async function decryptBytesWithSharedSecret(ciphertext: Uint8Array<ArrayBuffer>, sharedSecret: string, salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, onProgress?: CryptoProgress): Promise<Uint8Array<ArrayBuffer>> {
    onProgress?.(2);

    try {
        onProgress?.(3);
        const decryptionKey = await deriveSharedSecretKey(sharedSecret, salt, ["decrypt"]);
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            decryptionKey,
            ciphertext
        );

        return new Uint8Array(decryptedBuffer) as Uint8Array<ArrayBuffer>;
    } catch {
        throw new CryptoError("AUTHENTICATION_FAILED", "The shared secret is incorrect or the encrypted resource has been modified.");
    }
}

export async function decryptTextWithSharedSecret(ciphertext: Uint8Array<ArrayBuffer>, sharedSecret: string, salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, onProgress?: CryptoProgress): Promise<string> {
    const decryptedBytes = await decryptBytesWithSharedSecret(ciphertext, sharedSecret, salt, iv, onProgress);

    return new TextDecoder().decode(decryptedBytes);
}

export async function decryptBytes(ciphertext: Uint8Array<ArrayBuffer>, password: string, salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>, onProgress?: CryptoProgress, algorithm: SymmetricAlgorithm = "AES-256-GCM"): Promise<Uint8Array<ArrayBuffer>> {
    onProgress?.(2);

    try {
        onProgress?.(3);
        let decryptedBytes: Uint8Array<ArrayBuffer>;

        if (algorithm === "ChaCha20-Poly1305") {
            const key = await deriveKeyBytes(password, salt, algorithm);
            decryptedBytes = chacha20poly1305(key, iv).decrypt(ciphertext) as Uint8Array<ArrayBuffer>;
        } else if (algorithm === "XChaCha20-Poly1305") {
            const key = await deriveKeyBytes(password, salt, algorithm);
            decryptedBytes = xchacha20poly1305(key, iv).decrypt(ciphertext) as Uint8Array<ArrayBuffer>;
        } else {
            const key = await deriveKey(password, salt, algorithm);
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                ciphertext
            );
            decryptedBytes = new Uint8Array(decryptedBuffer) as Uint8Array<ArrayBuffer>;
        }

        return decryptedBytes;
    } catch {
        throw new CryptoError("AUTHENTICATION_FAILED", "The password is incorrect or the encryption resource has been modified");
    }
}
