import type { EncryptionResult } from "./aes";
import { CryptoError } from "./error";
import type { SymmetricAlgorithm } from "./KeyDerivation";
import type { RsaAlgorithm, RsaEncryptionResult } from "./rsa";
import type { KeyExchangeAlgorithm } from "./keyExchange";
import type { ResourceType } from "./resourceCrypto";

export type KeyDerivationScheme = "HKDF-SHA-256";
export type ProtectionMode = "lock";

const PACKAGE_PREFIX = "LBX1";
const SUPPORTED_ALGORITHMS: SymmetricAlgorithm[] = [
    "AES-256-GCM",
    "AES-128-GCM",
    "ChaCha20-Poly1305",
    "XChaCha20-Poly1305",
];
const SUPPORTED_RSA_ALGORITHMS: RsaAlgorithm[] = ["RSA-2048", "RSA-3072", "RSA-4096"];

interface CommonPackageFields {
    version: 1;
    resourceType: ResourceType;
    filename?: string;
    mimeType?: string;
    iv: string;
    ciphertext: string;
    keyExchangeAlgorithm?: KeyExchangeAlgorithm;
    keyDerivation?: KeyDerivationScheme;
    protectionMode?: ProtectionMode;
    senderPublicKey?: string;
    folderName?: string;
    folderFileCount?: number;
    folderCount?: number;
}

export interface SymmetricLockBoxPackage extends CommonPackageFields {
    algorithm: SymmetricAlgorithm;
    salt: string;
}

export interface RsaLockBoxPackage extends CommonPackageFields {
    algorithm: RsaAlgorithm;
    wrappedKey: string;
}

export type LockBoxPackage = SymmetricLockBoxPackage | RsaLockBoxPackage;

export interface UnpackagedSymmetricPackage {
    resourceType: ResourceType;
    algorithm: SymmetricAlgorithm;
    filename?: string;
    mimeType?: string;
    salt: Uint8Array<ArrayBuffer>;
    iv: Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<ArrayBuffer>;
    keyExchangeAlgorithm?: KeyExchangeAlgorithm;
    keyDerivation?: KeyDerivationScheme;
    protectionMode?: ProtectionMode;
    senderPublicKey?: string;
    folderName?: string;
    folderFileCount?: number;
    folderCount?: number;
}

export interface UnpackagedRsaPackage {
    resourceType: ResourceType;
    algorithm: RsaAlgorithm;
    filename?: string;
    mimeType?: string;
    iv: Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<ArrayBuffer>;
    wrappedKey: Uint8Array<ArrayBuffer>;
    keyExchangeAlgorithm?: KeyExchangeAlgorithm;
    keyDerivation?: KeyDerivationScheme;
    protectionMode?: ProtectionMode;
    senderPublicKey?: string;
    folderName?: string;
    folderFileCount?: number;
    folderCount?: number;
}
export interface ResourceMetadata {
    resourceType: ResourceType;
    filename?: string;
    mimeType?: string;
    folderName?: string;
    folderFileCount?: number;
    folderCount?: number;
    keyExchangeAlgorithm?: KeyExchangeAlgorithm;
    keyDerivation?: KeyDerivationScheme;
    protectionMode?: ProtectionMode;
    senderPublicKey?: string;
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";

    for (const byte of bytes) binary += String.fromCharCode(byte);

    return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
    const binary = atob(base64);
    const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(new ArrayBuffer(binary.length));

    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

    return bytes;
}

export function createPackage(result: EncryptionResult, metadata: ResourceMetadata): string {
    const packageData: SymmetricLockBoxPackage = {
        version: 1,
        algorithm: result.algorithm,
        resourceType: metadata.resourceType,
        filename: metadata.filename,
        mimeType: metadata.mimeType,
        keyExchangeAlgorithm: metadata.keyExchangeAlgorithm,
        keyDerivation: metadata.keyDerivation,
        protectionMode: metadata.protectionMode,
        senderPublicKey: metadata.senderPublicKey,
        folderName: metadata.folderName,
        folderFileCount: metadata.folderFileCount,
        folderCount: metadata.folderCount,
        salt: bytesToBase64(result.salt),
        iv: bytesToBase64(result.iv),
        ciphertext: bytesToBase64(result.ciphertext),
    };
    return `${PACKAGE_PREFIX}.${JSON.stringify(packageData)}`;
}

export function createRsaPackage(result: RsaEncryptionResult, metadata: ResourceMetadata): string {
    const packageData: RsaLockBoxPackage = {
        version: 1,
        algorithm: result.algorithm,
        resourceType: metadata.resourceType,
        filename: metadata.filename,
        mimeType: metadata.mimeType,
        keyExchangeAlgorithm: metadata.keyExchangeAlgorithm,
        senderPublicKey: metadata.senderPublicKey,
        folderName: metadata.folderName,
        folderFileCount: metadata.folderFileCount,
        folderCount: metadata.folderCount,
        iv: bytesToBase64(result.iv),
        ciphertext: bytesToBase64(result.ciphertext),
        wrappedKey: bytesToBase64(result.wrappedKey),
    };
    return `${PACKAGE_PREFIX}.${JSON.stringify(packageData)}`;
}

export function parsePackage(encryptedPackage: string): LockBoxPackage {
    if (!encryptedPackage.startsWith(`${PACKAGE_PREFIX}.`)) throw new CryptoError("INVALID_PACKAGE", "This does not appear to be a valid LockBoxX package");

    const encodedData = encryptedPackage.slice(PACKAGE_PREFIX.length + 1);
    let packageData: LockBoxPackage;

    try {
        try {
            packageData = JSON.parse(encodedData);
        } catch {
            packageData = JSON.parse(atob(encodedData));
        }
    } catch { throw new Error("Corrupted LockBoxX package") }

    const isSymmetric = SUPPORTED_ALGORITHMS.includes(packageData.algorithm as SymmetricAlgorithm);
    const isRsa = SUPPORTED_RSA_ALGORITHMS.includes(packageData.algorithm as RsaAlgorithm);
    const hasRequiredFields = packageData.version === 1 && !!packageData.resourceType && !!packageData.iv && !!packageData.ciphertext;
    const hasSymmetricFields = isSymmetric && "salt" in packageData && !!packageData.salt;
    const hasRsaFields = isRsa && "wrappedKey" in packageData && !!packageData.wrappedKey;

    if (!hasRequiredFields || (!hasSymmetricFields && !hasRsaFields))
        throw new CryptoError("INVALID_PACKAGE", "The LockBoxX package is missing required encryption data.");

    return packageData;
}

export function unpackage(encryptedPackage: string): UnpackagedSymmetricPackage | UnpackagedRsaPackage {
    const packageData = parsePackage(encryptedPackage);

    if ("salt" in packageData) {
        return {
            resourceType: packageData.resourceType,
            algorithm: packageData.algorithm,
            filename: packageData.filename,
            mimeType: packageData.mimeType,
            salt: base64ToBytes(packageData.salt),
            iv: base64ToBytes(packageData.iv),
            ciphertext: base64ToBytes(packageData.ciphertext),
            keyExchangeAlgorithm: packageData.keyExchangeAlgorithm,
            keyDerivation: packageData.keyDerivation,
            protectionMode: packageData.protectionMode,
            senderPublicKey: packageData.senderPublicKey,
            folderName: packageData.folderName,
            folderFileCount: packageData.folderFileCount,
            folderCount: packageData.folderCount,
        };
    }

    return {
        resourceType: packageData.resourceType,
        algorithm: packageData.algorithm,
        filename: packageData.filename,
        mimeType: packageData.mimeType,
        iv: base64ToBytes(packageData.iv),
        ciphertext: base64ToBytes(packageData.ciphertext),
        wrappedKey: base64ToBytes(packageData.wrappedKey),
        keyExchangeAlgorithm: packageData.keyExchangeAlgorithm,
        keyDerivation: packageData.keyDerivation,
        protectionMode: packageData.protectionMode,
        senderPublicKey: packageData.senderPublicKey,
        folderName: packageData.folderName,
        folderFileCount: packageData.folderFileCount,
        folderCount: packageData.folderCount,
    };
}

export function isPackageValid(packageString: string): boolean {
    try {
        const packageData = parsePackage(packageString);

        return (
            packageData.version === 1 &&
            (SUPPORTED_ALGORITHMS.includes(packageData.algorithm as SymmetricAlgorithm) ||
                SUPPORTED_RSA_ALGORITHMS.includes(packageData.algorithm as RsaAlgorithm)) &&
            typeof packageData.resourceType === "string" &&
            (("salt" in packageData && typeof packageData.salt === "string") ||
                ("wrappedKey" in packageData && typeof packageData.wrappedKey === "string")) &&
            typeof packageData.iv === "string" &&
            typeof packageData.ciphertext === "string"
        );
    } catch {
        return false;
    }
}
