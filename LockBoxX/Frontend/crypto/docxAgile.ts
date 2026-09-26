import { cbc } from "@noble/ciphers/aes.js";
import * as CFB from "cfb";

export interface AgileEncryptionInfo {
    package: {
        saltValue: Uint8Array;
        blockSize: number;
        keyBits: number;
        hashSize: number;
        cipherAlgorithm: string;
        cipherChaining: string;
        hashAlgorithm: string;
    };
    dataIntegrity: {
        encryptedHmacKey: Uint8Array;
        encryptedHmacValue: Uint8Array;
    };
    key: {
        spinCount: number;
        saltValue: Uint8Array;
        blockSize: number;
        keyBits: number;
        hashSize: number;
        cipherAlgorithm: string;
        cipherChaining: string;
        hashAlgorithm: string;
        encryptedVerifierHashInput: Uint8Array;
        encryptedVerifierHashValue: Uint8Array;
        encryptedKeyValue: Uint8Array;
    };
}

const AGILE_BLOCK_KEYS = {
    verifierHashInput: new Uint8Array([
        0xfe, 0xa7, 0xd2, 0x76,
        0x3b, 0x4b, 0x9e, 0x79,
    ]),
    verifierHashValue: new Uint8Array([
        0xd7, 0xaa, 0x0f, 0x6d,
        0x30, 0x61, 0x34, 0x4e,
    ]),
    encryptedKeyValue: new Uint8Array([
        0x14, 0x6e, 0x0b, 0xe7,
        0xab, 0xac, 0xd0, 0xd6,
    ]),
    dataIntegrityHmacKey: new Uint8Array([
        0x5f, 0xb2, 0xad, 0x01,
        0x0c, 0xb9, 0xe1, 0xf6,
    ]),
    dataIntegrityHmacValue: new Uint8Array([
        0xa0, 0x67, 0x7f, 0x02,
        0xb2, 0x2c, 0x84, 0x33,
    ]),
};

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((total, array) => total + array.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
}

export async function sha512(data: Uint8Array): Promise<Uint8Array> {
    const exactData = data.slice();
    const digest = await crypto.subtle.digest("SHA-512", exactData.buffer as ArrayBuffer);

    return new Uint8Array(digest);
}

async function hmacSha512(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key.slice().buffer as ArrayBuffer,
        { name: "HMAC", hash: "SHA-512", },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        data.slice().buffer as ArrayBuffer
    );

    return new Uint8Array(signature);
}

export async function createDataIntegrity(packageKey: Uint8Array, salt: Uint8Array, encryptedPackage: Uint8Array): Promise<{ hmacKey: Uint8Array; hmacValue: Uint8Array; encryptedHmacKey: Uint8Array; encryptedHmacValue: Uint8Array; }> {
    const hmacKey = randomBytes(64);
    const hmacValue = await hmacSha512(hmacKey, encryptedPackage);
    const hmacKeyIv = await createAgileIv(salt, AGILE_BLOCK_KEYS.dataIntegrityHmacKey);
    const encryptedHmacKey = await aesCbcEncrypt(hmacKey, packageKey, hmacKeyIv);
    const hmacValueIv = await createAgileIv(salt, AGILE_BLOCK_KEYS.dataIntegrityHmacValue);
    const encryptedHmacValue = await aesCbcEncrypt(hmacValue, packageKey, hmacValueIv);

    return { hmacKey, hmacValue, encryptedHmacKey, encryptedHmacValue };
}

export function createAgileEncryptionInfo(
    packageSalt: Uint8Array,
    verifier: {
        salt: Uint8Array;
        encryptedVerifierHashInput: Uint8Array;
        encryptedVerifierHashValue: Uint8Array;
    },
    dataIntegrity: {
        encryptedHmacKey: Uint8Array;
        encryptedHmacValue: Uint8Array;
    },
    encryptedPackageKey: Uint8Array
): AgileEncryptionInfo {
    return {
        package: {
            saltValue: packageSalt,
            blockSize: 16,
            keyBits: 256,
            hashSize: 64,
            cipherAlgorithm: "AES",
            cipherChaining: "ChainingModeCBC",
            hashAlgorithm: "SHA512",
        },
        dataIntegrity: {
            encryptedHmacKey:
                dataIntegrity.encryptedHmacKey,

            encryptedHmacValue:
                dataIntegrity.encryptedHmacValue,
        },
        key: {
            spinCount: 100000,
            saltValue: verifier.salt,
            blockSize: 16,
            keyBits: 256,
            hashSize: 64,
            cipherAlgorithm: "AES",
            cipherChaining: "ChainingModeCBC",
            hashAlgorithm: "SHA512",
            encryptedVerifierHashInput: verifier.encryptedVerifierHashInput,
            encryptedVerifierHashValue: verifier.encryptedVerifierHashValue,
            encryptedKeyValue: encryptedPackageKey,
        },
    };
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function escapeXml(value: string): string {
    return value
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

export function buildAgileEncryptionInfoXml(encryptionInfo: AgileEncryptionInfo): string {
    const pkg = encryptionInfo.package;
    const integrity = encryptionInfo.dataIntegrity;
    const key = encryptionInfo.key;

    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <encryption
        xmlns="http://schemas.microsoft.com/office/2006/encryption"
        xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password"
        xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
        <keyData
            saltSize="${pkg.saltValue.length}"
            blockSize="${pkg.blockSize}"
            keyBits="${pkg.keyBits}"
            hashSize="${pkg.hashSize}"
            cipherAlgorithm="${escapeXml(pkg.cipherAlgorithm)}"
            cipherChaining="${escapeXml(pkg.cipherChaining)}"
            hashAlgorithm="${escapeXml(pkg.hashAlgorithm)}"
            saltValue="${bytesToBase64(pkg.saltValue)}"/>
        <dataIntegrity
            encryptedHmacKey="${bytesToBase64(integrity.encryptedHmacKey)}"
            encryptedHmacValue="${bytesToBase64(integrity.encryptedHmacValue)}"/>
        <keyEncryptors>
            <keyEncryptor
                uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
                <p:encryptedKey
                    spinCount="${key.spinCount}"
                    saltSize="${key.saltValue.length}"
                    blockSize="${key.blockSize}"
                    keyBits="${key.keyBits}"
                    hashSize="${key.hashSize}"
                    cipherAlgorithm="${escapeXml(key.cipherAlgorithm)}"
                    cipherChaining="${escapeXml(key.cipherChaining)}"
                    hashAlgorithm="${escapeXml(key.hashAlgorithm)}"
                    saltValue="${bytesToBase64(key.saltValue)}"
                    encryptedVerifierHashInput="${bytesToBase64(key.encryptedVerifierHashInput)}"
                    encryptedVerifierHashValue="${bytesToBase64(key.encryptedVerifierHashValue)}"
                    encryptedKeyValue="${bytesToBase64(key.encryptedKeyValue)}"/>
            </keyEncryptor>
        </keyEncryptors>
    </encryption>`;
}
function buildDataSpacesVersion(): Uint8Array {
    const buffer = new ArrayBuffer(4);
    new DataView(buffer).setUint32(0, 1, true);
    return new Uint8Array(buffer);
}

function buildDataSpaceMap(): Uint8Array {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
        <DataSpaceMap xmlns="http://schemas.microsoft.com/office/2006/encryption">
            <DataSpace name="StrongEncryptionDataSpace">
                <Reference ref="EncryptedPackage"/>
            </DataSpace>
        </DataSpaceMap>`;
    return new TextEncoder().encode(xml);
}

function buildStrongEncryptionDataSpace(): Uint8Array {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
    <DataSpaceInfo xmlns="http://schemas.microsoft.com/office/2006/encryption">
        <DataSpace name="StrongEncryptionDataSpace">
            <Transform name="StrongEncryptionTransform"/>
        </DataSpace>
    </DataSpaceInfo>`;
    return new TextEncoder().encode(xml);
}

function buildStrongEncryptionTransform(): Uint8Array {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
        <TransformInfo xmlns="http://schemas.microsoft.com/office/2006/encryption">
            <Transform name="StrongEncryption"/>
        </TransformInfo>`;
    return new TextEncoder().encode(xml);
}

export function buildDocxEncryptionContainer(encryptionInfoXml: string, encryptedPackage: Uint8Array): Uint8Array {
    const encryptionInfoPrefix = new Uint8Array([
        0x04, 0x00, 0x04, 0x00,
        0x40, 0x00, 0x00, 0x00,
    ]);
    const encryptionInfoBytes = new TextEncoder().encode(encryptionInfoXml);
    const encryptionInfo = concatBytes(encryptionInfoPrefix, encryptionInfoBytes);
    const cfb = CFB.utils.cfb_new();

    CFB.utils.cfb_add(cfb, "EncryptionInfo", encryptionInfo);
    CFB.utils.cfb_add(cfb, "EncryptedPackage", encryptedPackage);
    CFB.utils.cfb_add(cfb, "DataSpaces/Version", buildDataSpacesVersion());
    CFB.utils.cfb_add(cfb, "DataSpaces/DataSpaceMap", buildDataSpaceMap());
    CFB.utils.cfb_add(cfb, "DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace", buildStrongEncryptionDataSpace());
    CFB.utils.cfb_add(cfb, "DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace/StrongEncryptionTransform", buildStrongEncryptionTransform());


    const result = CFB.write(cfb, { type: "buffer", });

    return new Uint8Array(result);
}

function createUInt32LE(value: number): Uint8Array {
    const buffer = new ArrayBuffer(4);
    const view = new DataView(buffer);

    view.setUint32(0, value, true);

    return new Uint8Array(buffer);
}

function createUInt64LE(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("Value must be a non-negative safe integer.");

    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    view.setUint32(0, value >>> 0, true);
    view.setUint32(4, Math.floor(value / 0x100000000), true);

    return new Uint8Array(buffer);
}

function randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
}

export async function convertPasswordToKey(password: string, saltValue: Uint8Array, spinCount: number, keyBits: number, blockKey: Uint8Array): Promise<Uint8Array> {
    const passwordBytes = new Uint8Array(password.length * 2);

    for (let i = 0; i < password.length; i++) {
        const code = password.charCodeAt(i);

        passwordBytes[i * 2] = code & 0xff;
        passwordBytes[i * 2 + 1] = code >>> 8;
    }

    let key = await sha512(concatBytes(saltValue, passwordBytes));

    for (let i = 0; i < spinCount; i++) {
        key = await sha512(concatBytes(createUInt32LE(i), key));
    }

    key = await sha512(concatBytes(key, blockKey));

    const keyBytes = keyBits / 8;

    if (key.length < keyBytes) {
        const padded = new Uint8Array(keyBytes);

        padded.fill(0x36);
        padded.set(key);

        key = padded;
    } else if (key.length > keyBytes) {
        key = key.slice(0, keyBytes);
    }

    return key;
}

export async function createAgileIv(saltValue: Uint8Array, blockKey: Uint8Array, blockSize = 16): Promise<Uint8Array> {
    const hash = await sha512(concatBytes(saltValue, blockKey));

    if (hash.length >= blockSize) return hash.slice(0, blockSize);

    const iv = new Uint8Array(blockSize);

    iv.fill(0x36);
    iv.set(hash);

    return iv;
}

export async function createPasswordVerifier(password: string): Promise<{ salt: Uint8Array; verifierHashInput: Uint8Array; encryptedVerifierHashInput: Uint8Array; encryptedVerifierHashValue: Uint8Array; }> {
    const salt = randomBytes(16);
    const verifierHashInput = randomBytes(16);
    const passwordKeyInput = await convertPasswordToKey(password, salt, 100000, 256, AGILE_BLOCK_KEYS.verifierHashInput);
    const passwordKeyHash = await convertPasswordToKey(password, salt, 100000, 256, AGILE_BLOCK_KEYS.verifierHashValue);
    const ivInput = salt;
    const ivHash = salt;
    const encryptedVerifierHashInput = await aesCbcEncrypt(verifierHashInput, passwordKeyInput, ivInput);
    const verifierHash = await sha512(verifierHashInput);
    const verifierHashPadded = new Uint8Array(64);

    verifierHashPadded.set(verifierHash);

    const encryptedVerifierHashValue = await aesCbcEncrypt(verifierHashPadded, passwordKeyHash, ivHash);

    return { salt, verifierHashInput, encryptedVerifierHashInput, encryptedVerifierHashValue, };
}

export async function createEncryptedPackageKey(password: string, salt: Uint8Array, packageKey: Uint8Array): Promise<Uint8Array> {
    if (packageKey.length !== 32) throw new Error("Agile package key must be 32 bytes.");

    const passwordKey = await convertPasswordToKey(password, salt, 100000, 256, AGILE_BLOCK_KEYS.encryptedKeyValue);
   const iv = salt;

    return aesCbcEncrypt(packageKey, passwordKey, iv);
}

const PACKAGE_CHUNK_SIZE = 4096;
const PACKAGE_BLOCK_SIZE = 16;

export async function encryptDocxPackage(data: Uint8Array, packageKey: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    if (packageKey.length !== 32) throw new Error("Agile package key must be 32 bytes.");

    if (salt.length !== 16) throw new Error("Agile package salt must be 16 bytes.");

    const packageLength = createUInt64LE(data.length);
    const encryptedChunks: Uint8Array[] = [];

    for (let offset = 0; offset < data.length; offset += PACKAGE_CHUNK_SIZE) {
        const chunk = data.slice(offset, Math.min(offset + PACKAGE_CHUNK_SIZE, data.length));
        let encryptedInput = chunk;
        const isFinalChunk = offset + chunk.length >= data.length;

        if (isFinalChunk && chunk.length % PACKAGE_BLOCK_SIZE !== 0) {
            const paddedLength = Math.ceil(chunk.length / PACKAGE_BLOCK_SIZE) * PACKAGE_BLOCK_SIZE;
            const paddedChunk = new Uint8Array(paddedLength);

            paddedChunk.set(chunk);
            encryptedInput = paddedChunk;
        }

        const chunkIndex = createUInt32LE(offset / PACKAGE_CHUNK_SIZE);
        const ivHash = await sha512(concatBytes(salt, chunkIndex));
        const iv = ivHash.slice(0, PACKAGE_BLOCK_SIZE);
        const encryptedChunk = await aesCbcEncrypt(encryptedInput, packageKey, iv);

        encryptedChunks.push(encryptedChunk);
    }

    return concatBytes(packageLength, ...encryptedChunks);
}

export async function decryptDocxPackage(encryptedData: Uint8Array, packageKey: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    if (packageKey.length !== 32) throw new Error("Agile package key must be 32 bytes.");

    if (salt.length !== 16) throw new Error("Agile package salt must be 16 bytes.");

    if (encryptedData.length < 8) throw new Error("Encrypted package is too short.");

    const lengthView = new DataView(encryptedData.slice(0, 8).buffer);
    const low = lengthView.getUint32(0, true);
    const high = lengthView.getUint32(4, true);
    const originalLength = low + high * 0x100000000;
    const encryptedPayload = encryptedData.slice(8);

    if (encryptedPayload.length % 16 !== 0) throw new Error("Encrypted package payload is not block-aligned.");

    const decryptedChunks: Uint8Array[] = [];

    for (let offset = 0; offset < encryptedPayload.length; offset += PACKAGE_CHUNK_SIZE) {
        const encryptedChunk = encryptedPayload.slice(offset, Math.min(offset + PACKAGE_CHUNK_SIZE, encryptedPayload.length));
        const chunkIndex = Math.floor(offset / PACKAGE_CHUNK_SIZE);
        const chunkIndexBytes = createUInt32LE(chunkIndex);
        const ivHash = await sha512(concatBytes(salt, chunkIndexBytes));
        const iv = ivHash.slice(0, 16);
        const decryptedChunk = await aesCbcDecrypt(encryptedChunk, packageKey, iv);

        decryptedChunks.push(decryptedChunk);
    }

    const decryptedData = concatBytes(...decryptedChunks);

    if (originalLength > decryptedData.length) throw new Error("Original package length exceeds decrypted data.");

    return decryptedData.slice(0, originalLength);
}

export async function aesCbcEncrypt(data: Uint8Array, keyBytes: Uint8Array, ivBytes: Uint8Array): Promise<Uint8Array> {
    if (keyBytes.length !== 32) throw new Error("AES-256 requires a 32-byte key.");

    if (ivBytes.length !== 16) throw new Error("AES-CBC requires a 16-byte IV.");

    if (data.length % 16 !== 0) throw new Error("AES-CBC input must be aligned to a 16-byte block.");

    return cbc(keyBytes, ivBytes, { disablePadding: true, }).encrypt(data);
}

export async function aesCbcDecrypt(data: Uint8Array, keyBytes: Uint8Array, ivBytes: Uint8Array): Promise<Uint8Array> {
    if (keyBytes.length !== 32) throw new Error("AES-256 requires a 32-byte key.");

    if (ivBytes.length !== 16) throw new Error("AES-CBC requires a 16-byte IV.");

    if (data.length === 0 || data.length % 16 !== 0) throw new Error("AES-CBC ciphertext must be aligned to a 16-byte block.");

    return cbc(keyBytes, ivBytes, { disablePadding: true, }).decrypt(data);
}

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

const ENCRYPTION_NS = "http://schemas.microsoft.com/office/2006/encryption";
const PASSWORD_KEY_ENCRYPTOR_NS = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";

function requireAttribute(element: Element, name: string): string {
    const value = element.getAttribute(name);

    if (value === null) throw new Error(`EncryptionInfo XML is missing the "${name}" attribute.`);

    return value;
}

export function parseAgileEncryptionInfoXml(xml: string): AgileEncryptionInfo {
    const parsed = new DOMParser().parseFromString(xml, "application/xml");

    if (parsed.getElementsByTagName("parsererror").length > 0) throw new Error("EncryptionInfo XML could not be parsed.");

    const keyDataEl = parsed.getElementsByTagNameNS(ENCRYPTION_NS, "keyData")[0];
    const dataIntegrityEl = parsed.getElementsByTagNameNS(ENCRYPTION_NS, "dataIntegrity")[0];
    const encryptedKeyEl = parsed.getElementsByTagNameNS(PASSWORD_KEY_ENCRYPTOR_NS, "encryptedKey")[0];

    if (!keyDataEl || !encryptedKeyEl) throw new Error("EncryptionInfo XML is missing required elements. This file may use an encryption method that isn't supported.");

    return {
        package: {
            saltValue: base64ToBytes(requireAttribute(keyDataEl, "saltValue")),
            blockSize: Number(requireAttribute(keyDataEl, "blockSize")),
            keyBits: Number(requireAttribute(keyDataEl, "keyBits")),
            hashSize: Number(requireAttribute(keyDataEl, "hashSize")),
            cipherAlgorithm: requireAttribute(keyDataEl, "cipherAlgorithm"),
            cipherChaining: requireAttribute(keyDataEl, "cipherChaining"),
            hashAlgorithm: requireAttribute(keyDataEl, "hashAlgorithm"),
        },

        dataIntegrity: dataIntegrityEl
            ? {
                encryptedHmacKey: base64ToBytes(requireAttribute(dataIntegrityEl, "encryptedHmacKey")),
                encryptedHmacValue: base64ToBytes(requireAttribute(dataIntegrityEl, "encryptedHmacValue")),
            }
            : { encryptedHmacKey: new Uint8Array(0), encryptedHmacValue: new Uint8Array(0), },

        key: {
            spinCount: Number(requireAttribute(encryptedKeyEl, "spinCount")),
            saltValue: base64ToBytes(requireAttribute(encryptedKeyEl, "saltValue")),
            blockSize: Number(requireAttribute(encryptedKeyEl, "blockSize")),
            keyBits: Number(requireAttribute(encryptedKeyEl, "keyBits")),
            hashSize: Number(requireAttribute(encryptedKeyEl, "hashSize")),
            cipherAlgorithm: requireAttribute(encryptedKeyEl, "cipherAlgorithm"),
            cipherChaining: requireAttribute(encryptedKeyEl, "cipherChaining"),
            hashAlgorithm: requireAttribute(encryptedKeyEl, "hashAlgorithm"),
            encryptedVerifierHashInput: base64ToBytes(requireAttribute(encryptedKeyEl, "encryptedVerifierHashInput")),
            encryptedVerifierHashValue: base64ToBytes(requireAttribute(encryptedKeyEl, "encryptedVerifierHashValue")),
            encryptedKeyValue: base64ToBytes(requireAttribute(encryptedKeyEl, "encryptedKeyValue")),
        },
    };
}

export async function verifyAgilePassword(password: string, key: AgileEncryptionInfo["key"]): Promise<boolean> {
    const keyInput = await convertPasswordToKey(password, key.saltValue, key.spinCount, key.keyBits, AGILE_BLOCK_KEYS.verifierHashInput);
    const keyHash = await convertPasswordToKey(password, key.saltValue, key.spinCount, key.keyBits, AGILE_BLOCK_KEYS.verifierHashValue);
    const iv = key.saltValue;
    const verifierHashInput = await aesCbcDecrypt(key.encryptedVerifierHashInput, keyInput, iv);
    const expectedHash = await aesCbcDecrypt(key.encryptedVerifierHashValue, keyHash, iv);
    const actualHash = await sha512(verifierHashInput);

    if (actualHash.length !== expectedHash.length) return false;

    return actualHash.every((byte, index) => byte === expectedHash[index]);
}

export async function decryptEncryptedPackageKey(password: string, key: AgileEncryptionInfo["key"]): Promise<Uint8Array> {
    const passwordKey = await convertPasswordToKey(password, key.saltValue, key.spinCount, key.keyBits, AGILE_BLOCK_KEYS.encryptedKeyValue);
    const iv = key.saltValue;

    return aesCbcDecrypt(key.encryptedKeyValue, passwordKey, iv);
}

export async function lockDocxFile(file: File, password: string): Promise<Blob> {
    const arrayBuffer = await file.arrayBuffer();
    const originalBytes = new Uint8Array(arrayBuffer);
    const verifier = await createPasswordVerifier(password);
    const packageKey = randomBytes(32);
    const encryptedPackageKey = await createEncryptedPackageKey(password, verifier.salt, packageKey);
    const packageSalt = randomBytes(16);
    const encryptedPackage = await encryptDocxPackage(originalBytes, packageKey, packageSalt);
    const dataIntegrity = await createDataIntegrity(packageKey, packageSalt, encryptedPackage);
    const encryptionInfo = createAgileEncryptionInfo(packageSalt, verifier, dataIntegrity, encryptedPackageKey);
    const encryptionInfoXml = buildAgileEncryptionInfoXml(encryptionInfo);
    const containerBytes = buildDocxEncryptionContainer(encryptionInfoXml, encryptedPackage);

    return new Blob(
        [new Uint8Array(containerBytes)],
        { type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }
    );
}

export async function unlockDocxFile(file: File, password: string): Promise<Blob> {
    const arrayBuffer = await file.arrayBuffer();
    const cfb = CFB.read(new Uint8Array(arrayBuffer), { type: "array", });
    const encryptionInfoEntry = CFB.find(cfb, "EncryptionInfo");
    const encryptedPackageEntry = CFB.find(cfb, "EncryptedPackage");

    if (!encryptionInfoEntry?.content || !encryptedPackageEntry?.content) throw new Error("This doesn't look like a password-protected Office document.");

    const encryptionInfoBytes = new Uint8Array(encryptionInfoEntry.content as ArrayLike<number>);
    const xml = new TextDecoder("utf-8").decode(encryptionInfoBytes.slice(8));
    const encryptionInfo = parseAgileEncryptionInfoXml(xml);
    const passwordIsValid = await verifyAgilePassword(password, encryptionInfo.key);

    if (!passwordIsValid) throw new Error("Incorrect password.");

    const packageKey = await decryptEncryptedPackageKey(password, encryptionInfo.key);
    const encryptedPackageBytes = new Uint8Array(encryptedPackageEntry.content as ArrayLike<number>);
    const decryptedBytes = await decryptDocxPackage(encryptedPackageBytes, packageKey, encryptionInfo.package.saltValue);

    return new Blob(
        [new Uint8Array(decryptedBytes)],
        { type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }
    );
}
