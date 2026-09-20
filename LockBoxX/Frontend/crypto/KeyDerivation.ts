const PBKDF2_ITERATIONS = 600_000;
const HASH_ALGORITHM = "SHA-256";
export type SymmetricAlgorithm =
    | "AES-256-GCM"
    | "AES-128-GCM"
    | "ChaCha20-Poly1305"
    | "XChaCha20-Poly1305";

const ALGORITHM_KEY_LENGTH: Record<SymmetricAlgorithm, number> = {
    "AES-256-GCM": 32,
    "AES-128-GCM": 16,
    "ChaCha20-Poly1305": 32,
    "XChaCha20-Poly1305": 32,
};

export async function deriveKeyBytes(password: string, salt: Uint8Array<ArrayBuffer>, algorithm: SymmetricAlgorithm): Promise<Uint8Array<ArrayBuffer>> {
    const keyLength = ALGORITHM_KEY_LENGTH[algorithm];

    if (!keyLength) throw new Error(`Unsupported encryption algorithm: ${algorithm}`);

    const passwordKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const keyBuffer = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: HASH_ALGORITHM,
        },
        passwordKey,
        keyLength * 8
    );

    return new Uint8Array(keyBuffer) as Uint8Array<ArrayBuffer>;
}

export async function deriveKey(password: string, salt: Uint8Array<ArrayBuffer>, algorithm: SymmetricAlgorithm): Promise<CryptoKey> {
    const keyBytes = await deriveKeyBytes(password, salt, algorithm);
    const name = "AES-GCM";

    return crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name },
        false,
        ["encrypt", "decrypt"]
    );
}