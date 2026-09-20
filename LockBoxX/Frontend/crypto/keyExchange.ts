import { x25519 } from "@noble/curves/ed25519.js";
import { CryptoError } from "./error";

export type KeyExchangeAlgorithm = "ECDH" | "X25519";
export interface KeyExchangeKeyPair {
    publicKey: string;
    privateKey: string;
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";

    for (const byte of bytes) binary += String.fromCharCode(byte);

    return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
    const binary = atob(value.replace(/\s/g, ""));
    const bytes = new Uint8Array(new ArrayBuffer(binary.length));

    for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);

    return bytes;
}

function textToBase64(value: string): string {
    return bytesToBase64(new TextEncoder().encode(value));
}

function base64ToText(value: string): string {
    return new TextDecoder().decode(base64ToBytes(value));
}

export async function generateKeyExchangePair(algorithm: KeyExchangeAlgorithm): Promise<KeyExchangeKeyPair> {
    if (algorithm === "X25519") {
        const keyPair = x25519.keygen();

        return {
            publicKey: bytesToBase64(keyPair.publicKey),
            privateKey: bytesToBase64(keyPair.secretKey),
        };
    }

    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
    );
    const publicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    return {
        publicKey: bytesToBase64(new Uint8Array(publicKey)),
        privateKey: textToBase64(JSON.stringify(privateKey)),
    };
}

export async function deriveSharedSecret(algorithm: KeyExchangeAlgorithm, privateKey: string, peerPublicKey: string): Promise<string> {
    try {
        if (algorithm === "X25519") {
            const sharedSecret = x25519.getSharedSecret(
                base64ToBytes(privateKey),
                base64ToBytes(peerPublicKey)
            );

            return bytesToBase64(sharedSecret);
        }

        const privateJwk = JSON.parse(base64ToText(privateKey)) as JsonWebKey;
        const localPrivateKey = await crypto.subtle.importKey(
            "jwk",
            privateJwk,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveBits"]
        );
        const peerKey = await crypto.subtle.importKey(
            "raw",
            base64ToBytes(peerPublicKey),
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
        const sharedSecret = await crypto.subtle.deriveBits(
            { name: "ECDH", public: peerKey },
            localPrivateKey,
            256
        );

        return bytesToBase64(new Uint8Array(sharedSecret));
    } catch {
        throw new CryptoError("KEY_EXCHANGE_FAILED", "The peer public key or local private key is invalid.");
    }
}
