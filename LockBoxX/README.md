# LockBox

LockBox is a browser-based encryption tool for protecting text, individual files, media, and folders. It provides password encryption, RSA public-key encryption for text, and ECDH/X25519 key exchange for securely deriving a shared encryption key between two people.

## Features

- Encrypt and decrypt text, files, images, audio, video, and folders.
- Encrypt folders as portable archives and restore them after decryption.
- Keep encryption and decryption in the browser; private keys and secrets are not sent to a LockBox server.
- Produce self-contained `LBX1` LockBox packages that carry the encrypted content and the metadata needed to restore it.
- Use authenticated encryption so modified ciphertext is rejected during decryption.

## Supported cryptography

| Use case | Available algorithms |
| --- | --- |
| Password encryption | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| Public-key encryption (text) | RSA-OAEP with 2048, 3072, or 4096-bit keys |
| Shared-secret key exchange | ECDH P-256 and X25519 |
| Key-exchange content encryption | HKDF-SHA-256-derived AES-256-GCM |

## Key-exchange workflow

Use ECDH or X25519 when you need to encrypt content for a specific recipient without sharing a password.

1. Each person generates a key pair in LockBox.
2. Exchange only public keys through a trusted channel.
3. The sender enters their private key and the recipient's public key, then encrypts the resource.
4. LockBox derives a shared secret, derives an AES-256-GCM key with HKDF-SHA-256, and packages the sender's public key with the encrypted resource.
5. The recipient opens the package, enters their private key, and LockBox derives the same shared secret using the packaged sender public key before decrypting.

> **Important:** key exchange alone does not prove who supplied a public key. Verify public-key fingerprints through a separate trusted channel before encrypting sensitive data. Do not share private keys or derived shared secrets.

## Getting started

### Prerequisites

- Node.js 20 or newer

### Run locally

```bash
cd Frontend
npm install
npm run dev
```

Open the local address shown by Vite in your browser.

### Build for production

```bash
cd Frontend
npm run build
```

The production files are written to `Frontend/dist`.

## Usage

### Password encryption

1. Choose **Encrypt** and select a resource type.
2. Choose a symmetric algorithm, enter a strong password, and encrypt.
3. Save or copy the generated LockBox package.
4. To decrypt, choose **Decrypt**, provide the package and the same password.

### RSA text encryption

1. Choose an RSA algorithm and generate a key pair, or paste a recipient public key.
2. Encrypt the text and send the resulting package to the private-key holder.
3. The recipient chooses **Decrypt** and supplies the matching private key.

## Project structure

```text
LockBox/
├── Frontend/
│   ├── crypto/       # Encryption, package, key-exchange, and archive logic
│   ├── src/          # React application
│   └── styles/       # Application styling
└── README.md
```

## Security notes

- Encryption protects data only while passwords and private keys remain secret.
- Use a unique, strong password for every password-encrypted package.
- Store private keys outside the encrypted package and back them up securely; a lost private key cannot be recovered.
- Treat encrypted packages as sensitive: although ciphertext is protected, their metadata can include resource names and media types.

## Development commands

From `Frontend`:

```bash
npm run dev      # Start the development server
npm run build    # Type-check and create a production build
npm run lint     # Run linting
npm run preview  # Preview a production build
```
