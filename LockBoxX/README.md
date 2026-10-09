# LockBoxX

LockBoxX is a browser-based security workspace for protecting digital resources through encryption and format-specific password protection.

It provides password-based encryption, public-key encryption, key exchange, and native protection for supported file formats — all through a browser-based interface.

## Features

- Encrypt and decrypt text, files, images, audio, and video.
- Encrypt folders as portable archives and restore them after decryption.
- Perform cryptographic operations directly in the browser.
- Choose between full encryption control and password-lock workflows when starting.
- Produce self-contained `LBX1` LockBox packages containing encrypted content and the metadata required to restore it.
- Use authenticated encryption so modified ciphertext is rejected during decryption.
- Support RSA public-key encryption for text.
- Support ECDH and X25519 key exchange for securely deriving shared encryption keys.
- Protect supported file formats using native password-protection mechanisms.
- Dedicated Help & Guide page with visual walkthroughs and usage documentation.
- Responsive interface designed for desktop and mobile browsers.

## Supported Cryptography

| Use case | Available algorithms |
| --- | --- |
| Password encryption | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| Public-key encryption (text) | RSA-OAEP with 2048, 3072, or 4096-bit keys |
| Shared-secret key exchange | ECDH P-256 and X25519 |
| Key-exchange content encryption | HKDF-SHA-256-derived AES-256-GCM |

## Key-Exchange Workflow

Use ECDH or X25519 when you need to encrypt content for a specific recipient without sharing a password.

1. Each person generates a key pair in LockBoxX.
2. Exchange only public keys through a trusted channel.
3. The sender enters their private key and the recipient's public key, then encrypts the resource.
4. LockBoxX derives a shared secret, derives an AES-256-GCM key with HKDF-SHA-256, and packages the sender's public key with the encrypted resource.
5. The recipient opens the package, enters their private key, and LockBoxX derives the same shared secret using the packaged sender public key before decrypting.

> **Important:** Key exchange alone does not prove who supplied a public key. Verify public-key fingerprints through a separate trusted channel before encrypting sensitive data. Never share private keys or derived shared secrets.

## File Protection

LockBoxX supports protection beyond its portable `LBX1` encryption format.

Where supported, native file-format protection can be used so that a protected file remains compatible with the software designed to open that format.

Password-lock workflows are available for:

- PDF password protection
- Microsoft Office documents (DOCX, PPTX, and XLSX)
- Images, audio, and video as self-opening, password-protected HTML files
- Folders as password-protected ZIP archives

PDF and Office protection use the corresponding file format's password mechanism. Media is packaged in a self-opening HTML file, while folders are packaged as ZIP archives. These workflows are separate from `LBX1` encryption packages.

## Getting Started

### Prerequisites

- Node.js 20 or newer

### Run Locally

```bash
cd Frontend
npm install
npm run dev
```

Open the local address shown by Vite in your browser.

### Build for Production

```bash
cd Frontend
npm run build
```

The production files are written to Frontend/dist.

## Usage

When the platform opens, choose how to protect your resource:

- **Fully control your encryption** reveals **Encrypt** and **Decrypt**.
- **Password protect your resource** reveals **Create Password Lock** and **Remove Password Lock**.

Select the action you need, then use **Change approach** or **Back to actions** to navigate between the workflow steps.

### Encrypt and Decrypt

1. Choose **Fully control your encryption**, then choose **Encrypt**.
2. Select a resource type and an available encryption algorithm.
3. Enter the required password, key, or shared-secret details for the selected algorithm.
4. Start encryption and save the resulting LockBox package.
5. Choose **Decrypt**, provide the encrypted package, and enter the matching credentials to restore the resource.

For RSA text encryption:

1. Choose the RSA encryption algorithm.
2. Generate a key pair or provide the recipient's public key.
3. Encrypt the text and send the resulting package to the private-key holder.
4. The recipient chooses **Decrypt** and supplies the matching private key.

For key exchange:

1. Generate an ECDH or X25519 key pair.
2. Exchange public keys with the intended recipient.
3. Use the recipient's public key together with your private key to encrypt content.
4. The recipient uses their private key and the packaged sender public key to derive the same shared secret.
5. The recipient uses the shared secret to decrypt the package.

### Password Locks

1. Choose **Password protect your resource**, then select **Create Password Lock** or **Remove Password Lock**.
2. Select a supported resource type and provide the required resource and password.
3. Start the operation and save the resulting protected resource or restored file.

PDF and Office files use file-format password protection. Images, audio, and video are delivered as self-opening HTML files, and folders are protected as ZIP archives. The supported removal workflows depend on the resource type.

### Help & Guide

LockBoxX includes a dedicated Help & Guide page accessible from the main workspace.
The guide covers:
- Understanding the LockBoxX workspace
- Selecting resources
- Choosing security methods
- Protecting resources
- Unlocking and decrypting resources
- Understanding operation results
- Password and security guidance
- Troubleshooting
- Frequently asked questions
The guide also includes visual screenshots of the LockBoxX interface and its major workflows.

## Project Structure

```text
LockBoxX/
├── Frontend/
│   ├── crypto/       # Encryption, package, key-exchange, and protection logic
│   ├── Handlers/     # File-format and media protection handlers
│   ├── public/
│   │   └── help/     # Help page screenshots and visual documentation
│   ├── src/          # React application
│   └── styles/       # Application styling
└── README.md
```

## Security Notes
- Encryption protects data only while passwords and private keys remain secret.
- Use strong, unique passwords for sensitive resources.
- Never share private keys or derived shared secrets.
- Store important private keys and passwords securely and maintain appropriate backups.
- A lost password or private key may make protected data unrecoverable.
- Treat encrypted packages and protected files as sensitive data.
- Although encrypted content is protected, package metadata may contain information such as resource names and media types.
- Public-key fingerprints should be verified through a separate trusted channel when authenticating a recipient's public key is important.
- LockBoxX is not a password-recovery or password-bypass tool.
## Development Commands

Run these commands from `Frontend`:

```bash
npm run dev      # Start the development server
npm run build    # Type-check and create a production build
npm run lint     # Run linting
npm run preview  # Preview a production build
```

## Deployment
LockBoxX is deployed as a web application and can be accessed through its production deployment:
https://lockboxx.vercel.app/
## Technology Stack
- React
- TypeScript
- Vite
- Web Cryptography APIs
- Node.js / npm
- CSS
- Vercel
## Project Status
LockBoxX is an actively developed security project.
The core encryption workflows, resource handling, format-specific protection, deployment, and user documentation are implemented. Additional platform features and improvements may be added as development continues.
## License
This project is currently under development. Licensing information will be added as the project reaches its intended release stage.