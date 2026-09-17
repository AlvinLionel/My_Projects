import "../styles/App.css";
import { useState } from "react";
import { encryptText, decryptText, decryptTextWithSharedSecret, encryptTextWithSharedSecret } from "../crypto/aes";
import { createPackage, createRsaPackage, isPackageValid, unpackage } from "../crypto/package";
import { CryptoError } from "../crypto/error";
import { type ResourceType, encryptFile, encryptFileWithSharedSecret, decryptFile, decryptFileWithSharedSecret, downloadFile } from "../crypto/resourceCrypto";
import type { SymmetricAlgorithm } from "../crypto/KeyDerivation";
import { decryptRsaText, encryptRsaText, generateRsaKeyPair, type RsaAlgorithm } from "../crypto/rsa";
import { deriveSharedSecret, generateKeyExchangePair, type KeyExchangeAlgorithm } from "../crypto/keyExchange";
import { createFolderArchive, createFolderArchiveFromDirectory, formatBytes, inspectFolderArchive, type FolderSummary } from "../crypto/folderArchive";

type Mode = "encrypt" | "decrypt";
type EncryptionAlgorithm = SymmetricAlgorithm | RsaAlgorithm | KeyExchangeAlgorithm;

function downloadPrivateKey(privateKey: string, algorithm: RsaAlgorithm): void {
    const blob = new Blob([privateKey], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `lockbox-${algorithm.toLowerCase()}-private-key.pem`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

type AlgorithmCategory = {
    id: string;
    icon: string;
    name: string;
    description: string;
    algorithms: Algorithm[];
};
type Algorithm = {
    id: string;
    name: string;
    description: string;
    icon: string;
    badge: string;
    badgeType: "recommended" | "default";
    keyType: "password" | "keypair";
    operation: "encryption" | "key-exchange";
    supports: ResourceType[];
};


const algorithmCategories: Record<string, AlgorithmCategory> = {
    symmetric: {
        id: "symmetric",
        icon: "◈",
        name: "Symmetric Encryption",
        description: "Shared-key encryption for your data",
        algorithms: [
            {
                id: "AES-256-GCM",
                name: "AES-256-GCM",
                description: "Strong & recommended",
                icon: "🔐",
                badge: "RECOMMENDED",
                badgeType: "recommended",
                keyType: "password",
                operation: "encryption",
                supports: ["text", "file", "image", "audio", "video", "folder"]
            },
            {
                id: "AES-128-GCM",
                name: "AES-128-GCM",
                description: "Fast & secure",
                icon: "⚡",
                badge: "FAST",
                badgeType: "default",
                keyType: "password",
                operation: "encryption",
                supports: ["text", "file", "image", "audio", "video", "folder"],
            },
            {
                id: "ChaCha20-Poly1305",
                name: "ChaCha20-Poly1305",
                description: "Fast & modern",
                icon: "⚡",
                badge: "MODERN",
                badgeType: "default",
                keyType: "password",
                operation: "encryption",
                supports: ["text", "file", "image", "audio", "video", "folder"],
            },
            {
                id: "XChaCha20-Poly1305",
                name: "XChaCha20-Poly1305",
                description: "Strong & flexible",
                icon: "🛡️",
                badge: "ADVANCED",
                badgeType: "default",
                keyType: "password",
                operation: "encryption",
                supports: ["text", "file", "image", "audio", "video", "folder"]
            }
        ] satisfies Algorithm[],
    },

    publicKey: {
        id: "public-key",
        icon: "◇",
        name: "Public-Key Encryption",
        description: "Encryption using key pairs",
        algorithms: [
            {
                id: "RSA-2048",
                name: "RSA-2048",
                description: "Secure & widely supported",
                icon: "🔑",
                badge: "STANDARD",
                badgeType: "default",
                keyType: "keypair",
                operation: "encryption",
                supports: ["text"],
            },
            {
                id: "RSA-3072",
                name: "RSA-3072",
                description: "Stronger protection",
                icon: "🛡️",
                badge: "STRONG",
                badgeType: "default",
                keyType: "keypair",
                operation: "encryption",
                supports: ["text"],
            },
            {
                id: "RSA-4096",
                name: "RSA-4096",
                description: "Maximum RSA strength",
                icon: "🛡️",
                badge: "HIGH SECURITY",
                badgeType: "default",
                keyType: "keypair",
                operation: "encryption",
                supports: ["text"],
            }
        ] satisfies Algorithm[],
    },

    keyExchange: {
        id: "key-exchange",
        icon: "⇄",
        name: "Key Exchange",
        description: "Establish secure shared secrets",
        algorithms: [
            {
                id: "ECDH",
                name: "ECDH",
                description: "Secure key exchange",
                icon: "🔑",
                badge: "SECURE",
                badgeType: "default",
                keyType: "keypair",
                operation: "key-exchange",
                supports: [],
            },
            {
                id: "X25519",
                name: "X25519",
                description: "Fast & modern key exchange",
                icon: "⚡",
                badge: "MODERN",
                badgeType: "default",
                keyType: "keypair",
                operation: "key-exchange",
                supports: [],
            }
        ] satisfies Algorithm[],
    },
};

const resourceTypes: Record<ResourceType,
    {
        name: string;
        description: string;
        icon: string;
    }
> = {
    text: {
        name: "Text",
        description: "Messages, notes and other text",
        icon: "📝",
    },
    file: {
        name: "File",
        description: "Documents and other files",
        icon: "📄",
    },
    image: {
        name: "Image",
        description: "Photos and other images",
        icon: "📸",
    },
    audio: {
        name: "Audio",
        description: "Music, recordings and audio",
        icon: "🔊",
    },
    video: {
        name: "Video",
        description: "Videos and recordings",
        icon: "🎬",
    },
    folder: {
        name: "Folder",
        description: "Protect an entire folder",
        icon: "📁",
    },
};

function App() {
    const [mode, setMode] = useState<Mode>("encrypt");
    const [selectedResource, setSelectedResource] = useState<ResourceType>("text");
    const [selectedAlgorithm, setSelectedAlgorithm] = useState<EncryptionAlgorithm>("AES-256-GCM");
    const [openCategory, setOpenCategory] = useState<string | null>("symmetric");
    const [isProcessing, setIsProcessing] = useState(false);
    const [processingStep, setProcessingStep] = useState(0);
    const [operationComplete, setOperationComplete] = useState(false);
    const [operationResult, setOperationResult] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [downloaded, setDownloaded] = useState(false);
    const [resourceText, setResourceText] = useState("");
    const [inputPassword, setInputPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [operationError, setOperationError] = useState<string | null>(null);
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [uploadError, setUploadError] = useState("");
    const [decryptedFile, setDecryptedFile] = useState<File | null>(null);
    const [folderSummary, setFolderSummary] = useState<FolderSummary | null>(null);
    const [decryptedFolderSummary, setDecryptedFolderSummary] = useState<FolderSummary | null>(null);
    const [publicKey, setPublicKey] = useState("");
    const [privateKey, setPrivateKey] = useState("");
    const [showPrivateKey, setShowPrivateKey] = useState(false);
    const [exchangePublicKey, setExchangePublicKey] = useState("");
    const [exchangePrivateKey, setExchangePrivateKey] = useState("");
    const [showExchangePrivateKey, setShowExchangePrivateKey] = useState(false);
    const [peerPublicKey, setPeerPublicKey] = useState("");
    const [sharedSecret, setSharedSecret] = useState("");
    const [showSharedSecret, setShowSharedSecret] = useState(false);
    const [exchangeError, setExchangeError] = useState("");

    const selectedAlgorithmConfig =
        Object.values(algorithmCategories)
            .flatMap(category => category.algorithms)
            .find(algorithm => algorithm.id === selectedAlgorithm);

    const availableAlgorithms = Object.values(algorithmCategories)
        .flatMap(category => category.algorithms)
        .filter(algorithm =>
            algorithm.supports.includes(selectedResource)
        );

    const hasResource = selectedResource === "text"
        ? resourceText.trim().length > 0
        : selectedFile !== null;
    const resourceRequirementMessage = selectedResource === "text"
        ? "Enter text before starting this operation."
        : `Upload a ${resourceTypes[selectedResource].name.toLowerCase()} before starting this operation.`;
    const keyRequirementMessage = mode === "encrypt"
        ? "Enter a public key or generate a key pair before starting this operation."
        : "Enter the private key for this encrypted resource before starting this operation.";
    const keyMaterialMissing = selectedAlgorithmConfig?.operation === "key-exchange"
        ? !exchangePrivateKey || (mode === "encrypt" && !peerPublicKey.trim())
        : selectedAlgorithmConfig?.keyType === "keypair" && !(mode === "encrypt" ? publicKey.trim() : privateKey.trim());

    const handleFolderPicker = async () => {
        const picker = (window as Window & {
            showDirectoryPicker?: () => Promise<FileSystemDirectoryHandle>;
        }).showDirectoryPicker;

        if (!picker) {
            document.getElementById("resource-upload")?.click();
            return;
        }

        try {
            const directory = await picker();
            const { file, summary } = await createFolderArchiveFromDirectory(directory);
            setSelectedFile(file);
            setFolderSummary(summary);
            setUploadError("");
        } catch (error) {
            if ((error as DOMException)?.name === "AbortError") return;
            setUploadError(error instanceof CryptoError ? error.message : "The folder could not be read.");
        }
    };

    const handleResourceChange = (resourceType: ResourceType) => {
        const resourceAlgorithms = Object.values(algorithmCategories)
            .flatMap(category => category.algorithms)
            .filter(algorithm => algorithm.supports.includes(resourceType));
        const isCurrentAlgorithmAvailable = resourceAlgorithms.some(algorithm => algorithm.id === selectedAlgorithm);

        setSelectedResource(resourceType);

        if (!isCurrentAlgorithmAvailable && resourceAlgorithms.length > 0) {
            const recommendedAlgorithm = resourceAlgorithms.find(algorithm => algorithm.badgeType === "recommended");

            setSelectedAlgorithm((recommendedAlgorithm?.id ?? resourceAlgorithms[0].id) as EncryptionAlgorithm);
        }
        setSelectedFile(null);
        setFolderSummary(null);
        setDecryptedFolderSummary(null);
        setUploadError("");
    };

    const ResourceIsValid = (file: File, resourceType: ResourceType): boolean => {
        switch (resourceType) {
            case "text":
                return file.type.startsWith("text/");
            case "image":
                return file.type.startsWith("image/");
            case "audio":
                return file.type.startsWith("audio/");
            case "video":
                return file.type.startsWith("video/")
            case "file":
                return true;
            default:
                return false;
        }
    };

    {/************** PROCESSING DISPLAY DETAILS **************/ }
    const processingSteps = mode === "encrypt"
        ? [
            "Preparing resource",
            "Generating secure parameters",
            "Deriving encryption key",
            "Encrypting and authenticating resource",
        ]
        : [
            "Reading encrypted resource",
            "Verifying encrypted data",
            "Deriving decryption key",
            "Decrypting and authenticating resource",
            "Restoring original resource",
        ];

    return (
        <div className="app">
            <header className="navbar">
                <div className="brand">
                    <div className="brand-icon">◈</div>
                    <div>
                        <h1>LockBox</h1>
                        <span>CRYPTOGRAPHIC WORKSPACE</span>
                    </div>
                </div>
                <nav>
                    <button className="nav-link active">Workspace</button>
                    <button className="nav-link">Tools</button>
                    <button className="nav-link">About</button>
                </nav>
                <div className="security-status">
                    <span className="status-dot"></span>SECURITY MADE EASY
                </div>
            </header>
            <main className="workspace">
                {/**************INTRO **************/}
                <section className="intro">
                    <div className="eyebrow">
                        <span>01</span> SECURE YOUR DATA
                    </div>
                    <h2>Your Data <br /> <span>Your Control</span></h2>
                    <p>Encrypt text,files, images, audio,videos and folders directly from your workspace</p>
                </section>

                <section className="crypto-workspace">
                    {/**************MODES **************/}
                    <div className="mode-selector">
                        <button
                            className={mode === "encrypt" ? "mode active" : "mode"}
                            onClick={() => setMode("encrypt")} >
                            <span className="mode-icon">🔒</span>
                            <div>
                                <strong>Encrypt</strong>
                                <small>Protect your resource</small>
                            </div>
                        </button>
                        <button
                            className={mode === "decrypt" ? "mode active" : "mode"}
                            onClick={() => setMode("decrypt")}>
                            <span className="mode-icon">🔓</span>
                            <div>
                                <strong>Decrypt</strong>
                                <small>Restore a resource</small>
                            </div>
                        </button>
                    </div>
                    <div className="workspace-grid">
                        <section className="panel resource-panel">
                            <div className="panel-header">
                                <div>
                                    <span className="panel-number">01</span>
                                    <h3>Resource</h3>
                                </div>
                                <span className="panel-label">
                                    {mode === "encrypt" ? "INPUT" : "ENCRYPTED INPUT"}
                                </span>
                            </div>
                            <label className="field-label">
                                {mode === "encrypt" ? "What would you like to secure?" : "What would you like unlocked?"}
                            </label>

                            {/**************RESOURCES **************/}
                            <div className="resource-grid">
                                {(
                                    Object.entries(resourceTypes) as [
                                        ResourceType,
                                        typeof resourceTypes[ResourceType]
                                    ][]
                                ).map(([type, resource]) => {
                                    const isSelected = selectedResource === type;

                                    return (
                                        <button key={type} type="button"
                                            className={`resource-card ${isSelected ? "selected" : ""}`}
                                            onClick={() => handleResourceChange(type)}
                                        >
                                            <span className="resource-icon">{resource.icon}</span>

                                            <span className="resource-info">
                                                <strong>{resource.name}</strong>
                                                <small>{resource.description}</small>
                                            </span>

                                            {isSelected && (<span className="resource-check">✓ </span>)}
                                        </button>
                                    );
                                })}
                            </div>

                            {selectedResource === "text" ? (
                                <textarea className="text-input"
                                    placeholder={mode === "encrypt" ? "Enter the text you want secured..." : "Paste your encrypted text here..."}
                                    value={resourceText}
                                    onChange={(event) => setResourceText(event.target.value)}
                                ></textarea>
                            ) : (
                                /************** DROP ZONE **************/
                                <div className={`drop-zone ${isDragging ? "dragging" : ""}`}
                                    onClick={() => selectedResource === "folder" && mode === "encrypt" ? void handleFolderPicker() : document.getElementById("resource-upload")?.click()}
                                    onDragOver={(e) => {
                                        e.preventDefault();
                                        setIsDragging(true);
                                    }}
                                    onDragLeave={(e) => {
                                        e.preventDefault();
                                        setIsDragging(false);
                                    }}
                                    onDrop={async (e) => {
                                        e.preventDefault();
                                        setIsDragging(false);

                                        const files = Array.from(e.dataTransfer.files ?? []);
                                        const file = files[0] ?? null;

                                        if (!file && selectedResource === "folder") {
                                            setUploadError("The selected folder is empty.");
                                            return;
                                        }
                                        if (!file) return;

                                        if (mode === "decrypt") {
                                            if (!file.name.toLowerCase().endsWith(".lbx") && file.type !== "application/x-lockbox") {
                                                setUploadError("Please select a valid LockBox (.lbx) file.");
                                                return;
                                            }

                                            void file.text().then((packageString) => {
                                                const trimmedPackage = packageString.trim();
                                                if (!isPackageValid(trimmedPackage)) {
                                                    setUploadError("This file is not a valid LockBox package or has been tampered with.");
                                                    return;
                                                }
                                                setUploadError("");
                                                setSelectedFile(file);
                                            }).catch(() => setUploadError("The LockBox file could not be read."));

                                            return;
                                        }

                                        if (selectedResource === "folder") {
                                            const item = e.dataTransfer.items?.[0];

                                            const itemWithDirectorySupport = item as DataTransferItem & {
                                                getAsFileSystemHandle?: () => Promise<FileSystemDirectoryHandle>;
                                            };

                                            if (itemWithDirectorySupport?.getAsFileSystemHandle) {
                                                try {
                                                    const handle = await itemWithDirectorySupport.getAsFileSystemHandle();

                                                    if (handle.kind !== "directory") {
                                                        setUploadError("Please drop a folder.");
                                                        return;
                                                    }

                                                    const archive = await createFolderArchiveFromDirectory(handle);

                                                    setSelectedFile(archive.file);
                                                    setFolderSummary(archive.summary);
                                                    setUploadError("");
                                                } catch (error) {
                                                    setUploadError(error instanceof CryptoError ? error.message : "The selected folder could not be archived.");
                                                }

                                                return;
                                            }

                                            void createFolderArchive(files)
                                                .then(({ file: archive, summary }) => {
                                                    setSelectedFile(archive);
                                                    setFolderSummary(summary);
                                                    setUploadError("");
                                                })
                                                .catch((error) => {
                                                    setUploadError(error instanceof CryptoError ? error.message : "The folder could not be read.");
                                                });
                                            return;
                                        }

                                        if (!ResourceIsValid(file, selectedResource)) {
                                            setUploadError(`You entered the wrong resource type`);
                                            return;
                                        }
                                        setUploadError("");
                                        setSelectedFile(file);
                                    }}
                                >
                                    {selectedFile ? (
                                        <>
                                            <div className="upload-icon">✓</div>
                                            <strong>{selectedResource === "folder" && folderSummary ? folderSummary.folderName : selectedFile.name}</strong>

                                            {selectedResource === "folder" && folderSummary ? (
                                                <span>{folderSummary.fileCount} files · {folderSummary.folderCount} folders · {formatBytes(folderSummary.size)}</span>
                                            ) : (
                                                <span>
                                                    {selectedFile.size >= 1024 * 1024
                                                        ? `${(selectedFile.size / (1024 * 1024)).toFixed(1)} MB`
                                                        : `${(selectedFile.size / 1024).toFixed(1)} KB`}
                                                </span>
                                            )}

                                            <button type="button" className="browse-button" onClick={(event) => {
                                                event.stopPropagation();
                                                if (selectedResource === "folder" && mode === "encrypt") {
                                                    void handleFolderPicker();
                                                } else {
                                                    document.getElementById("resource-upload")?.click();
                                                }
                                            }}
                                            >
                                                Change file
                                            </button>
                                        </>
                                    ) : (
                                        <>
                                            <div className="upload-icon">↑</div>
                                            {mode === "decrypt" ? (
                                                <>
                                                    <strong>Drag and drop your LockBox file here</strong>
                                                    <span>Only .lbx encrypted files are accepted</span>
                                                </>
                                            ) : (
                                                <>
                                                    <strong>Drag and drop your {selectedResource} here</strong>
                                                    <span>or click to browse your device</span>
                                                </>
                                            )}

                                            <button type="button" className="browse-button" onClick={(e) => {
                                                e.stopPropagation();
                                                if (selectedResource === "folder" && mode === "encrypt") {
                                                    void handleFolderPicker();
                                                } else {
                                                    document.getElementById("resource-upload")?.click();
                                                }
                                            }}
                                            >
                                                {selectedFile ? "Change file"
                                                    : mode === "decrypt"
                                                        ? "Browse .lbx file"
                                                        : "Browse files"}
                                            </button>
                                        </>
                                    )}

                                    <input type="file" id="resource-upload" hidden
                                        {...(selectedResource === "folder" && mode === "encrypt" ? { webkitdirectory: "", multiple: true } : {})}
                                        accept={
                                            mode === "decrypt"
                                                ? ".lbx,application/x-lockbox"
                                                : selectedResource === "folder"
                                                    ? undefined
                                                    : selectedResource === "image"
                                                        ? "image/*"
                                                        : selectedResource === "audio"
                                                            ? "audio/*"
                                                            : selectedResource === "video"
                                                                ? "video/*"
                                                                : "*/*"
                                        }
                                        onChange={async (e) => {
                                            const files = Array.from(e.target.files ?? []);
                                            const file = files[0] ?? null;

                                            if (!file && mode === "encrypt" && selectedResource === "folder") {
                                                setUploadError("The selected folder is empty.");
                                                e.target.value = "";
                                                return;
                                            }
                                            if (!file) return;

                                            if (mode === "encrypt" && selectedResource === "folder") {
                                                try {
                                                    const { file: archive, summary } = await createFolderArchive(files);
                                                    setSelectedFile(archive);
                                                    setFolderSummary(summary);
                                                    setUploadError("");
                                                } catch (error) {
                                                    setUploadError(error instanceof CryptoError ? error.message : "The folder could not be read.");
                                                }
                                                return;
                                            }

                                            if (mode === "decrypt") {
                                                if (!file.name.toLowerCase().endsWith(".lbx") && file.type !== "application/x-lockbox") {
                                                    setUploadError("Please select a valid LockBox (.lbx) file.");
                                                    e.target.value = "";
                                                    return;
                                                }
                                                const packageString = (await file.text()).trim();
                                                if (!isPackageValid(packageString)) {
                                                    setUploadError("This file is not a valid LockBox package or has been tampered with.");
                                                    e.target.value = "";
                                                    return;
                                                }
                                            } else if (selectedResource !== "folder" && !ResourceIsValid(file, selectedResource)) {
                                                setUploadError("You entered the wrong resource type");
                                                e.target.value = "";
                                                return;
                                            }

                                            setUploadError("");
                                            setSelectedFile(file);
                                        }}
                                    />
                                    {uploadError && (
                                        <div className="upload-error">
                                            <span>⚠</span>
                                            {uploadError}
                                        </div>
                                    )}
                                </div>
                            )}
                        </section>

                        {/**************ALGORITHMS **************/}
                        <section className="panel crypto-panel">
                            <div className="panel-header">
                                <div>
                                    <span className="panel-number">02</span>
                                    <h3>Cryptography</h3>
                                </div>
                                <span className="panel-label">CONFIG</span>
                            </div>
                            <label className="field-label">
                                Encryption algorithm
                            </label>

                            <div className="algorithm-catalog">

                                {Object.values(algorithmCategories).map((category) => {
                                    const isOpen = openCategory === category.id;

                                    return (
                                        <div className="algorithm-category" key={category.id}>
                                            <button
                                                className={`category-header ${isOpen ? "open" : ""}`}
                                                onClick={() => setOpenCategory(isOpen ? null : category.id)}
                                            >
                                                <div className="category-title">
                                                    <div className="category-icon">{category.icon}</div>
                                                    <div>
                                                        <strong>{category.name}</strong>
                                                        <span>{category.description}</span>
                                                    </div>
                                                </div>

                                                <div className="category-right">
                                                    <span className="algorithm-count">
                                                        {category.algorithms.length}{" "}
                                                        {category.algorithms.length === 1 ? "METHOD" : "METHODS"}
                                                    </span>
                                                    <span className="category-chevron">{isOpen ? "-" : "+"}</span>
                                                </div>
                                            </button>

                                            {isOpen && (
                                                <div className="algorithm-options">
                                                    {category.algorithms.map((algorithm) => {
                                                        const isSupported = algorithm.operation === "key-exchange" || availableAlgorithms.some(available => available.id === algorithm.id);

                                                        return (
                                                            <button
                                                                key={algorithm.id}
                                                                className={`algorithm-card ${selectedAlgorithm === algorithm.id ? "selected" : ""} ${!isSupported ? "disabled" : ""}`}
                                                                onClick={() => {
                                                                    if (isSupported) {
                                                                        setSelectedAlgorithm(algorithm.id as EncryptionAlgorithm);
                                                                        setSharedSecret("");
                                                                    }
                                                                }}
                                                            >
                                                                <div className="algorithm-icon">{algorithm.icon}</div>

                                                                <div className="algorithm-info">
                                                                    <strong>{algorithm.name}</strong>
                                                                    <span>{algorithm.description}</span>
                                                                </div>
                                                                {!isSupported && (
                                                                    <span className="unsupported-reason">
                                                                        Not suitable for {resourceTypes[selectedResource].name}
                                                                    </span>
                                                                )}
                                                                <div className={`algorithm-badge ${algorithm.badgeType === "recommended" ? "recommended" : ""}`}>
                                                                    {algorithm.badge}
                                                                </div>
                                                            </button>
                                                        );
                                                    })}
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                            {/**************SECURITY KEY **************/}
                            {selectedAlgorithmConfig?.keyType === "password" && (
                                <>
                                    <label className="field-label key-label">
                                        {mode === "encrypt" ? "Encryption password" : "Decryption password"}
                                    </label>

                                    <div className="password-input">
                                        <input type={showPassword ? "text" : "password"}
                                            placeholder="Enter your secret key"
                                            value={inputPassword}
                                            onChange={(e) => setInputPassword(e.target.value)}
                                        />
                                        <button type="button"
                                            onClick={() => setShowPassword((prev) => !prev)}
                                            aria-label={showPassword ? "Hide password" : "Show password"}
                                        >
                                            {showPassword ?
                                                (
                                                    <svg
                                                        viewBox="0 0 24 24"
                                                        width="18"
                                                        height="18"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        strokeWidth="2"
                                                        strokeLinecap="round"
                                                        strokeLinejoin="round"
                                                    >
                                                        <path d="M3 3l18 18" />
                                                        <path d="M10.6 10.6a2 2 0 0 0 2.8 2.8" />
                                                        <path d="M9.9 4.2A10.8 10.8 0 0 1 12 4c5 0 8.3 4 9 5a11.6 11.6 0 0 1-3.2 3.3" />
                                                        <path d="M6.6 6.6C4.5 8 3.3 9.7 3 10c.7 1 4 5 9 5 1.1 0 2.1-.2 3-.5" />
                                                    </svg>
                                                ) : (
                                                    <svg
                                                        viewBox="0 0 24 24"
                                                        width="18"
                                                        height="18"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        strokeWidth="2"
                                                        strokeLinecap="round"
                                                        strokeLinejoin="round"
                                                    >
                                                        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
                                                        <circle cx="12" cy="12" r="3" />
                                                    </svg>
                                                )}
                                        </button>
                                    </div>
                                    <div className="security-note">
                                        <span>✓</span> Your encryption key is processed locally
                                    </div>
                                </>
                            )}
                            {selectedAlgorithmConfig?.keyType === "keypair" &&
                                selectedAlgorithmConfig?.operation === "encryption" && (
                                    <div className="keypair-section">
                                        <div className="keypair-header">
                                            <div>
                                                <strong>{mode === "encrypt" ? "Encryption public key" : "Decryption private key"}</strong>
                                                <span>{mode === "encrypt" ? "Use a public key to protect your resource" : "Use the private key that matches the encryption key pair"}</span>
                                            </div>
                                            <span className="keypair-icon">🔑</span>
                                        </div>

                                        <label className="field-label">{mode === "encrypt" ? "Public key" : "Private key"}</label>

                                        <div className="key-input">
                                            <textarea
                                                placeholder={mode === "encrypt" ? "Paste your public key here..." : "Paste your private key here..."}
                                                rows={4}
                                                value={mode === "encrypt" ? publicKey : privateKey}
                                                onChange={(event) => mode === "encrypt" ? setPublicKey(event.target.value) : setPrivateKey(event.target.value)}
                                                className={mode === "decrypt" && privateKey && !showPrivateKey ? "secret-field" : ""}
                                            />
                                        </div>

                                        {mode === "decrypt" && privateKey && (
                                            <button type="button" className="secondary-action" onClick={() => setShowPrivateKey((visible) => !visible)}>
                                                {showPrivateKey ? "Hide Private Key" : "Reveal Private Key"}
                                            </button>
                                        )}

                                        {mode === "encrypt" && (
                                            <button
                                                type="button"
                                                className="secondary-action"
                                                onClick={async () => {
                                                    try {
                                                        const keyPair = await generateRsaKeyPair(selectedAlgorithm as RsaAlgorithm);
                                                        setPublicKey(keyPair.publicKey);
                                                        setPrivateKey(keyPair.privateKey);
                                                        setOperationError(null);
                                                    } catch {
                                                        setOperationError("LockBox could not generate the key pair locally.");
                                                    }
                                                }}
                                            >
                                                ⚙ Generate Key Pair
                                            </button>
                                        )}
                                        {mode === "encrypt" ? (
                                            privateKey && (
                                                <button
                                                    type="button"
                                                    className="secondary-action"
                                                    onClick={() => downloadPrivateKey(privateKey, selectedAlgorithm as RsaAlgorithm)}>
                                                    ↓ Download Private Key
                                                </button>)
                                        ) : (
                                            <>
                                                    <button
                                                        type="button"
                                                        className="secondary-action"
                                                        onClick={() => {
                                                            document.getElementById("pkey-upload")?.click();
                                                        }}>
                                                        Browse Private Key
                                                    </button>
                                                <input type="file" id="pkey-upload" hidden accept=".pem"
                                                    onChange={(event) => {
                                                        const file = event.target.files?.[0];
                                                        if (!file) return;

                                                        const reader = new FileReader();
                                                        reader.onload = () => setPrivateKey(reader.result as string);
                                                        reader.readAsText(file);
                                                    }} />
                                            </>
                                        )}

                                        <div className="security-note">
                                            <span>✓</span>
                                            {mode === "encrypt" ? "Your private key remains on your device" : "Your private key is processed locally"}
                                        </div>
                                    </div>
                                )}
                            {selectedAlgorithmConfig?.operation === "key-exchange" && (
                                <div className="key-exchange-section">
                                    <div className="keypair-header">
                                        <div>
                                            <strong>Secure key exchange</strong>
                                            <span>Establish a shared secret securely</span>
                                        </div>

                                        <span className="keypair-icon">⇄</span>
                                    </div>

                                    <div className="exchange-info">
                                        <div className="exchange-step">
                                            <span>01</span>
                                            <div>
                                                <strong>Generate key pair</strong>
                                                <small> Create your private and public keys</small>
                                            </div>
                                        </div>

                                        <div className="exchange-line" />

                                        <div className="exchange-step">
                                            <span>02</span>
                                            <div>
                                                <strong>Share public key</strong>
                                                <small>Your private key stays secret</small>
                                            </div>
                                        </div>
                                        <div className="exchange-line" />
                                        <div className="exchange-step">
                                            <span>03</span>
                                            <div>
                                                <strong>Establish shared secret</strong>
                                                <small>Both parties derive the same secret</small>
                                            </div>
                                        </div>
                                    </div>

                                    <label className="field-label">Your public key</label>
                                    <div className="key-input">
                                        <textarea
                                            placeholder="Generate your key pair to create a public key..."
                                            rows={3}
                                            value={exchangePublicKey}
                                            readOnly
                                        />
                                    </div>

                                    <label className="field-label">Your private key</label>
                                    <div className="key-input">
                                        <textarea
                                            placeholder="Generate or paste your private key here..."
                                            rows={3}
                                            value={exchangePrivateKey}
                                            onChange={(event) => setExchangePrivateKey(event.target.value)}
                                            className={exchangePrivateKey && !showExchangePrivateKey ? "secret-field" : ""}
                                        />
                                    </div>

                                    {exchangePrivateKey && (
                                        <button type="button" className="secondary-action" onClick={() => setShowExchangePrivateKey((visible) => !visible)}>
                                            {showExchangePrivateKey ? "Hide Private Key" : "Reveal Private Key"}
                                        </button>
                                    )}

                                    <label className="field-label">Peer public key</label>
                                    <div className="key-input">
                                        <textarea
                                            placeholder="Paste the other party's public key here..."
                                            rows={3}
                                            value={peerPublicKey}
                                            onChange={(event) => setPeerPublicKey(event.target.value)}
                                        />
                                    </div>

                                    <button
                                        type="button"
                                        className="secondary-action"
                                        onClick={async () => {
                                            try {
                                                const keyPair = await generateKeyExchangePair(selectedAlgorithm as KeyExchangeAlgorithm);
                                                setExchangePublicKey(keyPair.publicKey);
                                                setExchangePrivateKey(keyPair.privateKey);
                                                setSharedSecret("");
                                                setExchangeError("");
                                            } catch {
                                                setExchangeError("LockBox could not generate the key pair locally.");
                                            }
                                        }}
                                    >
                                        🔑 Generate Key Pair
                                    </button>

                                    <button
                                        type="button"
                                        className="secondary-action"
                                        disabled={!exchangePrivateKey || !peerPublicKey.trim()}
                                        onClick={async () => {
                                            try {
                                                const secret = await deriveSharedSecret(
                                                    selectedAlgorithm as KeyExchangeAlgorithm,
                                                    exchangePrivateKey,
                                                    peerPublicKey
                                                );
                                                setSharedSecret(secret);
                                                setExchangeError("");
                                            } catch (error) {
                                                setSharedSecret("");
                                                setExchangeError(error instanceof CryptoError ? error.message : "The shared secret could not be derived.");
                                            }
                                        }}
                                    >
                                        ⇄ Establish Shared Secret
                                    </button>

                                    {sharedSecret && (
                                        <>
                                            <label className="field-label">Derived shared secret</label>
                                            <div className="key-input">
                                                <textarea value={showSharedSecret ? sharedSecret : "Shared secret derived"} rows={3} readOnly />
                                            </div>
                                            <button type="button" className="secondary-action" onClick={() => setShowSharedSecret((visible) => !visible)}>
                                                {showSharedSecret ? "Hide Shared Secret" : "Reveal Shared Secret"}
                                            </button>
                                        </>
                                    )}

                                    {exchangeError && <div className="upload-error">⚠ {exchangeError}</div>}

                                    <div className="security-note">
                                        <span>✓</span> Private key and shared secret remain in this browser
                                    </div>
                                </div>
                            )}
                            {(selectedAlgorithmConfig?.operation === "encryption" || selectedAlgorithmConfig?.operation === "key-exchange") && (
                                <>
                                    {isProcessing ? (
                                        /************** PROCESSING PROGRESSION ANIMATION **************/
                                        <div className="processing-panel">
                                            <div className="processing-icon">◈</div>
                                            <div className="processing-title">
                                                {mode === "encrypt" ? "SECURING RESOURCE" : "RESTORING RESOURCE"}
                                            </div>
                                            <div className="processing-description">
                                                {processingSteps[processingStep]}...
                                            </div>

                                            <div className="processing-bar">
                                                <div className="processing-progress"
                                                    style={{ width: `${((processingStep + 1) / processingSteps.length) * 100}%`, }}
                                                />
                                            </div>
                                            <div className="processing-steps">
                                                {processingSteps.map((step, index) => (
                                                    <div
                                                        key={step}
                                                        className={
                                                            index < processingStep
                                                                ? "complete"
                                                                : index === processingStep
                                                                    ? "active"
                                                                    : ""
                                                        }
                                                    >
                                                        <span>
                                                            {index < processingStep
                                                                ? "✓"
                                                                : index === processingStep
                                                                    ? "●"
                                                                    : "○"}
                                                        </span>
                                                        {step}
                                                    </div>
                                                ))}
                                            </div>
                                            <div className="processing-meta">
                                                <span>{selectedAlgorithm}</span>
                                                <span>LOCAL PROCESSING</span>
                                            </div>
                                        </div>
                                    ) : operationError ? (
                                        /**************ERROR SHOWING SECTION **************/
                                        <div className="error-panel">
                                            <div className="error-icon">!</div>
                                            <div className="error-tile">{mode === "decrypt" ? "DECRYPTION FAILED" : "ENCRYPTION FAILED"}</div>
                                            <div className="error-description">{operationError} </div>
                                            <button className="primary-action" onClick={() => setOperationError(null)}>↻ Try Again</button>
                                        </div>
                                    ) : operationComplete ? (
                                        /**************COMPLETE RESULT SECTION **************/
                                        <div className="completion-panel">
                                            <div className="completion-icon">✓</div>

                                            <div className="completion-title">
                                                {mode === "encrypt" ? "ENCRYPTION COMPLETE" : "DECRYPTION COMPLETE"}
                                            </div>
                                            <div className="completion-description">
                                                {mode === "encrypt" ? "Your resource has been successfully secured." : "Your resource has been successfully restored."}
                                            </div>
                                            {operationResult && (
                                                <div className="result-container">
                                                    <div className="result-header">
                                                        <span>ENCRYPTED RESOURCE</span>
                                                        <span>{selectedAlgorithm}</span>
                                                    </div>
                                                    {/**************RESULT DISPLAY SECTION **************/}
                                                    <div className="result-box">
                                                        {mode === "decrypt" && decryptedFile && decryptedFolderSummary ? (
                                                            <div className="decrypted-preview folder-preview">
                                                                <div className="file-info">
                                                                    <strong>{decryptedFolderSummary.folderName}</strong>
                                                                    <span>{decryptedFolderSummary.fileCount} files · {decryptedFolderSummary.folderCount} folders · {formatBytes(decryptedFolderSummary.size)}</span>
                                                                </div>
                                                                <div className="generic-file-preview">
                                                                    📁 <span>Folder archive ready to download</span>
                                                                </div>
                                                            </div>
                                                        ) : mode === "decrypt" && decryptedFile ? (
                                                            <div className="decrypted-preview">
                                                                <div className="file-info">
                                                                    <strong>{decryptedFile.name}</strong>
                                                                    <span>
                                                                        {decryptedFile.type || "Unknown type"} ·{" "}
                                                                        {(decryptedFile.size / 1024 / 1024).toFixed(2)} MB
                                                                    </span>
                                                                </div>

                                                                {decryptedFile.type.startsWith("image/") && (
                                                                    <img src={URL.createObjectURL(decryptedFile)} alt={decryptedFile.name} className="preview-image" />
                                                                )}
                                                                {decryptedFile.type.startsWith("audio/") && (
                                                                    <audio controls src={URL.createObjectURL(decryptedFile)} className="preview-audio" />
                                                                )}
                                                                {decryptedFile.type.startsWith("video/") && (
                                                                    <video controls src={URL.createObjectURL(decryptedFile)} className="preview-video" />
                                                                )}
                                                                {decryptedFile.type.startsWith("text/") && (
                                                                    <iframe src={URL.createObjectURL(decryptedFile)} title={`Preview of ${decryptedFile.name}`} className="preview-text" />
                                                                )}
                                                                {!decryptedFile.type.startsWith("image/") && !decryptedFile.type.startsWith("audio/") && !decryptedFile.type.startsWith("video/") && !decryptedFile.type.startsWith("text/") && (
                                                                    <div className="generic-file-preview">📄
                                                                        <span>Preview unavailable</span>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ) : (
                                                            operationResult
                                                        )}
                                                    </div>
                                                    {/**************COPY & DOWNLOAD BUTTONS **************/}
                                                    <div className="result-actions">
                                                        <button
                                                            className={`result-action ${copied ? "done" : ""}`}
                                                            onClick={async () => {
                                                                if (!operationResult) return;

                                                                await navigator.clipboard.writeText(operationResult);

                                                                setCopied(true);
                                                                setTimeout(() => {
                                                                    setCopied(false);
                                                                }, 3000);
                                                            }}
                                                        >
                                                            {copied ? "✓ Copied" : "⧉ Copy"}
                                                        </button>
                                                        <button
                                                            className={`result-action ${downloaded ? "done" : ""}`}
                                                            disabled={mode === "decrypt" && !decryptedFile}
                                                            onClick={() => {
                                                                if (mode === "decrypt") {
                                                                    if (!decryptedFile) return;

                                                                    downloadFile(decryptedFile);
                                                                } else {
                                                                    const blob = new Blob(
                                                                        [operationResult],
                                                                        { type: "application/x-lockbox" }
                                                                    );

                                                                    const url = URL.createObjectURL(blob);
                                                                    const link = document.createElement("a");
                                                                    link.href = url;

                                                                    const originalName = selectedResource === "text" ? "encrypted-text" : selectedFile?.name ?? "lockbox-resource";
                                                                    const baseName = originalName.includes(".") ? originalName.substring(0, originalName.lastIndexOf(".")) : originalName;

                                                                    link.download = `${baseName}.lbx`;

                                                                    document.body.appendChild(link);
                                                                    link.click();
                                                                    document.body.removeChild(link);

                                                                    URL.revokeObjectURL(url);
                                                                }
                                                                setDownloaded(true);
                                                                setTimeout(() => {
                                                                    setDownloaded(false);
                                                                }, 3000);
                                                            }}
                                                        >
                                                            {downloaded
                                                                ? "✓ Downloaded"
                                                                : mode === "decrypt" && decryptedFile
                                                                    ? decryptedFolderSummary
                                                                        ? `↓ Download ${decryptedFolderSummary.folderName}.zip`
                                                                        : `↓ Download ${decryptedFile.name}`
                                                                    : "↓ Download"}
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                            <div className="completion-meta">
                                                <span>{selectedAlgorithm}</span>
                                                <span>LOCAL PROCESSING</span>
                                            </div>

                                            <button
                                                className="primary-action"
                                                onClick={() => {
                                                    setOperationComplete(false);
                                                    setOperationResult(null);
                                                    setResourceText("");
                                                    setInputPassword("");
                                                    setSelectedFile(null);
                                                    setFolderSummary(null);
                                                    setDecryptedFolderSummary(null);
                                                    setUploadError("");
                                                    setCopied(false);
                                                    setDownloaded(false);
                                                    setDecryptedFile(null);

                                                    const fileInput = document.getElementById("resource-upload") as HTMLInputElement | null;
                                                    if (fileInput) fileInput.value = "";
                                                }}
                                            >
                                                <span>↻</span>
                                                {mode === "encrypt" ? "Encrypt Another Resource" : "Decrypt Another Resource"}
                                            </button>
                                        </div>
                                    ) : (
                                        /**************MAIN BUTTON **************/
                                        <>
                                            <button
                                                className="primary-action"
                                                disabled={
                                                    isProcessing ||
                                                    !hasResource ||
                                                    keyMaterialMissing
                                                }
                                                onClick={async () => {
                                                    setCopied(false);
                                                    setDownloaded(false);
                                                    setOperationResult(null);
                                                    setOperationComplete(false);
                                                    setIsProcessing(true);
                                                    setProcessingStep(0);
                                                    setOperationError(null);

                                                    try {
                                                        if (mode === "encrypt") {
                                                            if (selectedResource === "text") {
                                                                if (selectedAlgorithmConfig?.operation === "key-exchange") {
                                                                    const secret = await deriveSharedSecret(selectedAlgorithm as KeyExchangeAlgorithm, exchangePrivateKey, peerPublicKey);
                                                                    const result = await encryptTextWithSharedSecret(resourceText, secret, setProcessingStep);
                                                                    setOperationResult(createPackage(result, {
                                                                        resourceType: "text",
                                                                        keyExchangeAlgorithm: selectedAlgorithm as KeyExchangeAlgorithm,
                                                                        keyDerivation: "HKDF-SHA-256",
                                                                        senderPublicKey: exchangePublicKey,
                                                                    }));
                                                                } else if (selectedAlgorithmConfig?.keyType === "keypair") {
                                                                    const result = await encryptRsaText(resourceText, publicKey, selectedAlgorithm as RsaAlgorithm, setProcessingStep);
                                                                    setOperationResult(createRsaPackage(result, { resourceType: "text" }));
                                                                } else {
                                                                    const result = await encryptText(resourceText, inputPassword, setProcessingStep, selectedAlgorithm as SymmetricAlgorithm);
                                                                    setOperationResult(createPackage(result, { resourceType: "text" }));
                                                                }
                                                            } else {
                                                                if (!selectedFile) {
                                                                    setOperationError("Please select a file first.");
                                                                    return;
                                                                }
                                                                const isKeyExchange = selectedAlgorithmConfig?.operation === "key-exchange";
                                                                const { result, metadata } = isKeyExchange
                                                                    ? await encryptFileWithSharedSecret(
                                                                        selectedFile,
                                                                        selectedResource,
                                                                        await deriveSharedSecret(selectedAlgorithm as KeyExchangeAlgorithm, exchangePrivateKey, peerPublicKey),
                                                                        setProcessingStep
                                                                    )
                                                                    : await encryptFile(selectedFile, selectedResource, inputPassword, setProcessingStep, "AES-256-GCM");

                                                                const encryptedPackage = createPackage(result, {
                                                                    ...metadata,
                                                                    ...(selectedAlgorithmConfig?.operation === "key-exchange"
                                                                        ? { keyExchangeAlgorithm: selectedAlgorithm as KeyExchangeAlgorithm, keyDerivation: "HKDF-SHA-256" as const, senderPublicKey: exchangePublicKey }
                                                                        : {}),
                                                                    ...(selectedResource === "folder" && folderSummary
                                                                        ? { folderName: folderSummary.folderName, folderFileCount: folderSummary.fileCount, folderCount: folderSummary.folderCount }
                                                                        : {}),
                                                                });

                                                                setOperationResult(encryptedPackage);
                                                            }
                                                        } else {
                                                            if (selectedResource === "text") {
                                                                const packageData = unpackage(resourceText);
                                                                if ("wrappedKey" in packageData) {
                                                                    const decryptedText = await decryptRsaText(packageData.ciphertext, packageData.wrappedKey, packageData.iv, privateKey, setProcessingStep);
                                                                    setOperationResult(decryptedText);
                                                                } else if (packageData.keyExchangeAlgorithm && packageData.senderPublicKey) {
                                                                    const secret = await deriveSharedSecret(packageData.keyExchangeAlgorithm, exchangePrivateKey, packageData.senderPublicKey);
                                                                    const decryptedText = packageData.keyDerivation === "HKDF-SHA-256"
                                                                        ? await decryptTextWithSharedSecret(packageData.ciphertext, secret, packageData.salt, packageData.iv, setProcessingStep)
                                                                        : await decryptText(packageData.ciphertext, secret, packageData.salt, packageData.iv, setProcessingStep, packageData.algorithm);
                                                                    setOperationResult(decryptedText);
                                                                } else {
                                                                    setProcessingStep(1);
                                                                    const decryptedText = await decryptText(packageData.ciphertext, inputPassword, packageData.salt, packageData.iv, setProcessingStep, packageData.algorithm);

                                                                    setProcessingStep(4);
                                                                    setOperationResult(decryptedText);
                                                                }
                                                            } else {
                                                                if (!selectedFile) {
                                                                    setOperationError("Please provide an encrypted LockBox package.");
                                                                    return;
                                                                }
                                                                const encryptedPackage = await selectedFile.text();
                                                                const packageData = unpackage(encryptedPackage.trim());
                                                                if ("wrappedKey" in packageData) {
                                                                    throw new CryptoError("INVALID_PACKAGE", "RSA encryption currently supports text resources only.");
                                                                }
                                                                const isKeyExchangePackage = !!packageData.keyExchangeAlgorithm && !!packageData.senderPublicKey;
                                                                const decryptionPassword = isKeyExchangePackage
                                                                    ? await deriveSharedSecret(packageData.keyExchangeAlgorithm!, exchangePrivateKey, packageData.senderPublicKey!)
                                                                    : inputPassword;
                                                                setProcessingStep(1);
                                                                const decryptedFile = isKeyExchangePackage && packageData.keyDerivation === "HKDF-SHA-256"
                                                                    ? await decryptFileWithSharedSecret(encryptedPackage.trim(), decryptionPassword, setProcessingStep)
                                                                    : await decryptFile(encryptedPackage.trim(), decryptionPassword, setProcessingStep);

                                                                setProcessingStep(4);
                                                                setDecryptedFile(decryptedFile);
                                                                if (packageData.resourceType === "folder") {
                                                                    const summary = await inspectFolderArchive(decryptedFile, packageData.folderName);
                                                                    setDecryptedFolderSummary(summary);
                                                                    setOperationResult(`Restored folder: ${summary.folderName}`);
                                                                } else {
                                                                    setOperationResult(`Decrypted file: ${decryptedFile.name}`);
                                                                }
                                                            }
                                                        }

                                                        setProcessingStep(processingSteps.length);
                                                        setIsProcessing(false);
                                                        setOperationComplete(true);

                                                    } catch (error) {
                                                        console.error("Operation failed: ", error);

                                                        setIsProcessing(false);
                                                        setOperationComplete(false);

                                                        if (error instanceof CryptoError) {
                                                            switch (error.code) {
                                                                case "INVALID_PACKAGE":
                                                                    setOperationError("This doesn't appear to be a valid LockBox encrypted resource");
                                                                    break;
                                                                case "AUTHENTICATION_FAILED":
                                                                    setOperationError("The password is incorrect or the encrypted resource has been modified");
                                                                    break;
                                                                case "DECRYPTION_FAILED":
                                                                    setOperationError("LockBox could not decrypt this resource. Please try again.");
                                                                    break;
                                                                case "ENCRYPTION_FAILED":
                                                                    setOperationError("LockBox could not encrypt this resource. Please try again.");
                                                                    break;
                                                                case "EMPTY_FOLDER":
                                                                    setOperationError("The selected folder is empty. Choose a folder containing at least one file.");
                                                                    break;
                                                                case "ARCHIVE_FAILED":
                                                                    setOperationError("Some files could not be read, so the folder archive could not be created.");
                                                                    break;
                                                                case "ARCHIVE_CORRUPTED":
                                                                    setOperationError("The folder archive is corrupted and could not be restored.");
                                                                    break;
                                                                case "EXTRACTION_FAILED":
                                                                    setOperationError("The folder could not be extracted. Please try again.");
                                                                    break;
                                                                case "RESOURCE_TOO_LARGE":
                                                                    setOperationError(error.message);
                                                                    break;
                                                                default:
                                                                    setOperationError("The operation could not be completed.");
                                                            }
                                                        } else {
                                                            setOperationError(mode === "decrypt" ? "The entered lbx file has been tampered with or corrupted" : "Something unexpected happened. Please try again");
                                                        }
                                                    }
                                                }}
                                            >
                                                <span>
                                                    {mode === "encrypt" ? "🔒" : "🔓"}
                                                </span>

                                                {mode === "encrypt" ? "Encrypt Resource" : "Decrypt Resource"}
                                            </button>
                                            {!hasResource ? (
                                                <p className="action-reason" role="status">
                                                    {resourceRequirementMessage}
                                                </p>
                                            ) : keyMaterialMissing ? (
                                                <p className="action-reason" role="status">
                                                    {selectedAlgorithmConfig?.operation === "key-exchange"
                                                        ? mode === "encrypt"
                                                            ? "Generate your key pair and enter the peer public key before encrypting."
                                                            : "Generate or enter your private key before decrypting."
                                                        : keyRequirementMessage}
                                                </p>
                                            ) : null}
                                        </>
                                    )}
                                </>
                            )}
                        </section>
                    </div>
                    {/************** APP DETAILS **************/}
                    <section className="activity-panel">
                        <div className="activity-heading">
                            <span className="activity-dot" />
                            <div>
                                <strong>Cryptographic Engine</strong>
                                <span>READY</span>
                            </div>
                        </div>
                        <div className="activity-flow">
                            <span>RESOURCE</span>
                            <i>→</i>
                            <span>KEY DERIVATION</span>
                            <i>→</i>
                            <span>{selectedAlgorithm}</span>
                            <i>→</i>
                            <span>AUTHENTICATION</span>
                            <i>→</i>
                            <strong>{mode === "encrypt" ? "ENCRYPTED" : "DECRYPTED"}</strong>
                        </div>
                    </section>
                </section>
            </main>
            <footer>
                <span>LockBox</span>
                <span>CLIENT SIDE CRYPTOGRAPHY</span>
                <span>● SYSTEM READY</span>
            </footer>
        </div>
    )
}

export default App;
