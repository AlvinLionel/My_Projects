import JSZip from "jszip";
import { CryptoError } from "./error";

export interface FolderSummary {
    folderName: string;
    fileCount: number;
    folderCount: number;
    size: number;
}
export interface FolderArchive {
    file: File;
    summary: FolderSummary;
}
interface FolderEntry {
    path: string;
    file?: File;
    directory: boolean;
}

const MAX_FOLDER_BYTES = 100 * 1024 * 1024;

function getRelativePath(file: File): string {
    const path = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
    return path.replace(/\\/g, "/").replace(/^\/+/, "");
}

function getFolderName(files: File[]): string {
    const firstPath = getRelativePath(files[0]);
    return firstPath.includes("/") ? firstPath.split("/")[0] : "Selected folder";
}

async function createArchive(entries: FolderEntry[], folderName: string): Promise<FolderArchive> {
    const files = entries.filter(entry => !entry.directory && entry.file);

    if (files.length === 0) throw new CryptoError("EMPTY_FOLDER", "The selected folder is empty.");

    const totalBytes = files.reduce((total, entry) => total + (entry.file?.size ?? 0), 0);
    if (totalBytes > MAX_FOLDER_BYTES) throw new CryptoError("RESOURCE_TOO_LARGE", "This folder is too large for safe browser-only processing. Please choose a folder smaller than 100 MB.");

    try {
        const zip = new JSZip();

        for (const entry of entries) {
            if (!entry.path) throw new Error("Unsupported folder entry.");

            if (entry.directory) {
                zip.folder(entry.path.replace(/\/$/, ""));
            } else if (entry.file) {
                zip.file(entry.path, entry.file);
            }
        }

        const archive = await zip.generateAsync({ type: "blob", compression: "STORE", streamFiles: true });
        const archiveFile = new File([archive], `${folderName}.zip`, { type: "application/zip" });
        const folders = new Set<string>();

        for (const entry of entries.filter(item => item.directory)) folders.add(entry.path.replace(/\/$/, ""));
        for (const entry of files) {
            const parts = entry.path.split("/");
            parts.pop();
            for (let index = 1; index <= parts.length; index++) folders.add(parts.slice(0, index).join("/"));
        }

        return {
            file: archiveFile,
            summary: {
                folderName,
                fileCount: files.length,
                folderCount: folders.size,
                size: archiveFile.size,
            },
        };
    } catch (error) {
        if (error instanceof CryptoError) throw error;

        throw new CryptoError("ARCHIVE_FAILED", "The selected folder could not be archived.");
    }
}

export async function createFolderArchive(files: File[]): Promise<FolderArchive> {
    if (files.length === 0) throw new CryptoError("EMPTY_FOLDER", "The selected folder is empty.");

    return createArchive(
        files.map(file => ({ path: getRelativePath(file), file, directory: false })), getFolderName(files)
    );
}

export async function createFolderArchiveFromDirectory(directory: FileSystemDirectoryHandle): Promise<FolderArchive> {
    const entries: FolderEntry[] = [];

    async function visit(handle: FileSystemDirectoryHandle, parentPath: string): Promise<void> {
        for await (const [name, entry] of handle.entries()) {
            const path = `${parentPath}/${name}`;
            if (entry.kind === "file") {
                entries.push({ path, file: await entry.getFile(), directory: false });
            } else {
                entries.push({ path: `${path}/`, directory: true });
                await visit(entry, path);
            }
        }
    }

    await visit(directory, directory.name);
    return createArchive(entries, directory.name);
}

export async function inspectFolderArchive(file: File, fallbackName = "Restored folder"): Promise<FolderSummary> {
    try {
        const zip = await JSZip.loadAsync(await file.arrayBuffer());
        const paths = Object.keys(zip.files);
        const filePaths = paths.filter(path => !zip.files[path].dir);
        const folderPaths = new Set<string>();

        for (const path of filePaths) {
            const parts = path.split("/");
            parts.pop();
            for (let index = 1; index <= parts.length; index++) {
                folderPaths.add(parts.slice(0, index).join("/"));
            }
        }

        return {
            folderName: filePaths[0]?.split("/")[0] || fallbackName,
            fileCount: filePaths.length,
            folderCount: folderPaths.size,
            size: file.size,
        };
    } catch {
        throw new CryptoError("ARCHIVE_CORRUPTED", "The decrypted folder archive is corrupted or cannot be read.");
    }
}

export function formatBytes(size: number): string {
    if (size < 1024) return `${size} B`;

    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    
    return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}
