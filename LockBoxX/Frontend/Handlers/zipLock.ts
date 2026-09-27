import { ZipWriter, BlobWriter, BlobReader } from "@zip.js/zip.js";
import { CryptoError } from "../crypto/error";
import { collectDirectoryEntries, collectFileListEntries, getFolderName, MAX_FOLDER_BYTES, MAX_FOLDER_SIZE_MESSAGE, type FolderEntry, } from "../crypto/folderArchive";
export interface PasswordProtectedZip {
    file: File;
    fileCount: number;
    folderCount: number;
}
async function buildPasswordProtectedZip(entries: FolderEntry[], folderName: string, password: string): Promise<PasswordProtectedZip> {
    const files = entries.filter(entry => !entry.directory && entry.file);

    if (files.length === 0) throw new CryptoError("EMPTY_FOLDER", "The selected folder is empty.");

    const totalBytes = files.reduce((total, entry) => total + (entry.file?.size ?? 0), 0);

    if (totalBytes > MAX_FOLDER_BYTES) throw new CryptoError("RESOURCE_TOO_LARGE", MAX_FOLDER_SIZE_MESSAGE);

    try {
        const zipWriter = new ZipWriter(new BlobWriter("application/zip"), {
            password,
            encryptionStrength: 3,
            zipCrypto: false,
        });

        const folders = new Set<string>();

        for (const entry of entries) {
            if (entry.directory) {
                folders.add(entry.path.replace(/\/$/, ""));
                continue;
            }

            if (!entry.file) continue;

            await zipWriter.add(entry.path, new BlobReader(entry.file));

            const parts = entry.path.split("/");
            parts.pop();
            
            for (let index = 1; index <= parts.length; index++) folders.add(parts.slice(0, index).join("/"));
        }

        const zipBlob = await zipWriter.close();
        const zipFile = new File([zipBlob], `${folderName}.zip`, { type: "application/zip" });

        return { file: zipFile, fileCount: files.length, folderCount: folders.size };
    } catch (error) {
        if (error instanceof CryptoError) throw error;

        throw new CryptoError("ARCHIVE_FAILED", "The selected folder could not be locked.");
    }
}

export async function lockFolderToZip(files: File[], password: string): Promise<PasswordProtectedZip> {
    if (files.length === 0) throw new CryptoError("EMPTY_FOLDER", "The selected folder is empty.");

    return buildPasswordProtectedZip(collectFileListEntries(files), getFolderName(files), password);
}

export async function lockDirectoryToZip(directory: FileSystemDirectoryHandle, password: string): Promise<PasswordProtectedZip> {
    const entries = await collectDirectoryEntries(directory);

    return buildPasswordProtectedZip(entries, directory.name, password);
}
