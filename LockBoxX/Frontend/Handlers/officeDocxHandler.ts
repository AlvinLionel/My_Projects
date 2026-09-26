import { lockFile, unlockFile } from "../crypto/officeCrypto";

const OFFICE_MIME_TYPES: Record<string, string> = {
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

function extensionOf(fileName: string): string {
    return fileName.split(".").pop()?.toLowerCase() ?? "";
}

export async function lockOfficeFile(file: File, password: string): Promise<Blob> {
    const bytes = await lockFile(file, password);

    return new Blob([bytes], { type: OFFICE_MIME_TYPES[extensionOf(file.name)] });
}

export async function unlockOfficeFile(file: File, password: string): Promise<Blob> {
    const bytes = await unlockFile(file, password);

    return new Blob([bytes], { type: OFFICE_MIME_TYPES[extensionOf(file.name)] });
}