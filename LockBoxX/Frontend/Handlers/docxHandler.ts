import { lockDocxFile, unlockDocxFile } from "../crypto/docxAgile";

export async function lockDocx(file: File, password: string): Promise<Blob> {
    try {
        return await lockDocxFile(file, password);
    } catch (error) {
        console.error("DOCX lock error:", error);
        throw error;
    }
}

export async function unlockDocx(file: File, password: string): Promise<Blob> {
    try {
        return await unlockDocxFile(file, password);
    } catch (error) {
        console.error("DOCX unlock error:", error);
        throw error;
    }
}
