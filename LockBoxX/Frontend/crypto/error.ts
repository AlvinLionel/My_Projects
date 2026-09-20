export type CryptoErrorCode =
    "INVALID_PACKAGE" |
    "AUTHENTICATION_FAILED" |
    "ENCRYPTION_FAILED" |
    "DECRYPTION_FAILED" |
    "KEY_EXCHANGE_FAILED" |
    "EMPTY_FOLDER" |
    "ARCHIVE_FAILED" |
    "ARCHIVE_CORRUPTED" |
    "EXTRACTION_FAILED" |
    "RESOURCE_TOO_LARGE";
export class CryptoError extends Error {
    code: CryptoErrorCode;

    constructor(code: CryptoErrorCode, message: string) {
        super(message);
        this.name = "CryptoError";
        this.code = code;
    }
}