import { encryptFile } from "../crypto/resourceCrypto";
import type { CryptoProgress } from "../crypto/aes";
import { buildSelfDecryptingHtml, type selfDecryptingResourceType } from "../crypto/selfDecryptingHtml";

export async function lockMediaToHtml(file: File,resourceType:selfDecryptingResourceType,password:string,onProgress?:CryptoProgress):Promise<Blob>{
    try{
        const {result,metadata} = await encryptFile(file,resourceType,password,onProgress,"AES-256-GCM");
        console.log("metadata:", JSON.stringify(metadata));
        const html = buildSelfDecryptingHtml({
            ciphertext:result.ciphertext,
            salt:result.salt,
            iv:result.iv,
            mimeType:metadata.mimeType,
            filename:metadata.filename,
            resourceType,
        });

        return new Blob([html], {type: "text/html"});
    }catch(error){
        console.error("Media HTML lock error:", error);
        throw error;
    }
}