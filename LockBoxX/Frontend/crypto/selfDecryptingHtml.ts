import { bytesToBase64 } from "./package";

export type selfDecryptingResourceType = "image" | "audio" | "video";

export interface selfDecryptingPayload {
    ciphertext: Uint8Array<ArrayBuffer>;
    salt: Uint8Array<ArrayBuffer>;
    iv: Uint8Array<ArrayBuffer>;
    mimeType: string;
    filename: string;
    resourceType: selfDecryptingResourceType;
}

const PBKDF2_ITERATIONS = 600_000;
const RESOURCE_TITLES: Record<selfDecryptingResourceType, string> = {
    image: "Protected Image",
    audio: "Protected Audio",
    video: "Protected Video"
};

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function toInlineJson(value: unknown): string {
    return JSON.stringify(value).replace(/</g, "\\u003c");
}

export function buildSelfDecryptingHtml(payload: selfDecryptingPayload): string {
    const embeddedPayload = toInlineJson({
        ciphertext: bytesToBase64(payload.ciphertext),
        salt: bytesToBase64(payload.salt),
        iv: bytesToBase64(payload.iv),
        mimeType: payload.mimeType,
        filename: payload.filename,
        resourceType: payload.resourceType,
        iterations: PBKDF2_ITERATIONS,
    });
    console.log("Text console message");
    const title = RESOURCE_TITLES[payload.resourceType];

    console.log("resourceType:", JSON.stringify(payload.resourceType));
    console.log("filename:", JSON.stringify(payload.filename));
    console.log("title:", JSON.stringify(title));

    return `
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${escapeHtml(title)} — LockBoxX</title>
        <style>
            :root {
                color-scheme: light dark;
                --bg: #f4f5f7;
                --card: #ffffff;
                --text: #1a1a1a;
                --muted: #6b7280;
                --accent: #4f46e5;
                --accent-hover: #4338ca;
                --error: #dc2626;
                --border: #e5e7eb;
            }
            @media (prefers-color-scheme: dark) {
                :root {
                    --bg: #121212;
                    --card: #1e1e1e;
                    --text: #f3f4f6;
                    --muted: #9ca3af;
                    --border: #333333;
                }
            }
            * { box-sizing: border-box; }
            body {
                margin: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 24px;
                background: var(--bg);
                color: var(--text);
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }
            .card {
                width: 100%;
                max-width: 420px;
                background: var(--card);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 32px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
                text-align: center;
            }
            .icon { font-size: 40px; margin-bottom: 8px; }
            h1 { font-size: 18px; margin: 0 0 4px; }
            .filename {
                color: var(--muted);
                font-size: 13px;
                margin: 0 0 24px;
                word-break: break-all;
            }
            form { display: flex; flex-direction: column; gap: 12px; }
            input[type="password"] {
                width: 100%;
                padding: 12px 14px;
                border-radius: 10px;
                border: 1px solid var(--border);
                background: transparent;
                color: var(--text);
                font-size: 15px;
            }
            input[type="password"]:focus { outline: 2px solid var(--accent); border-color: transparent; }
            button {
                padding: 12px 14px;
                border-radius: 10px;
                border: none;
                background: var(--accent);
                color: white;
                font-size: 15px;
                font-weight: 600;
                cursor: pointer;
            }
            button:hover { background: var(--accent-hover); }
            button:disabled { opacity: 0.6; cursor: default; }
            .error {
                color: var(--error);
                font-size: 13px;
                margin: 0;
            }
            .note {
                color: var(--muted);
                font-size: 12px;
                margin-top: 20px;
            }
            #media-container img,
            #media-container video {
                max-width: 100%;
                border-radius: 10px;
                display: block;
                margin: 0 auto 16px;
            }
            #media-container audio { width: 100%; margin-bottom: 16px; }
            .download-link {
                display: inline-block;
                margin-top: 4px;
                color: var(--accent);
                font-size: 14px;
                text-decoration: none;
                font-weight: 600;
            }
            .download-link:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">🔒</div>
            <h1>${escapeHtml(title)}</h1>
            <p class="filename">${escapeHtml(payload.filename)}</p>

            <form id="unlock-form">
                <input type="password" id="password-input" placeholder="Enter password" autocomplete="off" autofocus required>
                <button type="submit">Unlock</button>
            </form>
            <p id="error-message" class="error" hidden></p>
            <div id="media-container" hidden></div>

            <p class="note">Decrypted locally in your browser. Nothing is uploaded anywhere.</p>
        </div>

    <script>
        (function(){
            "use strict";

            var PAYLOAD = ${embeddedPayload};

            function base64ToBytes(base64) {
                var binary = atob(base64);
                var bytes = new Uint8Array(binary.length);
                for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                return bytes;
            }

            async function deriveKey(password, salt) {
                var passwordKey = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode(password),
                    "PBKDF2",
                    false,
                    ["deriveBits"]
                );
                var keyBits = await crypto.subtle.deriveBits(
                    { name: "PBKDF2", salt: salt, iterations: PAYLOAD.iterations, hash: "SHA-256" },
                    passwordKey,
                    256
                );

                return crypto.subtle.importKey("raw", keyBits, { name: "AES-GCM" }, false, ["decrypt"]);
            }

            async function unlock(password) {
                var salt = base64ToBytes(PAYLOAD.salt);
                var iv = base64ToBytes(PAYLOAD.iv);
                var ciphertext = base64ToBytes(PAYLOAD.ciphertext);
                var key = await deriveKey(password, salt);
                var plaintextBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);

                return new Blob([plaintextBuffer], { type: PAYLOAD.mimeType || "application/octet-stream" });
            }

            function showMedia(url) {
                document.getElementById("unlock-form").hidden = true;

                var container = document.getElementById("media-container");
                container.hidden = false;

                var mediaEl;
                if (PAYLOAD.resourceType === "image") {
                    mediaEl = document.createElement("img");
                    mediaEl.src = url;
                    mediaEl.alt = PAYLOAD.filename;
                } else if (PAYLOAD.resourceType === "video") {
                    mediaEl = document.createElement("video");
                    mediaEl.src = url;
                    mediaEl.controls = true;
                } else {
                    mediaEl = document.createElement("audio");
                    mediaEl.src = url;
                    mediaEl.controls = true;
                }
                container.appendChild(mediaEl);

                var downloadLink = document.createElement("a");
                downloadLink.href = url;
                downloadLink.download = PAYLOAD.filename || "decrypted-file";
                downloadLink.textContent = "Download original file";
                downloadLink.className = "download-link";
                container.appendChild(downloadLink);
            }

            document.getElementById("unlock-form").addEventListener("submit", async function (event) {
                event.preventDefault();

                var password = document.getElementById("password-input").value;
                var errorEl = document.getElementById("error-message");
                var submitButton = event.target.querySelector("button");

                errorEl.hidden = true;
                submitButton.disabled = true;
                submitButton.textContent = "Unlocking…";

                try {
                    var blob = await unlock(password);
                    var url = URL.createObjectURL(blob);
                    showMedia(url);
                } catch (err) {
                    errorEl.textContent = "Incorrect password. Please try again.";
                    errorEl.hidden = false;
                    submitButton.disabled = false;
                    submitButton.textContent = "Unlock";
                }
            });
        })();
        </script>
    </body>`;
}