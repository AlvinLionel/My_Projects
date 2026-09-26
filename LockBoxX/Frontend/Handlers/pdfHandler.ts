import initQPDF from "qpdf-wasm";
import { CryptoError } from "../crypto/error";

type QpdfModule = Awaited<ReturnType<typeof initQPDF>>;

export class PdfEngineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PdfEngineError";
  }
}

const INIT_TIMEOUT_MS = 20_000;
const INPUT_PATH = "/input.pdf";
const OUTPUT_PATH = "/output.pdf";
const JOB_PATH = "/job.json";
const EMPTY = new Uint8Array(0);

let qpdfPromise: Promise<QpdfModule> | null = null;

export function initPdfLib(): Promise<QpdfModule> {
  if (!qpdfPromise) {
    qpdfPromise = startQpdf().catch((error) => {
      qpdfPromise = null;
      throw error;
    });
  }
  return qpdfPromise;
}

async function startQpdf(): Promise<QpdfModule> {
  if (!self.crossOriginIsolated) {
    throw new PdfEngineError(
      "PDF protection couldn't be started. LockBoxX couldn't initialize the PDF security engine. Please refresh the page and try again."
    );
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new PdfEngineError(
            "PDF protection couldn't be initialized. The PDF security engine failed to load. Please refresh the page and try again."
          )
        ),
      INIT_TIMEOUT_MS
    );
  });

  try {
    return await Promise.race([
      initQPDF({ locateFile: (fileName) => `/qpdf/${fileName}` }),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function runQpdf(
  qpdf: QpdfModule,
  args: string[],
  input: Uint8Array,
  job?: object
): Uint8Array | null {
  try {
    qpdf.FS.writeFile(INPUT_PATH, input);
    qpdf.FS.writeFile(OUTPUT_PATH, EMPTY);
    if (job) {
      qpdf.FS.writeFile(JOB_PATH, new TextEncoder().encode(JSON.stringify(job)));
    }

    let code: number;
    try {
      code = qpdf.callMain(args);
    } catch {
      return null;
    }
    if (code !== 0 && code !== 3) return null;

    const output = qpdf.FS.readFile(OUTPUT_PATH);
    return output.length > 0 ? output : null;
  } finally {
    qpdf.FS.writeFile(INPUT_PATH, EMPTY);
    qpdf.FS.writeFile(OUTPUT_PATH, EMPTY);
    qpdf.FS.writeFile(JOB_PATH, EMPTY);
  }
}

export async function lockPdf(file: File, password: string): Promise<Blob> {
  if (!password) {
    throw new CryptoError("ENCRYPTION_FAILED", "A password is required to lock a PDF.");
  }

  const qpdf = await initPdfLib();
  const input = new Uint8Array(await file.arrayBuffer());

  const output = runQpdf(qpdf, [`--job-json-file=${JOB_PATH}`], input, {
    inputFile: INPUT_PATH,
    outputFile: OUTPUT_PATH,
    encrypt: { userPassword: password, ownerPassword: password, "256bit": {} },
  });
  if (!output) {
    throw new CryptoError("ENCRYPTION_FAILED", "The PDF could not be encrypted.");
  }

  return new Blob([new Uint8Array(output)], { type: "application/pdf" });
}

export async function unlockPdf(file: File, password: string): Promise<Blob> {
  const qpdf = await initPdfLib();
  const input = new Uint8Array(await file.arrayBuffer());

  const output = runQpdf(
    qpdf,
    ["--password=" + password, "--decrypt", INPUT_PATH, OUTPUT_PATH],
    input
  );
  if (!output) {
    throw new CryptoError(
      "AUTHENTICATION_FAILED",
      "The password is incorrect or the PDF is damaged."
    );
  }

  return new Blob([new Uint8Array(output)], { type: "application/pdf" });
}

export function downloadPdf(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
