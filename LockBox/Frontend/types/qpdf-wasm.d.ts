declare module "qpdf-wasm" {
  interface QpdfModule {
    FS: {
      writeFile(path: string, data: Uint8Array): void;
      readFile(path: string): Uint8Array;
      unlink(path: string): void;
    };

    callMain(args: string[]): number;
  }

  interface QpdfModuleOptions {
    locateFile?: (fileName: string) => string;
  }

  const initQPDF: (
    options?: QpdfModuleOptions
  ) => Promise<QpdfModule>;

  export default initQPDF;
}