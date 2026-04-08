declare module "tar-stream" {
  import { Readable, Writable } from "stream";

  interface PackEntry {
    name: string;
    size?: number;
    type?: "file" | "directory" | "link" | "symlink";
    mode?: number;
    mtime?: Date;
    uid?: number;
    gid?: number;
  }

  interface Pack extends Readable {
    entry(header: PackEntry, data?: string | Buffer): Writable;
    entry(header: PackEntry, callback?: (err: Error | null) => void): Writable;
    finalize(): void;
  }

  interface Extract extends Writable {
    on(event: "entry", listener: (header: PackEntry, stream: Readable, next: () => void) => void): this;
    on(event: string, listener: (...args: any[]) => void): this;
  }

  export function pack(): Pack;
  export function extract(): Extract;
}
