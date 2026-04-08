import { parseSync } from "@swc/core";

export interface SyntaxError {
  message: string;
  line: number;
  column: number;
}

export interface ValidationResult {
  valid: boolean;
  errors: SyntaxError[];
}

type SyntaxType = "typescript" | "ecmascript";
type JsxSetting = boolean;

function detectLanguage(filename: string): { syntax: SyntaxType; jsx: JsxSetting } {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  switch (ext) {
    case "ts":
      return { syntax: "typescript", jsx: false };
    case "tsx":
      return { syntax: "typescript", jsx: true };
    case "jsx":
      return { syntax: "ecmascript", jsx: true };
    case "js":
    case "mjs":
    case "cjs":
    default:
      return { syntax: "ecmascript", jsx: false };
  }
}

export function validateSyntax(code: string, filename: string): ValidationResult {
  const { syntax, jsx } = detectLanguage(filename);

  try {
    if (syntax === "typescript") {
      parseSync(code, {
        syntax: "typescript",
        tsx: jsx,
        target: "es2022",
      });
    } else {
      parseSync(code, {
        syntax: "ecmascript",
        jsx,
        target: "es2022",
      });
    }

    return { valid: true, errors: [] };
  } catch (err: any) {
    const message = err.message || String(err);

    // SWC error messages typically contain line/column info like:
    // "error: Expected ';', got 'const' at file.ts:10:5"
    let line = 0;
    let column = 0;
    const locationMatch = message.match(/:(\d+):(\d+)/);
    if (locationMatch) {
      line = parseInt(locationMatch[1], 10);
      column = parseInt(locationMatch[2], 10);
    }

    return {
      valid: false,
      errors: [{ message, line, column }],
    };
  }
}
