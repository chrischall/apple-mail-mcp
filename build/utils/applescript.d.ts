/**
 * AppleScript Execution Utilities
 *
 * This module provides a safe interface for executing AppleScript commands
 * on macOS. It handles script execution, error capture, and result parsing.
 *
 * @module utils/applescript
 */
import type { AppleScriptResult, AppleScriptOptions } from "../types.js";
/**
 * Executes an AppleScript command and returns a structured result.
 *
 * This function serves as the bridge between TypeScript and macOS AppleScript.
 * It handles the complexity of shell escaping, execution, and error handling
 * so that calling code can work with clean TypeScript interfaces.
 *
 * The script is executed synchronously via the `osascript` command-line tool.
 * Multi-line scripts are supported and preserved (important for AppleScript
 * tell blocks and repeat loops).
 *
 * @param script - The AppleScript code to execute
 * @param options - Optional execution settings (timeout, etc.)
 * @returns A result object with success status and output or error message
 *
 * @example
 * ```typescript
 * // Basic usage with default timeout (30 seconds)
 * const result = executeAppleScript(`
 *   tell application "Notes"
 *     get name of every note
 *   end tell
 * `);
 *
 * // With custom timeout for complex operations
 * const result = executeAppleScript(complexScript, { timeoutMs: 60000 });
 *
 * if (result.success) {
 *   console.log("Notes:", result.output);
 * } else {
 *   console.error("Failed:", result.error);
 * }
 * ```
 */
export declare function executeAppleScript(script: string, options?: AppleScriptOptions): AppleScriptResult;
//# sourceMappingURL=applescript.d.ts.map