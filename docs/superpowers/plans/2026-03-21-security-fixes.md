# Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 5 confirmed security vulnerabilities (AppleScript injection, path traversal, DoS via unbounded arrays, PII leakage in logs) and bump npm dependencies.

**Architecture:** All fixes are targeted and minimal — Zod schema validation at the MCP tool boundary, service-layer input validation in `appleMailManager.ts`, and log redaction in `applescript.ts`. No new source files. Two new test files.

**Tech Stack:** TypeScript, Zod (schema validation), Vitest (tests), Node.js `path`/`os` stdlib

---

## File Map

| File | Change |
|------|--------|
| `src/index.ts` | Add `.regex(/^\d+$/)` to 11 message `id` schemas; add `.regex(...)` to `dateFrom`/`dateTo`; add `.max(100)` to 6 batch `ids` arrays |
| `src/services/appleMailManager.ts` | Add `escapeForAppleScript()` to date interpolation; add path/name validation in `saveAttachment()` |
| `src/utils/applescript.ts` | Redact quoted strings in debug log preview |
| `src/index.test.ts` | New file: Zod schema tests for ID regex, date regex, batch max |
| `src/services/appleMailManager.test.ts` | New file: unit tests for `saveAttachment()` path validation |
| `src/utils/applescript.test.ts` | New test cases for debug log redaction |
| `package.json` / `package-lock.json` | Dependency bumps |

---

## Task 1: Add Numeric Regex to Message ID Schemas

**Files:**
- Modify: `src/index.ts` — 11 message tool schemas
- Test: `src/index.test.ts` (new)

The constant `MESSAGE_ID_SCHEMA` will be defined once and reused. This is DRY — 11 tools share the same constraint.

- [ ] **Step 1: Write the failing tests**

Create `src/index.test.ts`:

```typescript
/**
 * Tests for MCP tool input schema validation.
 * These tests import Zod schemas directly to verify validation rules
 * without needing a running MCP server.
 */
import { describe, it, expect } from "vitest";
import { z } from "zod";

// Re-export the schema constant for testing once it's added to index.ts
// For now, define the expected schema shape here to write tests first.
const MESSAGE_ID_SCHEMA = z.string().regex(/^\d+$/, "Message ID must be numeric");
const TEMPLATE_ID_SCHEMA = z.string().min(1, "Template ID is required");

describe("MESSAGE_ID_SCHEMA", () => {
  it("accepts a valid numeric ID", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("12345")).not.toThrow();
  });

  it("rejects an alphabetic string", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("abc")).toThrow("Message ID must be numeric");
  });

  it("rejects an injection payload", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("0 or true")).toThrow("Message ID must be numeric");
  });

  it("rejects an empty string", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("")).toThrow();
  });

  it("rejects a float", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("1.5")).toThrow("Message ID must be numeric");
  });
});

describe("TEMPLATE_ID_SCHEMA (regression: must NOT use numeric regex)", () => {
  it("accepts a tmpl_ prefixed ID", () => {
    expect(() => TEMPLATE_ID_SCHEMA.parse("tmpl_1")).not.toThrow();
  });

  it("accepts tmpl_42", () => {
    expect(() => TEMPLATE_ID_SCHEMA.parse("tmpl_42")).not.toThrow();
  });
});
```

- [ ] **Step 2: Run tests to verify they pass (they test the schema constants, not index.ts yet)**

```bash
npm test -- src/index.test.ts
```

Expected: PASS (the test file defines its own schemas for now)

- [ ] **Step 3: Add `MESSAGE_ID_SCHEMA` constant and apply it to all 11 message tools in `src/index.ts`**

Near the top of `src/index.ts`, after the imports, add:

```typescript
// Shared schema for Apple Mail message IDs (always numeric integers).
// Do NOT use this for template IDs — those use the "tmpl_N" format.
const MESSAGE_ID_SCHEMA = z.string().regex(/^\d+$/, "Message ID must be numeric");
```

Then replace each `z.string().min(1, "Message ID is required")` for the following tools with `MESSAGE_ID_SCHEMA`:

- `get-message` (line ~135): `id: MESSAGE_ID_SCHEMA`
- `reply-to-message` (line ~298): `id: MESSAGE_ID_SCHEMA`
- `forward-message` (line ~319): `id: MESSAGE_ID_SCHEMA`
- `mark-as-read` (line ~342): `id: MESSAGE_ID_SCHEMA`
- `mark-as-unread` (line ~360): `id: MESSAGE_ID_SCHEMA`
- `flag-message` (line ~378): `id: MESSAGE_ID_SCHEMA`
- `unflag-message` (line ~396): `id: MESSAGE_ID_SCHEMA`
- `delete-message` (line ~414): `id: MESSAGE_ID_SCHEMA`
- `move-message` (line ~432): `id: MESSAGE_ID_SCHEMA`
- `list-attachments` (line ~588): `id: MESSAGE_ID_SCHEMA`
- `save-attachment` (line ~613): `id: MESSAGE_ID_SCHEMA`

**Do NOT change** `get-template` (~884), `delete-template` (~912), or `use-template` (~930) — those use template IDs.

- [ ] **Step 4: Update the test to import from index.ts**

Update `src/index.test.ts` — replace the local schema definitions with an exported import. First, export the constant from `src/index.ts` by changing it to:

```typescript
export const MESSAGE_ID_SCHEMA = z.string().regex(/^\d+$/, "Message ID must be numeric");
```

Then update `src/index.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { z } from "zod";
import { MESSAGE_ID_SCHEMA } from "./index.js";

const TEMPLATE_ID_SCHEMA = z.string().min(1, "Template ID is required");

describe("MESSAGE_ID_SCHEMA", () => {
  it("accepts a valid numeric ID", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("12345")).not.toThrow();
  });

  it("rejects an alphabetic string", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("abc")).toThrow("Message ID must be numeric");
  });

  it("rejects an injection payload", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("0 or true")).toThrow("Message ID must be numeric");
  });

  it("rejects an empty string", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("")).toThrow();
  });

  it("rejects a float", () => {
    expect(() => MESSAGE_ID_SCHEMA.parse("1.5")).toThrow("Message ID must be numeric");
  });
});

describe("TEMPLATE_ID_SCHEMA (regression: must NOT use numeric regex)", () => {
  it("accepts a tmpl_ prefixed ID", () => {
    expect(() => TEMPLATE_ID_SCHEMA.parse("tmpl_1")).not.toThrow();
  });
});
```

- [ ] **Step 5: Run all tests**

```bash
npm test
```

Expected: All pass. No regressions.

- [ ] **Step 6: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "fix: add numeric regex validation to message ID schemas (prevent AppleScript injection)"
```

---

## Task 2: Add Date String Allowlist Validation

**Files:**
- Modify: `src/index.ts` — `search-messages` schema
- Modify: `src/services/appleMailManager.ts` — date interpolation lines ~381-388
- Test: `src/index.test.ts` (extend)

- [ ] **Step 1: Write the failing tests**

Add to `src/index.test.ts`. Note: at this point `./index.js` is already imported. Update the existing import line to also include `DATE_FILTER_SCHEMA`:

```typescript
import { MESSAGE_ID_SCHEMA, DATE_FILTER_SCHEMA } from "./index.js";
```

Then add the new describe block:

```typescript
describe("DATE_FILTER_SCHEMA", () => {
  it("accepts a valid AppleScript date string", () => {
    expect(() => DATE_FILTER_SCHEMA.parse("January 1, 2026")).not.toThrow();
  });

  it("accepts a date with time", () => {
    expect(() => DATE_FILTER_SCHEMA.parse("March 21, 2026 09:00:00")).not.toThrow();
  });

  it("rejects an injection payload", () => {
    expect(() => DATE_FILTER_SCHEMA.parse('" & (do shell script "id") & "')).toThrow("Invalid date format");
  });

  it("rejects a string with quotes", () => {
    expect(() => DATE_FILTER_SCHEMA.parse('"quoted"')).toThrow("Invalid date format");
  });

  it("accepts undefined (field is optional)", () => {
    expect(() => DATE_FILTER_SCHEMA.optional().parse(undefined)).not.toThrow();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- src/index.test.ts
```

Expected: FAIL — `DATE_FILTER_SCHEMA` not exported yet.

- [ ] **Step 3: Add `DATE_FILTER_SCHEMA` and apply it in `src/index.ts`**

After `MESSAGE_ID_SCHEMA`, add:

```typescript
// Allowlist for date filter strings passed to AppleScript's `date "..."` literal.
// Permits only alphanumeric, spaces, commas, colons, and forward slashes —
// the characters used by AppleScript date formats like "January 1, 2026 09:00:00".
export const DATE_FILTER_SCHEMA = z
  .string()
  .regex(/^[A-Za-z0-9 ,:/]+$/, "Invalid date format — use formats like 'January 1, 2026'");
```

Then in the `search-messages` tool schema (~lines 108-109), change:

```typescript
dateFrom: z.string().optional().describe("Start date filter (e.g., 'January 1, 2026')"),
dateTo: z.string().optional().describe("End date filter (e.g., 'March 1, 2026')"),
```

to:

```typescript
dateFrom: DATE_FILTER_SCHEMA.optional().describe("Start date filter (e.g., 'January 1, 2026')"),
dateTo: DATE_FILTER_SCHEMA.optional().describe("End date filter (e.g., 'March 1, 2026')"),
```

- [ ] **Step 4: Add `escapeForAppleScript()` at the interpolation site in `appleMailManager.ts`**

In `src/services/appleMailManager.ts`, change lines ~381-386 from:

```typescript
if (dateFrom) {
  dateChecks.push(`date received of msg >= date "${dateFrom}"`);
}
if (dateTo) {
  dateChecks.push(`date received of msg <= date "${dateTo}"`);
}
```

to:

```typescript
if (dateFrom) {
  dateChecks.push(`date received of msg >= date "${escapeForAppleScript(dateFrom)}"`);
}
if (dateTo) {
  dateChecks.push(`date received of msg <= date "${escapeForAppleScript(dateTo)}"`);
}
```

- [ ] **Step 5: Run all tests**

```bash
npm test
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/index.ts src/index.test.ts src/services/appleMailManager.ts
git commit -m "fix: add allowlist validation for date filter parameters (prevent AppleScript injection)"
```

---

## Task 3: Add Path Validation to `saveAttachment()`

**Files:**
- Modify: `src/services/appleMailManager.ts` — `saveAttachment()` method
- Test: `src/services/appleMailManager.test.ts` (new)

- [ ] **Step 1: Write the failing tests**

Create `src/services/appleMailManager.test.ts`:

```typescript
/**
 * Tests for AppleMailManager service layer.
 * Focuses on input validation that does not require a live Mail.app.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AppleMailManager } from "./appleMailManager.js";
import * as applescript from "@/utils/applescript.js";
import * as os from "os";

// Mock AppleScript execution so tests don't require Mail.app
vi.mock("@/utils/applescript.js", () => ({
  executeAppleScript: vi.fn(),
}));

const mockExecuteAppleScript = vi.mocked(applescript.executeAppleScript);

describe("AppleMailManager.saveAttachment() — path validation", () => {
  let manager: AppleMailManager;

  beforeEach(() => {
    vi.clearAllMocks();
    manager = new AppleMailManager();
  });

  it("rejects a relative savePath", () => {
    const result = manager.saveAttachment("12345", "report.pdf", "relative/path");
    expect(result).toBe(false);
    expect(mockExecuteAppleScript).not.toHaveBeenCalled();
  });

  it("rejects a savePath outside allowed prefixes (e.g. /etc)", () => {
    const result = manager.saveAttachment("12345", "sudoers", "/etc");
    expect(result).toBe(false);
    expect(mockExecuteAppleScript).not.toHaveBeenCalled();
  });

  it("rejects a savePath of /usr/bin", () => {
    const result = manager.saveAttachment("12345", "file.txt", "/usr/bin");
    expect(result).toBe(false);
    expect(mockExecuteAppleScript).not.toHaveBeenCalled();
  });

  it("accepts a savePath within home directory", () => {
    mockExecuteAppleScript.mockReturnValue({ success: true, output: "ok" });
    const homePath = os.homedir() + "/Downloads";
    const result = manager.saveAttachment("12345", "report.pdf", homePath);
    expect(result).toBe(true);
    expect(mockExecuteAppleScript).toHaveBeenCalled();
  });

  it("accepts /tmp as savePath", () => {
    mockExecuteAppleScript.mockReturnValue({ success: true, output: "ok" });
    const result = manager.saveAttachment("12345", "report.pdf", "/tmp");
    expect(result).toBe(true);
    expect(mockExecuteAppleScript).toHaveBeenCalled();
  });

  it("accepts /Volumes/ExternalDrive as savePath", () => {
    mockExecuteAppleScript.mockReturnValue({ success: true, output: "ok" });
    const result = manager.saveAttachment("12345", "report.pdf", "/Volumes/ExternalDrive");
    expect(result).toBe(true);
    expect(mockExecuteAppleScript).toHaveBeenCalled();
  });

  it("rejects an attachmentName with a path separator", () => {
    const result = manager.saveAttachment("12345", "../../../etc/passwd", os.homedir());
    expect(result).toBe(false);
    expect(mockExecuteAppleScript).not.toHaveBeenCalled();
  });

  it("rejects an attachmentName containing a slash", () => {
    const result = manager.saveAttachment("12345", "sub/dir/file.pdf", os.homedir());
    expect(result).toBe(false);
    expect(mockExecuteAppleScript).not.toHaveBeenCalled();
  });

  it("rejects an attachmentName with a null byte", () => {
    const result = manager.saveAttachment("12345", "file\0.pdf", os.homedir());
    expect(result).toBe(false);
    expect(mockExecuteAppleScript).not.toHaveBeenCalled();
  });

  it("accepts a normal attachmentName", () => {
    mockExecuteAppleScript.mockReturnValue({ success: true, output: "ok" });
    const result = manager.saveAttachment("12345", "report.pdf", os.homedir() + "/Downloads");
    expect(result).toBe(true);
    expect(mockExecuteAppleScript).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- src/services/appleMailManager.test.ts
```

Expected: Most FAIL — no path validation in `saveAttachment()` yet.

- [ ] **Step 3: Add path validation to `saveAttachment()` in `appleMailManager.ts`**

First, add `homedir` to the imports at the top of the file. Find the existing `import { isAbsolute } from "path";` line and change it to:

```typescript
import { isAbsolute } from "path";
import { homedir } from "os";
```

Then at the start of `saveAttachment()` (before `const safeName = ...`), add:

```typescript
saveAttachment(id: string, attachmentName: string, savePath: string): boolean {
  // Validate attachmentName: must not contain path traversal characters or null bytes
  if (attachmentName.includes("/") || attachmentName.includes("..") || attachmentName.includes("\0")) {
    console.error(`Invalid attachment name: "${attachmentName}"`);
    return false;
  }

  // Validate savePath: must be absolute and within an allowed directory prefix
  const ALLOWED_PREFIXES = [homedir(), "/tmp", "/private/tmp", "/Volumes"];
  if (!isAbsolute(savePath) || !ALLOWED_PREFIXES.some((prefix) => savePath.startsWith(prefix))) {
    console.error(`Save path "${savePath}" is not within an allowed directory`);
    return false;
  }

  const safeName = escapeForAppleScript(attachmentName);
  const safePath = escapeForAppleScript(savePath); // keep this existing line
  // ... rest of existing saveAttachment() body unchanged from line 1254 onward
```

- [ ] **Step 4: Run all tests**

```bash
npm test
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add src/services/appleMailManager.ts src/services/appleMailManager.test.ts
git commit -m "fix: add path traversal validation to saveAttachment()"
```

---

## Task 4: Cap Batch Operation Array Size

**Files:**
- Modify: `src/index.ts` — 6 batch tool schemas
- Test: `src/index.test.ts` (extend)

- [ ] **Step 1: Write the failing tests**

Add to `src/index.test.ts`:

```typescript
describe("Batch operation ids array — max 100 cap", () => {
  // The schema is defined inline in index.ts; test by constructing the same shape
  const BATCH_IDS_SCHEMA = z
    .array(z.string().regex(/^\d+$/, "Message ID must be numeric"))
    .min(1, "At least one message ID is required")
    .max(100, "Cannot process more than 100 messages at once");

  it("accepts an array of 1 ID", () => {
    expect(() => BATCH_IDS_SCHEMA.parse(["1"])).not.toThrow();
  });

  it("accepts an array of 100 IDs", () => {
    const ids = Array.from({ length: 100 }, (_, i) => String(i + 1));
    expect(() => BATCH_IDS_SCHEMA.parse(ids)).not.toThrow();
  });

  it("rejects an array of 101 IDs", () => {
    const ids = Array.from({ length: 101 }, (_, i) => String(i + 1));
    expect(() => BATCH_IDS_SCHEMA.parse(ids)).toThrow("Cannot process more than 100 messages at once");
  });

  it("rejects an empty array", () => {
    expect(() => BATCH_IDS_SCHEMA.parse([])).toThrow();
  });

  it("rejects non-numeric IDs within array", () => {
    expect(() => BATCH_IDS_SCHEMA.parse(["abc"])).toThrow("Message ID must be numeric");
  });
});
```

- [ ] **Step 2: Run tests to verify they pass (using local schema)**

```bash
npm test -- src/index.test.ts
```

Expected: PASS (tests use local schema constant, not index.ts yet)

- [ ] **Step 3: Export `BATCH_IDS_SCHEMA` and apply it to all 6 batch schemas in `src/index.ts`**

Add this exported constant alongside `MESSAGE_ID_SCHEMA` and `DATE_FILTER_SCHEMA`:

```typescript
export const BATCH_IDS_SCHEMA = z
  .array(MESSAGE_ID_SCHEMA)
  .min(1, "At least one message ID is required")
  .max(100, "Cannot process more than 100 messages at once");
```

Then update Task 4's test in `src/index.test.ts` — add `BATCH_IDS_SCHEMA` to the import line:

```typescript
import { MESSAGE_ID_SCHEMA, DATE_FILTER_SCHEMA, BATCH_IDS_SCHEMA } from "./index.js";
```

And replace the local `BATCH_IDS_SCHEMA` constant in the test with the imported one (remove the `const BATCH_IDS_SCHEMA = z.array(...)` line inside the describe block).

Then for each of the 6 batch tools, change `ids: z.array(z.string()).min(1, "...")` to:

```typescript
ids: BATCH_IDS_SCHEMA,
```

Apply this change to:
- `batch-delete-messages` (~line 452)
- `batch-move-messages` (~line 474)
- `batch-mark-as-read` (~line 500)
- `batch-mark-as-unread` (~line 522)
- `batch-flag-messages` (~line 544)
- `batch-unflag-messages` (~line 566)

- [ ] **Step 4: Run all tests**

```bash
npm test
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "fix: cap batch operation arrays at 100 messages and require numeric IDs"
```

---

## Task 5: Redact PII from Debug Logs

**Files:**
- Modify: `src/utils/applescript.ts` — `executeAppleScript()` debug log
- Test: `src/utils/applescript.test.ts` (extend)

- [ ] **Step 1: Write the failing tests**

Add a new describe block to `src/utils/applescript.test.ts`:

```typescript
describe("debug log redaction", () => {
  it("redacts double-quoted strings from the script preview", () => {
    // We test by checking what gets passed to console.error in debug mode.
    // Set DEBUG=1, capture console.error, then verify quoted content is hidden.
    const originalDebug = process.env.DEBUG;
    process.env.DEBUG = "1";

    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    mockExecSync.mockReturnValue("output");

    const scriptWithPII = `tell application "Mail" to send message to "alice@example.com" with subject "Secret Project"`;
    executeAppleScript(scriptWithPII);

    // Find the log call that contains scriptPreview
    const previewCall = consoleSpy.mock.calls.find(
      (call) => typeof call[1] === "object" && call[1] !== null && "scriptPreview" in (call[1] as object)
    );

    expect(previewCall).toBeDefined();
    const preview = (previewCall![1] as { scriptPreview: string }).scriptPreview;

    // PII should be redacted
    expect(preview).not.toContain("alice@example.com");
    expect(preview).not.toContain("Secret Project");
    // Structure keywords should still be visible
    expect(preview).toContain("tell application");
    expect(preview).toContain("[...]");

    // Restore
    consoleSpy.mockRestore();
    if (originalDebug === undefined) {
      delete process.env.DEBUG;
    } else {
      process.env.DEBUG = originalDebug;
    }
  });

  it("does not redact when string content is absent", () => {
    const originalDebug = process.env.DEBUG;
    process.env.DEBUG = "1";
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    mockExecSync.mockReturnValue("output");

    const scriptNoStrings = `tell application Mail\nget messages of inbox\nend tell`;
    executeAppleScript(scriptNoStrings);

    const previewCall = consoleSpy.mock.calls.find(
      (call) => typeof call[1] === "object" && call[1] !== null && "scriptPreview" in (call[1] as object)
    );
    expect(previewCall).toBeDefined();
    const preview = (previewCall![1] as { scriptPreview: string }).scriptPreview;

    // No [...]  replacement when no quoted strings
    expect(preview).not.toContain("[...]");
    expect(preview).toContain("tell application");

    consoleSpy.mockRestore();
    if (originalDebug === undefined) {
      delete process.env.DEBUG;
    } else {
      process.env.DEBUG = originalDebug;
    }
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
npm test -- src/utils/applescript.test.ts
```

Expected: FAIL — no redaction in debug log yet.

- [ ] **Step 3: Add redaction to `applescript.ts`**

In `src/utils/applescript.ts`, find the `debugLog` call around line 305:

```typescript
debugLog("Executing AppleScript", {
  scriptPreview: script.trim().substring(0, 200) + (script.length > 200 ? "..." : ""),
  timeout: timeoutMs,
  maxRetries,
});
```

Replace with:

```typescript
const redactedScript = script.trim().replace(/"[^"\n]+"/g, '"[...]"');
debugLog("Executing AppleScript", {
  scriptPreview: redactedScript.substring(0, 200) + (redactedScript.length > 200 ? "..." : ""),
  timeout: timeoutMs,
  maxRetries,
});
```

- [ ] **Step 4: Run all tests**

```bash
npm test
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add src/utils/applescript.ts src/utils/applescript.test.ts
git commit -m "fix: redact quoted string content from debug log previews to prevent PII leakage"
```

---

## Task 6: Bump Dependencies

**Files:**
- Modify: `package.json`, `package-lock.json`

- [ ] **Step 1: Update all packages within semver ranges**

```bash
npm update
```

- [ ] **Step 2: Check for out-of-range updates**

```bash
npm outdated
```

Review the output. For any package with a newer major/minor version available:
- `@modelcontextprotocol/sdk`: update manually if a newer version exists (`npm install @modelcontextprotocol/sdk@latest`)
- `@types/node`: update manually if a newer version exists (`npm install --save-dev @types/node@latest`)
- For other packages with major version bumps, review the changelog before updating

- [ ] **Step 3: Run tests to verify nothing broke**

```bash
npm test
```

Expected: All pass.

- [ ] **Step 4: Run the build to verify TypeScript compatibility**

```bash
npm run build
```

Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: bump dependencies"
```

---

## Task 7: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
npm test
```

Expected: All pass.

- [ ] **Step 2: Run typecheck**

```bash
npm run typecheck
```

Expected: No errors.

- [ ] **Step 3: Run lint**

```bash
npm run lint
```

Expected: No errors.

- [ ] **Step 4: Run build**

```bash
npm run build
```

Expected: Clean build output in `build/`.
