# Security Fixes Design — apple-mail-mcp

**Date:** 2026-03-21
**Scope:** Minimal targeted fixes for 5 of 6 audit findings; Issue 5 (execSync→spawnSync refactor) deferred.

---

## Issues and Fixes

### Issue 1 — AppleScript Injection via Message ID (Critical)

**Problem:** The `id` parameter is validated only as `z.string().min(1)`. It is interpolated bare into AppleScript (`whose id is ${id}`), enabling injection of arbitrary AppleScript/shell commands.

**Fix:** Add `.regex(/^\d+$/, "Message ID must be numeric")` to the `id` field in these **message operation** tool schemas in `src/index.ts`:
- `get-message` (line ~135)
- `mark-as-read`, `mark-as-unread`, `flag-message`, `unflag-message`
- `reply-to-message`, `forward-message`
- `delete-message`, `move-message`
- `list-attachments`, `save-attachment`

Also update the `ids` array element in all 6 batch schemas to `z.array(z.string().regex(/^\d+$/, "Message ID must be numeric"))`.

**Do NOT apply** the numeric regex to template `id` fields (`save-template`, `get-template`, `delete-template`, `use-template`). Template IDs have the format `tmpl_<number>` (e.g. `tmpl_1`) and are not interpolated into AppleScript.

**Files:** `src/index.ts`

---

### Issue 2 — AppleScript Injection via `dateFrom`/`dateTo` (Critical)

**Problem:** Date strings are interpolated directly into `date "..."` AppleScript literals without escaping or format validation. `escapeForAppleScript()` alone is insufficient — it only escapes backslashes and double-quotes but does not prevent injection via newlines or AppleScript comment syntax.

**Fix (two-layer):**
1. **Primary (schema layer):** Add a Zod regex to `dateFrom` and `dateTo` in `src/index.ts`: `.regex(/^[A-Za-z0-9 ,:/]+$/, "Invalid date format")`. This allowlist permits only alphanumeric, spaces, commas, colons, and slashes — the characters used by AppleScript date literals — and rejects all injection attempts.
2. **Secondary (service layer):** Also apply `escapeForAppleScript()` to both values at the interpolation site in `appleMailManager.ts` lines 381–388 as defense-in-depth.

**Files:** `src/index.ts` (schema), `src/services/appleMailManager.ts` (interpolation)

---

### Issue 3 — Path Traversal in `save-attachment` (High)

**Problem:** `savePath` and `attachmentName` have no boundary checks. A caller could write files to arbitrary locations.

**Fix:** At the start of `saveAttachment()` in `appleMailManager.ts`, validate:
- `savePath` is absolute (`path.isAbsolute`) and starts with one of: `os.homedir()`, `/tmp`, `/private/tmp`, or `/Volumes`. Return `false` with a console error if outside these prefixes.
- `attachmentName` does not contain `/`, `..`, or null bytes (`\0`). Return `false` with a console error if invalid.

The homedir-only restriction from the initial design is too narrow for legitimate use cases (e.g. saving to `/tmp` for processing, or to `/Volumes` for external drives). The expanded allowlist covers real use cases while still blocking writes to `/etc`, `/usr`, `/System`, etc.

**Files:** `src/services/appleMailManager.ts`

---

### Issue 4 — Unbounded Batch Operation Arrays (High)

**Problem:** All 6 batch operation schemas define only `.min(1)` with no upper bound, enabling DoS via thousands of AppleScript calls.

**Fix:** Add `.max(100, "Cannot process more than 100 messages at once")` to the `ids` array in all 6 batch tool schemas in `src/index.ts`. Cap is aligned with `send-serial-email`'s 100-recipient limit for consistency. (100 sequential full-mailbox-scan AppleScript calls is already expensive; 500 would create unacceptable latency.)

**Files:** `src/index.ts`

---

### Issue 6 — PII Leakage in Debug Logs (Medium)

**Problem:** When `DEBUG=1`/`VERBOSE=1`, the first 200 chars of every AppleScript script are logged to stderr, which can include recipient addresses, email subjects, and body content embedded as AppleScript string literals.

**Fix:** In `applescript.ts`, before building `scriptPreview`, redact the full script string by replacing all AppleScript double-quoted string values with `"[...]"`:

```typescript
const redactedScript = script.trim().replace(/"[^"\n]+"/g, '"[...]"');
const scriptPreview = redactedScript.substring(0, 200) + (redactedScript.length > 200 ? "..." : "");
```

The pattern `/"[^"\n]+"/g` matches any non-empty double-quoted string (excluding newlines, which don't appear inside AppleScript string literals). This will also redact non-PII values like mailbox names — that trade-off is acceptable since the debug log still shows script structure and AppleScript keywords, which is sufficient for diagnosing execution issues.

**Files:** `src/utils/applescript.ts`

---

### Dependency Bumps

Run `npm update` to update all packages within existing semver ranges, then check for newer major/minor versions of `@modelcontextprotocol/sdk` and `@types/node` and update manually if available.

---

## Testing

All new tests use Vitest (existing test runner). Test file locations:

| Fix | Test file |
|-----|-----------|
| Issue 1 — Message ID regex | `src/index.test.ts` (new file; tests Zod schema validation) |
| Issue 2 — Date string validation | `src/index.test.ts` (same new file) |
| Issue 3 — Path traversal | `src/services/appleMailManager.test.ts` (new file, test `saveAttachment` validation) |
| Issue 4 — Batch cap | `src/index.test.ts` (same new file) |
| Issue 6 — Debug log redaction | `src/utils/applescript.test.ts` (existing file, new test cases) |

Key test cases:
- Non-numeric ID (`"abc"`, `"1 or true"`) rejected by schema
- Numeric ID (`"12345"`) accepted
- Template IDs (`"tmpl_1"`) still accepted by template schemas (regression guard)
- Date with injection payload rejected by Zod regex
- Valid date string accepted
- `saveAttachment` rejects relative `savePath`, path outside allowed prefixes, and `attachmentName` with `/` or `..` or null byte
- Batch `ids` array of 101 items rejected; 100 accepted
- Debug log redaction replaces quoted strings with `[...]`

---

## Out of Scope

- Issue 5 (execSync → spawnSync): deferred.
- No new source files (test files are new, source files are not).
- No refactoring beyond what is required for the fixes.
