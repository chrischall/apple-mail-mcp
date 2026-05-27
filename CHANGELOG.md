# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.2] - 2026-05-27

### Fixed
- **`search-messages` silently ignored `from`, `subject`, `isRead`, `isFlagged` filters** — these four parameters were declared in the tool's input schema but the handler never forwarded them to `searchMessages()`, so callers (and LLM agents) reasonably assumed they worked while results came back unfiltered. The handler now passes all four through, and `searchMessages()` builds them into the AppleScript `whose` clause as AND filters. The existing `query` (subject-OR-sender) is parenthesized so precedence holds when combined. Clause-building logic is extracted to a pure `buildSearchCondition()` with 9 unit tests covering the `isRead:false` / `isFlagged:false` not-dropped regression, OR-grouping, and quote/backslash escaping. ([#13](https://github.com/sweetrb/apple-mail-mcp/pull/13) by @kevinmay-scoutsolutions)

### Changed
- **`search-messages` schema descriptions for `from` and `subject` clarify substring-match semantics** — `from` is a substring match against the full `Display Name <addr>` string (not an exact-address match), and `subject` is a substring match.

## [1.5.1] - 2026-04-28

### Fixed
- **Plugin install: `build/` not produced on marketplace install** — Claude Code installs path-source plugins by `git clone` only; it does not run `npm install`, so the `prepare` hook never fired and the cached plugin directory was missing `build/index.js`. The MCP server failed to start until the user manually ran `npm run build` inside the cached plugin dir. Build artifacts in `build/` are now committed to the repository so they are present immediately after marketplace clone. A pre-commit hook keeps `build/` in sync with `src/`, and CI fails if the committed `build/` is stale. ([#10](https://github.com/sweetrb/apple-mail-mcp/pull/10))
- **`.mcp.json` plugin entrypoint resolved against user cwd** — `args` referenced `build/index.js` as a relative path, so the MCP server only started when Claude Code was launched from inside a clone of this repo. Now uses `${CLAUDE_PLUGIN_ROOT}/build/index.js` so the path resolves against the plugin's install location. ([#10](https://github.com/sweetrb/apple-mail-mcp/pull/10) by @natekettles)

### Changed
- **`prepare` script no longer rebuilds.** It now runs `husky` only. Build artifacts are committed and kept current by the pre-commit hook; rebuilding on every `npm install` was producing churn in `git status` for daily development.

## [1.5.0] - 2026-04-20

### Fixed
- **Attachments invisible to AppleScript** — `list-attachments` and `save-attachment` returned empty across all account types (iCloud, Google, Exchange) when attachments were embedded as MIME parts in the message source (a known limitation of Mail.app's AppleScript bridge). Both tools now use a two-attempt pattern: AppleScript first, then fall back to parsing the raw MIME source of the message. Path-traversal protection is preserved on the fallback save path. ([#8](https://github.com/sweetrb/apple-mail-mcp/pull/8) by @kevinmay-scoutsolutions)
- **`hasAttachments` accuracy** — `get-message` now detects MIME-embedded attachments via raw source scan when AppleScript reports zero. `list-messages` uses the fast AppleScript count path only (may false-negative on MIME-embedded; use `get-message` or `list-attachments` for authoritative info).

### Added
- **Nested multipart support in MIME parser** — attachments nested inside `multipart/alternative` (text+html) or `multipart/related` (inline images) containers are now discovered by recursive descent.
- **Non-base64 transfer encoding decoding** — MIME fallback now supports `quoted-printable` and `7bit`/`8bit`/`binary` attachments in addition to base64.
- **New module `src/utils/mimeParse.ts`** — standalone MIME parser (zero dependencies) with 18 unit tests covering single/multi attachments, nested multipart, inline dispositions, and all supported transfer encodings.

## [1.4.0] - 2026-04-03

### Fixed
- **reply-to-message empty body from background processes** — Replies (and forwards) sent via the MCP server had empty body text because `reply msg with opening window` creates a GUI compose window that doesn't fully initialize from non-interactive processes. Switched to `without opening window`, which makes `set content` work immediately and reliably. `In-Reply-To` and `References` headers are still set correctly by Mail.app. ([#7](https://github.com/sweetrb/apple-mail-mcp/issues/7))
- **forward-message empty body from background processes** — Same root cause and fix as reply-to-message. `forward msg with opening window` → `without opening window`.
- **Removed no-op quoted content concatenation** — The old `& content of theReply` / `& content of theForward` appended to the body was always empty (the quoted content lives in Mail.app's HTML layer, not the plaintext `content` property). Removed the dead concatenation.

## [1.3.0] - 2026-04-01

### Changed
- **Search all mailboxes by default** - `search-messages` and `list-messages` now search across all mailboxes in an account when no mailbox is specified, instead of defaulting to INBOX. This dramatically improves results for Gmail accounts where messages live in labels rather than INBOX. Deduplication ensures each message appears only once.
- **Multi-account listing** - `list-messages` now iterates all accounts when no account is specified, matching the existing behavior of `search-messages`.

### Fixed
- **Date filter validation** - `dateFrom` and `dateTo` now reject non-parseable date strings (e.g., "31", "abc") with a clear error message instead of crashing AppleScript. The existing regex security filter is preserved; a semantic `.refine()` check is added on top.

## [1.2.1] - 2026-03-27

### Security
- **Message ID validation** - Message IDs are now validated as numeric-only (`/^\d+$/`) to prevent injection attacks
- **Batch size cap** - Batch operations are limited to a maximum of 100 messages per request
- **Date filter validation** - Date filters are validated to allow only alphanumeric characters and safe punctuation; an additional belt-and-suspenders `escapeForAppleScript()` call is applied before interpolation
- **Attachment save path traversal prevention** - `save-attachment` uses `path.resolve` and restricts save paths to the user's home directory, `/tmp`, `/private/tmp`, and `/Volumes`; attachment names containing `/`, `\`, null bytes, or `..` are rejected
- **Defense-in-depth ID coercion** - All AppleScript message ID interpolations now use `Number(id)` as an extra safeguard
- **Attachment count limit** - `send-email` and `create-draft` enforce a maximum of 20 file attachments

### Added
- **Security test suite** - `src/security.test.ts` with unit tests for all input validation schemas and path traversal prevention
- **Integration test suite** - `test/integration.test.ts` for live Mail.app testing
- **New npm scripts** - `test:integration` and `test:all` for running integration and combined test suites

## [1.2.0] - 2026-03-14

### Added
- **send-serial-email** - Mail merge tool: send personalized emails to multiple recipients with `{{placeholder}}` token support (max 100 recipients per batch) (PR #3 by @michaelhenze)
- **File attachments** - `send-email` and `create-draft` now accept an optional `attachments` parameter (array of absolute file paths) (PR #2 by @michaelhenze)

### Fixed
- **Locale-independent date parsing** - Dates now display correctly on non-English macOS systems (e.g., German). Previously, locale-dependent date strings could cause all emails to show the current date instead of actual received date (PR #4 by @michaelhenze)
- **Send/draft timeout resilience** - Increased timeout from 30s to 60s and enabled automatic retry with exponential backoff for `send-email` and `create-draft`, preventing failures when Mail.app is slow to establish SMTP connections

### Improved
- Attachment paths are validated (must be absolute, must exist) before sending — provides clear error messages instead of cryptic AppleScript failures
- `send-serial-email` uses `spawnSync("sleep")` instead of CPU-burning busy-wait between sends
- `send-serial-email` enforces safety limits: max 100 recipients, max 10s delay between sends

## [1.1.1] - 2026-03-10

### Fixed
- TTL cache for account and mailbox name resolution to reduce redundant AppleScript calls

## [1.1.0] - 2026-03-09

### Added
- **Batch operations** - `batch-mark-as-unread`, `batch-flag-messages`, `batch-unflag-messages`
- **Mailbox management** - `create-mailbox`, `delete-mailbox`, `rename-mailbox`
- **Mail rules** - `list-rules`, `enable-rule`, `disable-rule`
- **Contacts** - `search-contacts` (Contacts.app integration)
- **Email templates** - `save-template`, `list-template`, `get-template`, `delete-template`, `use-template`
- **save-attachment** - Download attachments to disk
- **HTML content** - `preferHtml` option in `get-message`
- Date received in search/list output
- Sender filter and pagination (`from`, `offset`) for `list-messages`
- Date range filtering (`dateFrom`, `dateTo`) for `search-messages`
- Cross-account search when no account specified
- Exposed `unflag-message` tool (was implemented but not wired up)

### Fixed
- Use Mail.app's configured default send account instead of hardcoded fallback (PR #1 by @Leewonchan14)
- Add message ID to search and list results (PR #1 by @Leewonchan14)

## [1.0.0] - 2026-01-06

First stable release with full Apple Mail integration.

### Features

#### Message Operations
- **search-messages** - Search messages by query, sender, subject with filtering options
- **list-messages** - List messages in any mailbox with pagination
- **get-message** - Retrieve full message content (subject, body, metadata)
- **send-email** - Send emails with To, CC, BCC recipients from any account
- **create-draft** - Save emails to Drafts folder without sending
- **reply-to-message** - Reply to messages with reply-all support, send or save as draft
- **forward-message** - Forward messages to new recipients with optional body
- **mark-as-read** / **mark-as-unread** - Toggle message read status
- **flag-message** / **unflag-message** - Toggle message flagged status
- **delete-message** - Move messages to Trash
- **move-message** - Organize messages into mailboxes

#### Mailbox Operations
- **list-mailboxes** - List all mailboxes/folders with unread counts
- **get-unread-count** - Get unread count for specific mailbox or all accounts

#### Account Operations
- **list-accounts** - List all configured Mail accounts

#### Diagnostics
- **health-check** - Verify Mail.app connectivity and permissions
- **get-mail-stats** - Get message and unread counts per account

### Technical
- Full AppleScript integration with proper escaping and error handling
- Retry logic with exponential backoff for transient failures
- User-friendly error messages with actionable suggestions
- Debug logging support (set DEBUG=1 or VERBOSE=1)
- 60-second timeout for message search operations
- Message ID lookup across all mailboxes for reliable operations

## [0.1.0] - 2026-01-06

Initial release - project skeleton.

### Added
- Initial project structure forked from apple-notes-mcp
- MCP server skeleton with tool definitions
- TypeScript types for Mail data models
- AppleScript utilities with error handling
