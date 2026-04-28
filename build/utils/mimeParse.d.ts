/**
 * MIME Source Parser for Attachment Extraction
 *
 * Parses raw email MIME source to extract attachment metadata and content.
 * Used as a fallback when AppleScript's `mail attachments` returns empty
 * (which happens across all account types: iCloud, Google, Exchange).
 *
 * @module utils/mimeParse
 */
export interface MimeAttachmentInfo {
    /** Filename from Content-Disposition or Content-Type name parameter */
    name: string;
    /** MIME type from Content-Type header */
    mimeType: string;
    /** Size in bytes from Content-Disposition size parameter, or estimated from body */
    size: number;
}
export interface MimeAttachmentData extends MimeAttachmentInfo {
    /** Decoded binary content */
    data: Buffer;
}
/**
 * Parse MIME source and return metadata for all file attachments.
 * Skips inline dispositions (signature images, etc.). Descends into
 * nested multipart/* containers.
 *
 * @param source - Raw MIME source of the email
 * @returns Array of attachment metadata (name, mimeType, size)
 */
export declare function parseMimeAttachments(source: string): MimeAttachmentInfo[];
/**
 * Extract and decode a specific attachment from MIME source by filename.
 * Supports base64, quoted-printable, and 7bit/8bit/binary transfer encodings.
 * Descends into nested multipart/* containers.
 *
 * @param source - Raw MIME source of the email
 * @param attachmentName - Filename to extract
 * @returns Decoded attachment data, or null if not found
 */
export declare function extractMimeAttachment(source: string, attachmentName: string): MimeAttachmentData | null;
//# sourceMappingURL=mimeParse.d.ts.map