/**
 * AES-256-GCM encryption for sensitive connection settings (passwords).
 * Uses JWT_SECRET as the encryption key derivation source.
 * Never logs or exposes decrypted values.
 */

import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

function getEncryptionKey(): Buffer {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is required for encryption");
  // Derive a 32-byte key from JWT_SECRET using SHA-256
  return crypto.createHash("sha256").update(secret).digest();
}

/**
 * Encrypt a plaintext string.
 * Returns a base64 string: iv:ciphertext:authTag
 */
export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  const authTag = cipher.getAuthTag();
  
  // Format: iv:ciphertext:authTag (all base64)
  return `${iv.toString("base64")}:${encrypted}:${authTag.toString("base64")}`;
}

/**
 * Decrypt a previously encrypted string.
 * Input format: iv:ciphertext:authTag (all base64)
 */
export function decrypt(encryptedText: string): string {
  const key = getEncryptionKey();
  const parts = encryptedText.split(":");
  
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted format");
  }
  
  const iv = Buffer.from(parts[0], "base64");
  const ciphertext = parts[1];
  const authTag = Buffer.from(parts[2], "base64");
  
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");
  
  return decrypted;
}
