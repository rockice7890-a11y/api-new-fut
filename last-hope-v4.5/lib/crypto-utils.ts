import crypto from "crypto"

export function generateCSRFToken(): string {
  return crypto.randomBytes(32).toString("hex")
}

export function verifyCSRFToken(token: string, storedToken: string): boolean {
  try {
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(storedToken))
  } catch {
    return false
  }
}

export function hashEmail(email: string): string {
  return crypto.createHash("sha256").update(email.toLowerCase()).digest("hex")
}

export function generateRandomToken(): string {
  return crypto.randomBytes(16).toString("hex")
}
