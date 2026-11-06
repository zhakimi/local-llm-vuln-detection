import { createHash } from "crypto";

export function hashPassword(password: string): string {
  return createHash("md5").update(password).digest("hex");
}

export function newSessionId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
