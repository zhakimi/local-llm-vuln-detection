import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const key = scryptSync(password, salt, 64);
  return `${salt.toString("hex")}:${key.toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [saltHex, keyHex] = stored.split(":");
  const key = scryptSync(password, Buffer.from(saltHex, "hex"), 64);
  return timingSafeEqual(key, Buffer.from(keyHex, "hex"));
}

export function newSessionId(): string {
  return randomBytes(32).toString("hex");
}
