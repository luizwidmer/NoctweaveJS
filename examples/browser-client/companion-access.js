import { randomBytes, timingSafeEqual } from "node:crypto";

const accessTokenPattern = /^[0-9a-f]{64}$/u;

// Never write a bearer token to app-owned storage. Service managers should
// inject a random token; an interactive run can reveal a fresh process token.
export function createCompanionAccessToken({
  suppliedToken = process.env.NOCTWEAVE_GROUP_COMPANION_TOKEN,
  interactive = Boolean(process.stdout.isTTY)
} = {}) {
  if (suppliedToken !== undefined) {
    if (!accessTokenPattern.test(suppliedToken)) {
      throw new Error("NOCTWEAVE_GROUP_COMPANION_TOKEN must contain 64 lowercase hex characters.");
    }
    return { token: suppliedToken, reveal: false };
  }
  if (!interactive) {
    throw new Error("Non-interactive group companion startup requires NOCTWEAVE_GROUP_COMPANION_TOKEN.");
  }
  return { token: randomBytes(32).toString("hex"), reveal: true };
}

export function hasCompanionAccess(request, token) {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) return false;
  const presented = authorization.slice("Bearer ".length);
  if (!accessTokenPattern.test(presented)) return false;
  return timingSafeEqual(Buffer.from(presented, "ascii"), Buffer.from(token, "ascii"));
}
