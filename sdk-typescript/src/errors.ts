/**
 * Structured error hierarchy. Every error thrown by the SDK derives from {@link AlesError}.
 * Enforcement code should treat any AlesError as "do not serve the protected object" (fail closed).
 *
 *   AlesError
 *   |- ConfigError
 *   |- InvalidRequestError
 *   |  `- RequestTooLargeError
 *   |- AlesConnectionError
 *   |  `- AlesTimeoutError
 *   |- AlesHTTPError
 *   |  |- AuthError              401 / 403
 *   |  |  `- TenantMismatchError 403 because the token's tenant differs from ours
 *   |  `- ServerUnavailableError 429 / 502 / 503 / 504 (retryable)
 *   |- ResponseError
 *   |- SnapshotError
 *   `- SessionResetRequired
 */

import type { TaintVerdict } from "./sessionTaint.js";

export class AlesError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class ConfigError extends AlesError {}

export class InvalidRequestError extends AlesError {}

export class RequestTooLargeError extends InvalidRequestError {
  readonly size: number;
  readonly limit: number;
  constructor(size: number, limit: number) {
    super(`request body is ${String(size)} bytes; client-side limit is ${String(limit)} bytes`);
    this.size = size;
    this.limit = limit;
  }
}

export class AlesConnectionError extends AlesError {}

export class AlesTimeoutError extends AlesConnectionError {}

export class AlesHTTPError extends AlesError {
  readonly statusCode: number;
  readonly body: unknown;
  readonly url: string;
  constructor(statusCode: number, body: unknown, url = "", message?: string) {
    super(message ?? `HTTP ${String(statusCode)} from ${url}: ${JSON.stringify(body)}`);
    this.statusCode = statusCode;
    this.body = body;
    this.url = url;
  }

  /** Best-effort human-readable server detail. */
  get detail(): string {
    return httpDetail(this.body);
  }
}

export function httpDetail(body: unknown): string {
  if (body !== null && typeof body === "object" && !Array.isArray(body)) {
    const rec = body as Record<string, unknown>;
    for (const k of ["detail", "error", "message"]) {
      const v = rec[k];
      if (v !== undefined && v !== null) return typeof v === "string" ? v : JSON.stringify(v);
    }
  }
  return typeof body === "string" ? body : JSON.stringify(body);
}

/** 401/403: the bearer token is missing, invalid, expired or lacks the required role. */
export class AuthError extends AlesHTTPError {
  constructor(statusCode: number, body: unknown, url = "", message?: string) {
    super(
      statusCode,
      body,
      url,
      message ??
        `authentication/authorization failed (HTTP ${String(statusCode)}) at ${url}: ${httpDetail(body)}`,
    );
  }
}

/** 403 because the tenant the client claims is not the tenant bound to its token. Never retried. */
export class TenantMismatchError extends AuthError {
  readonly tenantId: string;
  constructor(statusCode: number, body: unknown, url: string, tenantId: string) {
    super(
      statusCode,
      body,
      url,
      `tenant mismatch: client is configured for tenant ${JSON.stringify(tenantId)} but the server rejected it ` +
        `(HTTP ${String(statusCode)}: ${httpDetail(body)}). The tenant is derived from the auth token; ` +
        "check that tenantId matches the token's tenant.",
    );
    this.tenantId = tenantId;
  }
}

/** 429/502/503/504: the service is temporarily unavailable or shedding load. */
export class ServerUnavailableError extends AlesHTTPError {}

/** The server answered 2xx but the body was malformed. */
export class ResponseError extends AlesError {}

export type SnapshotErrorReason =
  | "bad_format"
  | "missing_signature"
  | "unknown_key_id"
  | "bad_signature"
  | "tenant_mismatch"
  | "expired"
  | "epoch_regression";

/** A signed policy snapshot failed verification. `reason` is a stable machine-readable code. */
export class SnapshotError extends AlesError {
  readonly reason: SnapshotErrorReason;
  constructor(reason: SnapshotErrorReason, message = "") {
    super(`policy snapshot rejected (${reason})${message ? ": " + message : ""}`);
    this.reason = reason;
  }
}

/** The session consumed context that is no longer allowed; discard its state before continuing. */
export class SessionResetRequired extends AlesError {
  readonly verdict: TaintVerdict;
  constructor(verdict: TaintVerdict) {
    const ids = [...verdict.revoked.map((v) => v.contextId), ...verdict.unverifiable];
    super(`session ${JSON.stringify(verdict.sessionId)} must be reset; affected contexts: ${JSON.stringify(ids)}`);
    this.verdict = verdict;
  }
}
