export {
  AuthorizeResult,
  DEFAULT_TIMEOUT_MS,
  InvariantClient,
  MAX_REQUEST_BYTES,
  RETRYABLE_STATUS,
  type AuthorizeOptions,
  type ContextEnvelope,
  type InvariantClientOptions,
  type JsonObject,
  type ObjectRef,
  type ObjectVerdict,
  type ParentRef,
  type Principal,
  type RevocationEvent,
} from "./client.js";
export {
  DecisionCache,
  DEFAULT_MAX_CLOCK_SKEW,
  DEFAULT_MAX_TTL,
  makeKey,
  type CacheKey,
  type Clock,
  type DecisionCacheOptions,
} from "./decisionCache.js";
export {
  AlesConnectionError,
  AlesError,
  AlesHTTPError,
  AlesTimeoutError,
  AuthError,
  ConfigError,
  InvalidRequestError,
  RequestTooLargeError,
  ResponseError,
  ServerUnavailableError,
  SessionResetRequired,
  SnapshotError,
  TenantMismatchError,
  type SnapshotErrorReason,
} from "./errors.js";
export { FailMode, isProtected, parseFailMode, resolve, type EffectiveAction } from "./failModes.js";
export { canonicalBytes, canonicalize } from "./jcs.js";
export {
  ENFORCE_BATCH_SIZE,
  SessionTaint,
  enforce,
  type Exposure,
  type RecordOptions,
  type TaintVerdict,
} from "./sessionTaint.js";
export {
  SnapshotKeys,
  canonicalSnapshotBytes,
  parsePublicKey,
  snapshotDeadline,
  snapshotValidAt,
  verifySnapshot,
  type Snapshot,
  type SnapshotPublicKeySpec,
  type VerifySnapshotOptions,
} from "./snapshot.js";
