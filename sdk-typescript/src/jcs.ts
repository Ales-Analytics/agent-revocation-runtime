/**
 * RFC 8785 (JSON Canonicalization Scheme) serialisation.
 *
 * - Object members are sorted by UTF-16 code units of their (unescaped) names.
 * - Numbers use the ECMAScript Number-to-string algorithm (`String(n)`), which is exactly the rule
 *   RFC 8785 section 3.2.2.3 mandates. NaN/Infinity are rejected.
 * - Strings use `JSON.stringify` escaping, which matches RFC 8785 section 3.2.2.2: only `"`, `\`, and
 *   control characters < 0x20 are escaped (using \b \t \n \f \r or lowercase \u00xx); everything else,
 *   including non-ASCII, is emitted verbatim. (Lone surrogates are emitted as \udXXX escapes by modern
 *   JSON.stringify, which is the well-formed JSON.stringify behaviour.)
 * - No insignificant whitespace.
 */

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue | undefined };

function compareUtf16(a: string, b: string): number {
  // JS string comparison with < / > is by UTF-16 code unit, which is what RFC 8785 requires.
  return a < b ? -1 : a > b ? 1 : 0;
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite numbers are not permitted");
      // String(-0) is "0", which is what RFC 8785 specifies for negative zero.
      return String(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
      }
      const rec = value as Record<string, unknown>;
      const keys = Object.keys(rec)
        .filter((k) => rec[k] !== undefined)
        .sort(compareUtf16);
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(rec[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`JCS: cannot serialise value of type ${typeof value}`);
  }
}

export function canonicalBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(canonicalize(value));
}
