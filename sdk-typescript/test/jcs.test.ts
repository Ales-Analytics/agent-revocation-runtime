import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/jcs.js";

function fromBits(hex: string): number {
  const dv = new DataView(new ArrayBuffer(8));
  dv.setBigUint64(0, BigInt("0x" + hex));
  return dv.getFloat64(0);
}

describe("JCS (RFC 8785)", () => {
  it("canonicalizes the section 3.2.3 example", () => {
    // RFC input text for "string": "€$\u000F\u000aA'B"\\\\"\/"
    const BS = "\\";
    const input = {
      numbers: JSON.parse("[333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001]") as number[],
      string: "€$\u000F\u000aA'B\"" + BS + BS + '"/',
      literals: [null, true, false],
    };
    // RFC output: "string":"<euro>$\u000f\nA'B\"\\\\\"/"
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$' +
      BS + "u000f" + BS + "nA'B" + BS + '"' + BS + BS + BS + BS + BS + '"/"}';
    expect(canonicalize(input)).toBe(expected);
  });

  it("sorts members by UTF-16 code units (section 3.2.3 sorting example)", () => {
    const input: Record<string, string> = {};
    input["€"] = "Euro Sign";
    input["\r"] = "Carriage Return";
    input["דּ"] = "Hebrew Letter Dalet With Dagesh";
    input["1"] = "One";
    input["😀"] = "Emoji: Grinning Face";
    input["\u0080"] = "Control";
    input["ö"] = "Latin Small Letter O With Diaeresis";
    expect(canonicalize(input)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",' +
        '"€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  // RFC 8785 Appendix B: IEEE 754 double bit patterns -> canonical number text.
  const numbers: [string, string][] = [
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555554", "333333333.33333325"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555556", "333333333.3333334"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ];
  it.each(numbers)("number table: %s -> %s", (bits, text) => {
    expect(canonicalize(fromBits(bits))).toBe(text);
  });

  it("rejects NaN and Infinity", () => {
    expect(() => canonicalize(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(TypeError);
  });

  it("emits no whitespace, drops undefined members, nests recursively", () => {
    expect(canonicalize({ b: [1, { z: 1, a: undefined, y: "x" }], a: null })).toBe('{"a":null,"b":[1,{"y":"x","z":1}]}');
  });
});
