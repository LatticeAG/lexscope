// Strict JSON parser for lexscope/1 wire bytes.
// Rejects: BOM, invalid UTF-8, unpaired surrogates, nonfinite/fractional/exponent
// number tokens, negative zero, unsafe integers, duplicate object keys (detected
// during tokenization), depth >16, >128 members per object, arrays >128.

export class JsonParseError extends Error {
  kind: "JSON_INVALID" | "JSON_LIMIT";
  constructor(kind: "JSON_INVALID" | "JSON_LIMIT", msg: string) {
    super(msg);
    this.kind = kind;
  }
}

const MAX_DEPTH = 16;
const MAX_MEMBERS = 128;
const MAX_ARRAY = 128;
const MAX_SAFE = 9007199254740991;

export function parseStrict(bytes: Uint8Array): unknown {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
    throw new JsonParseError("JSON_INVALID", "bom");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new JsonParseError("JSON_INVALID", "utf8");
  }
  const p = new P(text);
  p.ws();
  const v = p.value(0);
  p.ws();
  if (!p.eof()) throw new JsonParseError("JSON_INVALID", "trailing");
  return v;
}

export function tryParseStrict(bytes: Uint8Array): { ok: true; value: unknown } | { ok: false; kind: string } {
  try {
    return { ok: true, value: parseStrict(bytes) };
  } catch (e) {
    return { ok: false, kind: e instanceof JsonParseError ? e.kind : "JSON_INVALID" };
  }
}

class P {
  s: string;
  i = 0;
  constructor(s: string) {
    this.s = s;
  }
  eof(): boolean {
    return this.i >= this.s.length;
  }
  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }
  fail(msg: string): never {
    throw new JsonParseError("JSON_INVALID", msg);
  }
  value(depth: number): unknown {
    if (this.eof()) this.fail("eof");
    if (depth > MAX_DEPTH) throw new JsonParseError("JSON_LIMIT", "depth");
    const c = this.s.charCodeAt(this.i);
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
    this.fail("token");
  }
  lit(word: string, v: unknown): unknown {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    this.fail("literal");
  }
  number(): number {
    const start = this.i;
    if (this.s.charCodeAt(this.i) === 0x2d) this.i++;
    if (this.eof()) this.fail("num");
    let c = this.s.charCodeAt(this.i);
    if (c === 0x30) {
      this.i++;
      // "0" alone; "-0" rejected below via token text; leading zero digits invalid in JSON
    } else if (c >= 0x31 && c <= 0x39) {
      while (!this.eof() && (c = this.s.charCodeAt(this.i)) >= 0x30 && c <= 0x39) this.i++;
    } else this.fail("num");
    if (!this.eof()) {
      c = this.s.charCodeAt(this.i);
      if (c === 0x2e || c === 0x65 || c === 0x45) this.fail("num.profile"); // fraction/exponent
    }
    const tok = this.s.slice(start, this.i);
    if (tok === "-0") this.fail("negzero");
    const n = Number(tok);
    if (!Number.isSafeInteger(n) || Math.abs(n) > MAX_SAFE) this.fail("unsafe-int");
    return n;
  }
  string(): string {
    this.i++; // consume "
    let out = "";
    for (;;) {
      if (this.eof()) this.fail("str");
      let c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c === 0x5c) {
        this.i++;
        if (this.eof()) this.fail("esc");
        const e = this.s.charCodeAt(this.i);
        this.i++;
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += "\\"; break;
          case 0x2f: out += "/"; break;
          case 0x62: out += "\b"; break;
          case 0x66: out += "\f"; break;
          case 0x6e: out += "\n"; break;
          case 0x72: out += "\r"; break;
          case 0x74: out += "\t"; break;
          case 0x75: {
            const cp = this.hex4();
            if (cp >= 0xd800 && cp <= 0xdbff) {
              // require a paired low surrogate
              if (this.s.charCodeAt(this.i) === 0x5c && this.s.charCodeAt(this.i + 1) === 0x75) {
                this.i += 2;
                const lo = this.hex4();
                if (lo < 0xdc00 || lo > 0xdfff) this.fail("surrogate");
                out += String.fromCharCode(cp, lo);
              } else this.fail("surrogate");
            } else if (cp >= 0xdc00 && cp <= 0xdfff) this.fail("surrogate");
            else out += String.fromCharCode(cp);
            break;
          }
          default:
            this.fail("esc");
        }
      } else {
        if (c < 0x20) this.fail("ctrl");
        if (c >= 0xd800 && c <= 0xdbff) {
          // literal high surrogate must be followed by a literal low surrogate
          const lo = this.s.charCodeAt(this.i + 1);
          if (lo < 0xdc00 || lo > 0xdfff) this.fail("surrogate");
          out += this.s[this.i]! + this.s[this.i + 1]!;
          this.i += 2;
          continue;
        }
        if (c >= 0xdc00 && c <= 0xdfff) this.fail("surrogate"); // unpaired low
        out += this.s[this.i];
        this.i++;
      }
    }
  }
  hex4(): number {
    if (this.i + 4 > this.s.length) this.fail("hex");
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = this.s.charCodeAt(this.i + k);
      const d = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x61 && c <= 0x66 ? c - 0x57 : c >= 0x41 && c <= 0x46 ? c - 0x37 : -1;
      if (d < 0) this.fail("hex");
      v = v * 16 + d;
    }
    this.i += 4;
    return v;
  }
  object(depth: number): Record<string, unknown> {
    this.i++; // {
    const obj: Record<string, unknown> = {};
    this.ws();
    if (this.s.charCodeAt(this.i) === 0x7d) {
      this.i++;
      return obj;
    }
    let members = 0;
    for (;;) {
      this.ws();
      if (this.s.charCodeAt(this.i) !== 0x22) this.fail("key");
      const key = this.string();
      if (Object.prototype.hasOwnProperty.call(obj, key)) this.fail("dupkey:" + key);
      members++;
      if (members > MAX_MEMBERS) throw new JsonParseError("JSON_LIMIT", "members");
      this.ws();
      if (this.s.charCodeAt(this.i) !== 0x3a) this.fail("colon");
      this.i++;
      this.ws();
      obj[key] = this.value(depth + 1);
      this.ws();
      const c = this.s.charCodeAt(this.i);
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        return obj;
      }
      this.fail("obj");
    }
  }
  array(depth: number): unknown[] {
    this.i++; // [
    const arr: unknown[] = [];
    this.ws();
    if (this.s.charCodeAt(this.i) === 0x5d) {
      this.i++;
      return arr;
    }
    for (;;) {
      this.ws();
      arr.push(this.value(depth + 1));
      if (arr.length > MAX_ARRAY) throw new JsonParseError("JSON_LIMIT", "array");
      this.ws();
      const c = this.s.charCodeAt(this.i);
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        return arr;
      }
      this.fail("arr");
    }
  }
}
