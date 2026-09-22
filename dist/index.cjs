'use strict';

var dotenv = require('dotenv');
var yaml = require('yaml');
var zod = require('zod');
var cloneDeep = require('lodash/cloneDeep.js');
var get = require('lodash/get.js');
var toPath = require('lodash/toPath.js');
var hmac = require('@noble/hashes/hmac');
var hkdf = require('@noble/hashes/hkdf');
var sha256 = require('@noble/hashes/sha256');
var utils = require('@noble/hashes/utils');
var base = require('@scure/base');
var scrypt = require('@noble/hashes/scrypt');
var chacha = require('@noble/ciphers/chacha');
var sha2 = require('@noble/hashes/sha2');
var aes = require('@noble/ciphers/aes');
var promises = require('fs/promises');
var path = require('path');
var os = require('os');
var child_process = require('child_process');
var util = require('util');
var sshpk = require('sshpk');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

var dotenv__default = /*#__PURE__*/_interopDefault(dotenv);
var cloneDeep__default = /*#__PURE__*/_interopDefault(cloneDeep);
var get__default = /*#__PURE__*/_interopDefault(get);
var toPath__default = /*#__PURE__*/_interopDefault(toPath);
var sshpk__default = /*#__PURE__*/_interopDefault(sshpk);

var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/runtime.ts
async function loadFromFile(path) {
  if (globalThis.Deno) {
    return Deno.readTextFile(path);
  }
  if (globalThis.Bun) {
    return Bun.file(path).text();
  }
  if (typeof process !== "undefined" && process.versions?.node) {
    const fs = await import('fs/promises');
    return fs.readFile(path, "utf-8");
  }
  throw new Error(`Unable to determine method to load file "${path}"`);
}

// src/sops-file.ts
function isSopsInput(value) {
  if (!value) {
    return false;
  }
  if (typeof value === "string") {
    return true;
  }
  if (typeof value === "object" && value !== null && "sops" in value && typeof value.sops === "object" && value.sops !== null && (value.sops.age == null || Array.isArray(value.sops.age)) && typeof value.sops.mac === "string" && typeof value.sops.lastmodified === "string" && typeof value.sops.version === "string") {
    return true;
  }
  if (typeof value === "object") {
    return value instanceof File || value instanceof Blob || value instanceof ArrayBuffer || value instanceof Uint8Array || value instanceof Buffer || value instanceof ReadableStream;
  }
  return false;
}
var AgeRecipientSchema = zod.z.object({
  enc: zod.z.string(),
  recipient: zod.z.string()
});
var SopsSchema = zod.z.object({
  sops: zod.z.object({
    // age recipients; absent (null) when the file is encrypted only to
    // other master keys (e.g. AWS KMS) — decrypt those with `dataKey`.
    age: zod.z.array(AgeRecipientSchema).nullable().optional(),
    lastmodified: zod.z.string(),
    mac: zod.z.string().optional(),
    unencrypted_suffix: zod.z.string().optional(),
    version: zod.z.string()
  })
}).passthrough();
async function inputToString(input) {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof File || input instanceof Blob) {
    return await input.text();
  }
  if (input instanceof ArrayBuffer || input instanceof Uint8Array) {
    return new TextDecoder().decode(input);
  }
  if (typeof globalThis.Buffer !== "undefined" && globalThis.Buffer.isBuffer(input)) {
    return input.toString("utf-8");
  }
  if (input instanceof ReadableStream) {
    const reader = input.getReader();
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      chunks.push(value);
    }
    const concatenated = new Uint8Array(
      chunks.reduce((acc, chunk) => acc + chunk.length, 0)
    );
    let offset = 0;
    for (const chunk of chunks) {
      concatenated.set(chunk, offset);
      offset += chunk.length;
    }
    return new TextDecoder().decode(concatenated);
  }
  if (typeof input === "object") {
    return JSON.stringify(input);
  }
  throw new Error(`Unsupported input type: ${typeof input}`);
}
function autoDetectAndParseSops(data) {
  try {
    return parseSopsJson(data);
  } catch {
    try {
      return parseSopsYaml(data);
    } catch {
      try {
        return parseSopsEnv(data);
      } catch {
        throw new Error(
          "Could not auto-detect file type. Please specify: env, json, or yaml"
        );
      }
    }
  }
}
async function parseSops(input, sopsFileType) {
  try {
    const data = await inputToString(input);
    if (sopsFileType) {
      switch (sopsFileType) {
        case "env":
          return parseSopsEnv(data);
        case "json":
          return parseSopsJson(data);
        case "yaml":
          return parseSopsYaml(data);
        default:
          throw new Error(`Unknown SOPS file type: ${String(sopsFileType)}`);
      }
    }
    return autoDetectAndParseSops(data);
  } catch (err) {
    throw new Error(`Failed to load SOPS file: ${err.message}`, {
      cause: err
    });
  }
}
async function loadSopsFile(path, sopsFileType) {
  try {
    const content = await loadFromFile(path);
    return await parseSops(content, sopsFileType);
  } catch (err) {
    throw new Error(
      `Failed to load SOPS file '${path}': ${err.message}`,
      {
        cause: err
      }
    );
  }
}
function parseSopsYaml(yamlString) {
  return SopsSchema.parse(yaml.parse(yamlString));
}
function parseSopsJson(json) {
  return SopsSchema.parse(typeof json === "string" ? JSON.parse(json) : json);
}
function rebuildAgeArray(sops) {
  return Object.keys(sops).filter((key) => key.startsWith("age__list_")).reduce((acc, key) => {
    const match = key.match(/^age__list_(\d+)__(map_enc|map_recipient)$/);
    if (match) {
      const index = parseInt(match[1], 10);
      const type = match[2];
      acc[index] = acc[index] || {};
      acc[index][type === "map_enc" ? "enc" : "recipient"] = sops[key];
    }
    return acc;
  }, []).map(({ enc, recipient }) => ({
    enc: enc.replaceAll("\\n", "\n"),
    recipient
  }));
}
function constructSopsObject(base, sops) {
  return SopsSchema.parse({
    ...base,
    sops: {
      age: rebuildAgeArray(sops),
      lastmodified: sops.lastmodified,
      mac: sops.mac,
      unencrypted_suffix: sops.unencrypted_suffix,
      version: sops.version
    }
  });
}
function parseSopsEnv(envString) {
  const parsedEnv = dotenv__default.default.parse(envString);
  const sopsKeys = Object.keys(parsedEnv).filter(
    (key) => key.startsWith("sops_")
  );
  if (sopsKeys.length === 0) {
    throw new Error("Missing sops data in .env");
  }
  const sops = {};
  sopsKeys.forEach((key) => {
    const newKey = key.replace(/^sops_/, "");
    sops[newKey] = parsedEnv[key];
  });
  const nonSopsEnv = Object.keys(parsedEnv).reduce(
    (acc, key) => {
      if (!sopsKeys.includes(key)) {
        acc[key] = parsedEnv[key];
      }
      return acc;
    },
    {}
  );
  return constructSopsObject(nonSopsEnv, sops);
}

// node_modules/@noble/curves/esm/abstract/utils.js
var _0n = /* @__PURE__ */ BigInt(0);
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes(item) {
  if (!isBytes(item))
    throw new Error("Uint8Array expected");
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
var hasHexBuiltin = (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
);
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function bytesToNumberLE(bytes) {
  abytes(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
var validatorFns = {
  bigint: (val) => typeof val === "bigint",
  function: (val) => typeof val === "function",
  boolean: (val) => typeof val === "boolean",
  string: (val) => typeof val === "string",
  stringOrUint8Array: (val) => typeof val === "string" || isBytes(val),
  isSafeInteger: (val) => Number.isSafeInteger(val),
  array: (val) => Array.isArray(val),
  field: (val, object) => object.Fp.isValid(val),
  hash: (val) => typeof val === "function" && Number.isSafeInteger(val.outputLen)
};
function validateObject(object, validators, optValidators = {}) {
  const checkField = (fieldName, type, isOptional) => {
    const checkVal = validatorFns[type];
    if (typeof checkVal !== "function")
      throw new Error("invalid validator function");
    const val = object[fieldName];
    if (isOptional && val === void 0)
      return;
    if (!checkVal(val, object)) {
      throw new Error("param " + String(fieldName) + " is invalid. Expected " + type + ", got " + val);
    }
  };
  for (const [fieldName, type] of Object.entries(validators))
    checkField(fieldName, type, false);
  for (const [fieldName, type] of Object.entries(optValidators))
    checkField(fieldName, type, true);
  return object;
}

// node_modules/@noble/curves/esm/abstract/modular.js
var _0n2 = BigInt(0);
BigInt(1);
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}

// node_modules/@noble/curves/esm/abstract/montgomery.js
var _0n3 = BigInt(0);
var _1n2 = BigInt(1);
var _2n = BigInt(2);
function validateOpts(curve) {
  validateObject(curve, {
    adjustScalarBytes: "function",
    powPminus2: "function"
  });
  return Object.freeze({ ...curve });
}
function montgomery(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { P, type, adjustScalarBytes: adjustScalarBytes2, powPminus2 } = CURVE;
  const is25519 = type === "x25519";
  if (!is25519 && type !== "x448")
    throw new Error("invalid type");
  const montgomeryBits = is25519 ? 255 : 448;
  const fieldLen = is25519 ? 32 : 56;
  const Gu = is25519 ? BigInt(9) : BigInt(5);
  const a24 = is25519 ? BigInt(121665) : BigInt(39081);
  const minScalar = is25519 ? _2n ** BigInt(254) : _2n ** BigInt(447);
  const maxAdded = is25519 ? BigInt(8) * _2n ** BigInt(251) - _1n2 : BigInt(4) * _2n ** BigInt(445) - _1n2;
  const maxScalar = minScalar + maxAdded + _1n2;
  const modP = (n) => mod(n, P);
  const GuBytes = encodeU(Gu);
  function encodeU(u) {
    return numberToBytesLE(modP(u), fieldLen);
  }
  function decodeU(u) {
    const _u = ensureBytes("u coordinate", u, fieldLen);
    if (is25519)
      _u[31] &= 127;
    return modP(bytesToNumberLE(_u));
  }
  function decodeScalar(scalar) {
    return bytesToNumberLE(adjustScalarBytes2(ensureBytes("scalar", scalar, fieldLen)));
  }
  function scalarMult2(scalar, u) {
    const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
    if (pu === _0n3)
      throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  function scalarMultBase2(scalar) {
    return scalarMult2(scalar, GuBytes);
  }
  function cswap(swap, x_2, x_3) {
    const dummy = modP(swap * (x_2 - x_3));
    x_2 = modP(x_2 - dummy);
    x_3 = modP(x_3 + dummy);
    return { x_2, x_3 };
  }
  function montgomeryLadder(u, scalar) {
    aInRange("u", u, _0n3, P);
    aInRange("scalar", scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = _1n2;
    let z_2 = _0n3;
    let x_3 = u;
    let z_3 = _1n2;
    let swap = _0n3;
    for (let t = BigInt(montgomeryBits - 1); t >= _0n3; t--) {
      const k_t = k >> t & _1n2;
      swap ^= k_t;
      ({ x_2, x_3 } = cswap(swap, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
      swap = k_t;
      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B = x_2 - z_2;
      const BB = modP(B * B);
      const E = AA - BB;
      const C = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C * B);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      z_2 = modP(E * (AA + modP(a24 * E)));
    }
    ({ x_2, x_3 } = cswap(swap, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
    const z2 = powPminus2(z_2);
    return modP(x_2 * z2);
  }
  return {
    scalarMult: scalarMult2,
    scalarMultBase: scalarMultBase2,
    getSharedSecret: (privateKey, publicKey) => scalarMult2(privateKey, publicKey),
    getPublicKey: (privateKey) => scalarMultBase2(privateKey),
    utils: { randomPrivateKey: () => CURVE.randomBytes(fieldLen) },
    GuBytes: GuBytes.slice()
  };
}

// node_modules/@noble/curves/esm/ed25519.js
var ED25519_P = BigInt("57896044618658097711785492504343953926634992332820282019728792003956564819949");
BigInt(0);
var _1n3 = BigInt(1);
var _2n2 = BigInt(2);
var _3n = BigInt(3);
var _5n = BigInt(5);
BigInt(8);
function ed25519_pow_2_252_3(x) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ED25519_P;
  const x2 = x * x % P;
  const b2 = x2 * x % P;
  const b4 = pow2(b2, _2n2, P) * b2 % P;
  const b5 = pow2(b4, _1n3, P) * x % P;
  const b10 = pow2(b5, _5n, P) * b5 % P;
  const b20 = pow2(b10, _10n, P) * b10 % P;
  const b40 = pow2(b20, _20n, P) * b20 % P;
  const b80 = pow2(b40, _40n, P) * b40 % P;
  const b160 = pow2(b80, _80n, P) * b80 % P;
  const b240 = pow2(b160, _80n, P) * b80 % P;
  const b250 = pow2(b240, _10n, P) * b10 % P;
  const pow_p_5_8 = pow2(b250, _2n2, P) * x % P;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
var x25519 = /* @__PURE__ */ (() => montgomery({
  P: ED25519_P,
  type: "x25519",
  powPminus2: (x) => {
    const P = ED25519_P;
    const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
    return mod(pow2(pow_p_5_8, _3n, P) * b2, P);
  },
  adjustScalarBytes,
  randomBytes: utils.randomBytes
}))();

// node_modules/age-encryption/dist/x25519.js
var exportable = false;
var webCryptoOff = false;
var isX25519Supported = /* @__PURE__ */ (() => {
  let supported;
  return async () => {
    if (supported === void 0) {
      try {
        await crypto.subtle.importKey("raw", x25519.GuBytes, { name: "X25519" }, exportable, []);
        supported = true;
      } catch {
        supported = false;
      }
    }
    return supported;
  };
})();
async function scalarMult(scalar, u) {
  if (!await isX25519Supported() || webCryptoOff) {
    if (isCryptoKey(scalar)) {
      throw new Error("CryptoKey provided but X25519 WebCrypto is not supported");
    }
    return x25519.scalarMult(scalar, u);
  }
  let key;
  if (isCryptoKey(scalar)) {
    key = scalar;
  } else {
    key = await importX25519Key(scalar);
  }
  const peer = await crypto.subtle.importKey("raw", u, { name: "X25519" }, exportable, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peer }, key, 256));
}
async function scalarMultBase(scalar) {
  if (!await isX25519Supported() || webCryptoOff) {
    if (isCryptoKey(scalar)) {
      throw new Error("CryptoKey provided but X25519 WebCrypto is not supported");
    }
    return x25519.scalarMultBase(scalar);
  }
  return scalarMult(scalar, x25519.GuBytes);
}
var pkcs8Prefix = /* @__PURE__ */ new Uint8Array([
  48,
  46,
  2,
  1,
  0,
  48,
  5,
  6,
  3,
  43,
  101,
  110,
  4,
  34,
  4,
  32
]);
async function importX25519Key(key) {
  if (key.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes");
  }
  const pkcs8 = new Uint8Array([...pkcs8Prefix, ...key]);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, exportable, ["deriveBits"]);
}
function isCryptoKey(key) {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey;
}
var Stanza = class {
  /**
   * All space-separated arguments on the first line of the stanza.
   * Each argument is a string that does not contain spaces.
   * The first argument is often a recipient type, which should look like
   * `example.com/...` to avoid collisions.
   */
  args;
  /**
   * The raw body of the stanza. This is automatically base64-encoded and
   * split into lines of 48 characters each.
   */
  body;
  constructor(args, body) {
    this.args = args;
    this.body = body;
  }
};
var ByteReader = class {
  arr;
  constructor(arr) {
    this.arr = arr;
  }
  toString(bytes) {
    bytes.forEach((b) => {
      if (b < 32 || b > 136) {
        throw Error("invalid non-ASCII byte in header");
      }
    });
    return new TextDecoder().decode(bytes);
  }
  readString(n) {
    const out = this.arr.subarray(0, n);
    this.arr = this.arr.subarray(n);
    return this.toString(out);
  }
  readLine() {
    const i = this.arr.indexOf("\n".charCodeAt(0));
    if (i >= 0) {
      const out = this.arr.subarray(0, i);
      this.arr = this.arr.subarray(i + 1);
      return this.toString(out);
    }
    return null;
  }
  rest() {
    return this.arr;
  }
};
function parseNextStanza(header) {
  const hdr = new ByteReader(header);
  if (hdr.readString(3) !== "-> ") {
    throw Error("invalid stanza");
  }
  const argsLine = hdr.readLine();
  if (argsLine === null) {
    throw Error("invalid stanza");
  }
  const args = argsLine.split(" ");
  if (args.length < 1) {
    throw Error("invalid stanza");
  }
  for (const arg of args) {
    if (arg.length === 0) {
      throw Error("invalid stanza");
    }
  }
  const bodyLines = [];
  for (; ; ) {
    const nextLine = hdr.readLine();
    if (nextLine === null) {
      throw Error("invalid stanza");
    }
    const line = base.base64nopad.decode(nextLine);
    if (line.length > 48) {
      throw Error("invalid stanza");
    }
    bodyLines.push(line);
    if (line.length < 48) {
      break;
    }
  }
  const body = flattenArray(bodyLines);
  return [new Stanza(args, body), hdr.rest()];
}
function flattenArray(arr) {
  const len = arr.reduce((sum, line) => sum + line.length, 0);
  const out = new Uint8Array(len);
  let n = 0;
  for (const a of arr) {
    out.set(a, n);
    n += a.length;
  }
  return out;
}
function parseHeader(header) {
  const hdr = new ByteReader(header);
  const versionLine = hdr.readLine();
  if (versionLine !== "age-encryption.org/v1") {
    throw Error("invalid version " + (versionLine ?? "line"));
  }
  let rest = hdr.rest();
  const stanzas = [];
  for (; ; ) {
    let s;
    [s, rest] = parseNextStanza(rest);
    stanzas.push(s);
    const hdr2 = new ByteReader(rest);
    if (hdr2.readString(4) === "--- ") {
      const headerNoMAC = header.subarray(0, header.length - hdr2.rest().length - 1);
      const macLine = hdr2.readLine();
      if (macLine === null) {
        throw Error("invalid header");
      }
      const mac = base.base64nopad.decode(macLine);
      return {
        stanzas,
        headerNoMAC,
        MAC: mac,
        rest: hdr2.rest()
      };
    }
  }
}

// node_modules/age-encryption/dist/recipients.js
async function identityToRecipient(identity) {
  let scalar;
  if (isCryptoKey2(identity)) {
    scalar = identity;
  } else {
    const res = base.bech32.decodeToBytes(identity);
    if (!identity.startsWith("AGE-SECRET-KEY-1") || res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" || res.bytes.length !== 32) {
      throw Error("invalid identity");
    }
    scalar = res.bytes;
  }
  const recipient = await scalarMultBase(scalar);
  return base.bech32.encodeFromBytes("age", recipient);
}
var X25519Identity = class {
  identity;
  recipient;
  constructor(s) {
    if (isCryptoKey2(s)) {
      this.identity = s;
      this.recipient = scalarMultBase(s);
      return;
    }
    const res = base.bech32.decodeToBytes(s);
    if (!s.startsWith("AGE-SECRET-KEY-1") || res.prefix.toUpperCase() !== "AGE-SECRET-KEY-" || res.bytes.length !== 32) {
      throw Error("invalid identity");
    }
    this.identity = res.bytes;
    this.recipient = scalarMultBase(res.bytes);
  }
  async unwrapFileKey(stanzas) {
    for (const s of stanzas) {
      if (s.args.length < 1 || s.args[0] !== "X25519") {
        continue;
      }
      if (s.args.length !== 2) {
        throw Error("invalid X25519 stanza");
      }
      const share = base.base64nopad.decode(s.args[1]);
      if (share.length !== 32) {
        throw Error("invalid X25519 stanza");
      }
      const secret = await scalarMult(this.identity, share);
      const recipient = await this.recipient;
      const salt = new Uint8Array(share.length + recipient.length);
      salt.set(share);
      salt.set(recipient, share.length);
      const key = hkdf.hkdf(sha256.sha256, secret, salt, "age-encryption.org/v1/X25519", 32);
      const fileKey = decryptFileKey(s.body, key);
      if (fileKey !== null)
        return fileKey;
    }
    return null;
  }
};
var ScryptIdentity = class {
  passphrase;
  constructor(passphrase) {
    this.passphrase = passphrase;
  }
  unwrapFileKey(stanzas) {
    for (const s of stanzas) {
      if (s.args.length < 1 || s.args[0] !== "scrypt") {
        continue;
      }
      if (stanzas.length !== 1) {
        throw Error("scrypt recipient is not the only one in the header");
      }
      if (s.args.length !== 3) {
        throw Error("invalid scrypt stanza");
      }
      if (!/^[1-9][0-9]*$/.test(s.args[2])) {
        throw Error("invalid scrypt stanza");
      }
      const salt = base.base64nopad.decode(s.args[1]);
      if (salt.length !== 16) {
        throw Error("invalid scrypt stanza");
      }
      const logN = Number(s.args[2]);
      if (logN > 20) {
        throw Error("scrypt work factor is too high");
      }
      const label = "age-encryption.org/v1/scrypt";
      const labelAndSalt = new Uint8Array(label.length + 16);
      labelAndSalt.set(new TextEncoder().encode(label));
      labelAndSalt.set(salt, label.length);
      const key = scrypt.scrypt(this.passphrase, labelAndSalt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32 });
      const fileKey = decryptFileKey(s.body, key);
      if (fileKey !== null)
        return fileKey;
    }
    return null;
  }
};
function decryptFileKey(body, key) {
  if (body.length !== 32) {
    throw Error("invalid stanza");
  }
  const nonce = new Uint8Array(12);
  try {
    return chacha.chacha20poly1305(key, nonce).decrypt(body);
  } catch {
    return null;
  }
}
function isCryptoKey2(key) {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey;
}
var chacha20poly1305Overhead = 16;
var chunkSize = /* @__PURE__ */ (() => 64 * 1024)();
var chunkSizeWithOverhead = /* @__PURE__ */ (() => chunkSize + chacha20poly1305Overhead)();
function decryptSTREAM(key, ciphertext) {
  const streamNonce = new Uint8Array(12);
  const incNonce = () => {
    for (let i = streamNonce.length - 2; i >= 0; i--) {
      streamNonce[i]++;
      if (streamNonce[i] !== 0)
        break;
    }
  };
  const chunkCount = Math.ceil(ciphertext.length / chunkSizeWithOverhead);
  const overhead = chunkCount * chacha20poly1305Overhead;
  const plaintext = new Uint8Array(ciphertext.length - overhead);
  let plaintextSlice = plaintext;
  while (ciphertext.length > chunkSizeWithOverhead) {
    const chunk2 = chacha.chacha20poly1305(key, streamNonce).decrypt(ciphertext.subarray(0, chunkSizeWithOverhead));
    plaintextSlice.set(chunk2);
    plaintextSlice = plaintextSlice.subarray(chunk2.length);
    ciphertext = ciphertext.subarray(chunkSizeWithOverhead);
    incNonce();
  }
  streamNonce[11] = 1;
  const chunk = chacha.chacha20poly1305(key, streamNonce).decrypt(ciphertext);
  plaintextSlice.set(chunk);
  if (chunk.length === 0 && plaintext.length !== 0) {
    throw Error("empty final chunk");
  }
  if (plaintextSlice.length !== chunk.length) {
    throw Error("stream: internal error: didn't fill expected plaintext buffer");
  }
  return plaintext;
}

// node_modules/age-encryption/dist/armor.js
var armor_exports = {};
__export(armor_exports, {
  decode: () => decode,
  encode: () => encode
});
function encode(file) {
  const lines = [];
  lines.push("-----BEGIN AGE ENCRYPTED FILE-----\n");
  for (let i = 0; i < file.length; i += 48) {
    let end = i + 48;
    if (end > file.length)
      end = file.length;
    lines.push(base.base64.encode(file.subarray(i, end)) + "\n");
  }
  lines.push("-----END AGE ENCRYPTED FILE-----\n");
  return lines.join("");
}
function decode(file) {
  const lines = file.trim().replaceAll("\r\n", "\n").split("\n");
  if (lines.shift() !== "-----BEGIN AGE ENCRYPTED FILE-----") {
    throw Error("invalid header");
  }
  if (lines.pop() !== "-----END AGE ENCRYPTED FILE-----") {
    throw Error("invalid footer");
  }
  function isLineLengthValid(i, l) {
    if (i === lines.length - 1) {
      return l.length > 0 && l.length <= 64 && l.length % 4 === 0;
    }
    return l.length === 64;
  }
  if (!lines.every((l, i) => isLineLengthValid(i, l))) {
    throw Error("invalid line length");
  }
  if (!lines.every((l) => /^[A-Za-z0-9+/=]+$/.test(l))) {
    throw Error("invalid base64");
  }
  return base.base64.decode(lines.join(""));
}

// node_modules/age-encryption/dist/index.js
var Decrypter = class {
  identities = [];
  /**
   * Add a passphrase to decrypt password-encrypted file(s) with. This method
   * can be called multiple times to try multiple passphrases.
   *
   * @param s - The passphrase to decrypt the file with.
   */
  addPassphrase(s) {
    this.identities.push(new ScryptIdentity(s));
  }
  /**
   * Add an identity to decrypt file(s) with. This method can be called
   * multiple times to try multiple identities.
   *
   * @param s - The identity to decrypt the file with. Either a string
   * beginning with `AGE-SECRET-KEY-1...`, an X25519 private
   * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey | CryptoKey}
   * object, or an object implementing the {@link Identity} interface.
   *
   * A CryptoKey object must have
   * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/type | type}
   * `private`,
   * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/algorithm | algorithm}
   * `{name: 'X25519'}`, and
   * {@link https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/usages | usages}
   * `["deriveBits"]`. For example:
   * ```js
   * const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
   * decrypter.addIdentity(key.privateKey)
   * ```
   */
  addIdentity(s) {
    if (typeof s === "string" || isCryptoKey3(s)) {
      this.identities.push(new X25519Identity(s));
    } else {
      this.identities.push(s);
    }
  }
  async decrypt(file, outputFormat) {
    const h = parseHeader(file);
    const fileKey = await this.unwrapFileKey(h.stanzas);
    if (fileKey === null) {
      throw Error("no identity matched any of the file's recipients");
    }
    const hmacKey = hkdf.hkdf(sha256.sha256, fileKey, void 0, "header", 32);
    const mac = hmac.hmac(sha256.sha256, hmacKey, h.headerNoMAC);
    if (!compareBytes(h.MAC, mac)) {
      throw Error("invalid header HMAC");
    }
    const nonce = h.rest.subarray(0, 16);
    const streamKey = hkdf.hkdf(sha256.sha256, fileKey, nonce, "payload", 32);
    const payload = h.rest.subarray(16);
    const out = decryptSTREAM(streamKey, payload);
    if (outputFormat === "text")
      return new TextDecoder().decode(out);
    return out;
  }
  async unwrapFileKey(stanzas) {
    for (const identity of this.identities) {
      const fileKey = await identity.unwrapFileKey(stanzas);
      if (fileKey !== null)
        return fileKey;
    }
    return null;
  }
};
function compareBytes(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let acc = 0;
  for (let i = 0; i < a.length; i++) {
    acc |= a[i] ^ b[i];
  }
  return acc === 0;
}
function isCryptoKey3(key) {
  return typeof CryptoKey !== "undefined" && key instanceof CryptoKey;
}

// src/age.ts
var X25519_PRIVATE_KEY_HRP = "AGE-SECRET-KEY-1";
async function getPublicAgeKey(privateAgeKey) {
  return identityToRecipient(privateAgeKey);
}
async function decryptAgeEncryptionKey(encryptedKey, secretKey) {
  const decoded = armor_exports.decode(encryptedKey);
  const decrypter = new Decrypter();
  decrypter.addIdentity(secretKey);
  return decrypter.decrypt(decoded, "uint8array");
}
function decryptAesGcm(encryptedValue, key, additionalData) {
  const combined = new Uint8Array(
    encryptedValue.data.length + encryptedValue.tag.length
  );
  combined.set(encryptedValue.data);
  combined.set(encryptedValue.tag, encryptedValue.data.length);
  const aes$1 = aes.gcm(key, encryptedValue.iv, additionalData);
  return aes$1.decrypt(combined);
}
function clampX25519PrivateKey(key) {
  if (key.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes for clamping.");
  }
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
}
function encodeX25519Bech32PrivateKey(privateKeyBytes) {
  if (privateKeyBytes.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes for Bech32 encoding.");
  }
  const encoded = base.bech32.encode(
    "AGE-SECRET-KEY-",
    base.bech32.toWords(privateKeyBytes)
  );
  return encoded.toUpperCase();
}
function convertEd25519SeedToX25519PrivateKey(ed25519Seed) {
  if (ed25519Seed.length !== 32) {
    throw new Error("ed25519 seed must be 32 bytes.");
  }
  const hashedSeed = sha2.sha512(ed25519Seed);
  const x25519Sk = hashedSeed.slice(0, 32);
  return x25519Sk;
}
function convertRsaPublicKeyToX25519PrivateKey(rsaN, rsaE) {
  const hasher = sha2.sha256.create();
  hasher.update(rsaN);
  hasher.update(rsaE);
  const x25519Sk = hasher.digest();
  clampX25519PrivateKey(x25519Sk);
  return x25519Sk;
}
function sshKeyToAge(keyFileContent, filePathForErrorMsg = "unknown key source") {
  try {
    if (keyFileContent.trim() === "") {
      return null;
    }
    const sshPk = sshpk__default.default.parsePrivateKey(keyFileContent, "auto", {
      filename: filePathForErrorMsg
    });
    let x25519SkBytes;
    if (sshPk.type === "ed25519") {
      const seedPart = sshPk.parts.find(
        (part) => part.name === "k" && part.data && part.data.length === 32
      );
      if (!seedPart || !seedPart.data) {
        console.error(
          `Failed to find 32-byte "k" part (seed) for Ed25519 key. SSHPK Parts for ${filePathForErrorMsg}:`
        );
        sshPk.parts.forEach((part, index) => {
          console.error(
            `  Part ${index}: Name: "${part.name}", Type: ${typeof part.data}, Length: ${part.data?.length}`
          );
        });
        throw new Error(
          `Could not extract 32-byte seed (part "k") from Ed25519 key in ${filePathForErrorMsg}.`
        );
      }
      const ed25519Seed = Uint8Array.from(seedPart.data);
      x25519SkBytes = convertEd25519SeedToX25519PrivateKey(ed25519Seed);
    } else if (sshPk.type === "rsa") {
      const rsaNPart = sshPk.parts.find((part) => part.name === "n");
      const rsaEPart = sshPk.parts.find((part) => part.name === "e");
      if (!rsaNPart || !rsaEPart || !rsaNPart.data || !rsaEPart.data) {
        throw new Error(
          `Could not extract N or E (modulus or public exponent) from RSA key in ${filePathForErrorMsg}.`
        );
      }
      const rsaN = Uint8Array.from(rsaNPart.data);
      const rsaE = Uint8Array.from(rsaEPart.data);
      x25519SkBytes = convertRsaPublicKeyToX25519PrivateKey(rsaN, rsaE);
    } else {
      console.warn(
        `Unsupported SSH key type "${sshPk.type}" for age conversion in ${filePathForErrorMsg}. Skipping.`
      );
      return null;
    }
    return encodeX25519Bech32PrivateKey(x25519SkBytes);
  } catch (error) {
    throw new Error(
      `Failed to parse/convert SSH key from ${filePathForErrorMsg}: ${error.message || error}`,
      { cause: error }
    );
  }
}
async function sshKeyFileToAge(filePath) {
  const content = await promises.readFile(filePath, "utf-8");
  return sshKeyToAge(content, filePath);
}

// src/age-key.ts
var execAsync = util.promisify(child_process.exec);
var SOPS_AGE_KEY_USER_CONFIG_PATH = "sops/age/keys.txt";
function parseX25519KeysFromString(content, sourceName) {
  const keyStrings = [];
  const lines = content.split("\n");
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (trimmedLine === "" || trimmedLine.startsWith("#")) {
      continue;
    }
    if (trimmedLine.toUpperCase().startsWith(X25519_PRIVATE_KEY_HRP)) {
      keyStrings.push(trimmedLine);
    } else if (trimmedLine.startsWith("AGE-PLUGIN-")) {
      console.warn(
        `AGE plugin keys are not supported: ${trimmedLine.substring(0, 30)}... from ${sourceName}`
      );
    } else if (trimmedLine.length > 0) {
      console.warn(
        `Skipping unrecognized line in ${sourceName}: ${trimmedLine.substring(
          0,
          30
        )}...`
      );
    }
  }
  return keyStrings;
}
async function getUserConfigDir() {
  if (os.platform() === "darwin") {
    const xdgConfigHome = process.env.XDG_CONFIG_HOME;
    if (xdgConfigHome && xdgConfigHome.trim() !== "") return xdgConfigHome;
  }
  switch (os.platform()) {
    case "win32":
      const appData = process.env.APPDATA;
      if (!appData) throw new Error("APPDATA env var not set");
      return appData;
    case "darwin":
      return path.join(os.homedir(), "Library", "Application Support");
    default:
      const xdgConfigHome = process.env.XDG_CONFIG_HOME;
      if (xdgConfigHome && xdgConfigHome.trim() !== "") return xdgConfigHome;
      return path.join(os.homedir(), ".config");
  }
}
async function findAllAgeKeys() {
  let foundKeySource = false;
  const convertedSshKeys = [];
  const sshKeyFilePathEnv = process.env.SOPS_AGE_SSH_PRIVATE_KEY_FILE;
  if (sshKeyFilePathEnv) {
    try {
      const x25519KeyStr = await sshKeyFileToAge(sshKeyFilePathEnv);
      if (x25519KeyStr) {
        convertedSshKeys.push(x25519KeyStr);
        foundKeySource = true;
      }
    } catch (error) {
      throw new Error(
        `Error processing SOPS_AGE_SSH_PRIVATE_KEY_FILE (${sshKeyFilePathEnv}): ${error.message}`,
        { cause: error }
      );
    }
  } else {
    const userHomeDir = os.homedir();
    if (userHomeDir) {
      const defaultSshPaths = [
        path.join(userHomeDir, ".ssh", "id_ed25519"),
        path.join(userHomeDir, ".ssh", "id_rsa")
      ];
      for (const sshPath of defaultSshPaths) {
        if (foundKeySource && convertedSshKeys.length > 0) {
          break;
        }
        try {
          const x25519KeyStr = await sshKeyFileToAge(sshPath);
          if (x25519KeyStr) {
            convertedSshKeys.push(x25519KeyStr);
            foundKeySource = true;
            break;
          }
        } catch (error) {
          if (error.code === "ENOENT") {
            continue;
          }
          throw new Error(
            `Error processing default SSH key file (${sshPath}): ${error.message}`,
            { cause: error }
          );
        }
      }
    }
  }
  const sopsAgeKeyContents = [];
  const ageKeyEnv = process.env.SOPS_AGE_KEY;
  if (ageKeyEnv) {
    sopsAgeKeyContents.push({
      sourceName: "SOPS_AGE_KEY (environment variable)",
      content: ageKeyEnv
    });
    foundKeySource = true;
  }
  const ageKeyFileEnv = process.env.SOPS_AGE_KEY_FILE;
  if (ageKeyFileEnv) {
    try {
      const content = await promises.readFile(ageKeyFileEnv, "utf-8");
      sopsAgeKeyContents.push({
        sourceName: `SOPS_AGE_KEY_FILE (${ageKeyFileEnv})`,
        content
      });
      foundKeySource = true;
    } catch (error) {
      throw new Error(
        `Failed to read SOPS_AGE_KEY_FILE (${ageKeyFileEnv}): ${error.message}`,
        { cause: error }
      );
    }
  }
  const ageKeyCmdEnv = process.env.SOPS_AGE_KEY_CMD;
  if (ageKeyCmdEnv) {
    try {
      const { stdout } = await execAsync(ageKeyCmdEnv);
      sopsAgeKeyContents.push({
        sourceName: `SOPS_AGE_KEY_CMD output (${ageKeyCmdEnv})`,
        content: stdout
      });
      foundKeySource = true;
    } catch (error) {
      throw new Error(
        `Failed to execute SOPS_AGE_KEY_CMD (${ageKeyCmdEnv}): ${error.message}`,
        { cause: error }
      );
    }
  }
  let userConfigDirPath = null;
  try {
    userConfigDirPath = await getUserConfigDir();
  } catch (error) {
    if (!foundKeySource && convertedSshKeys.length === 0) {
      throw new Error(
        `User config directory not determinable, and no other key sources found: ${error.message}`
      );
    }
  }
  if (userConfigDirPath) {
    const sopsKeysFilePath = path.join(
      userConfigDirPath,
      SOPS_AGE_KEY_USER_CONFIG_PATH
    );
    try {
      const content = await promises.readFile(sopsKeysFilePath, "utf-8");
      sopsAgeKeyContents.push({
        sourceName: `Default keys.txt (${sopsKeysFilePath})`,
        content
      });
      foundKeySource = true;
    } catch (error) {
      if (error.code === "ENOENT") {
        if (!foundKeySource && convertedSshKeys.length === 0 && // No SSH keys found
        sopsAgeKeyContents.length === 0) {
          throw new Error(
            `Default sops keys file (${sopsKeysFilePath}) not found, and no other key sources specified.`,
            { cause: error }
          );
        }
      } else {
        throw new Error(
          `Failed to read default sops keys file (${sopsKeysFilePath}): ${error.message}`,
          { cause: error }
        );
      }
    }
  }
  const sopsKeys = sopsAgeKeyContents.map((sopsAgeKeyContent) => {
    const keysFromContent = parseX25519KeysFromString(
      sopsAgeKeyContent.content,
      sopsAgeKeyContent.sourceName
    );
    return keysFromContent;
  }).flat();
  return [.../* @__PURE__ */ new Set([...sopsKeys, ...convertedSshKeys])];
}

// src/decrypt.ts
function isValidSOPSDataType(value) {
  return ["bool", "bytes", "float", "int", "str"].includes(value);
}
function convertDecryptedValue(value, datatype) {
  switch (datatype) {
    case "bool":
      return value.toLowerCase() === "true";
    case "bytes":
      return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
    case "float":
      return Number.parseFloat(value);
    case "int":
      return Number.parseInt(value, 10);
    case "str":
      return value;
  }
}
var encRegex = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;
function parse(value) {
  const matches = value.match(encRegex);
  if (!matches) {
    throw new Error(`Input string ${value} does not match sops' data format`);
  }
  try {
    const data = Uint8Array.from(atob(matches[1]), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(matches[2]), (c) => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(matches[3]), (c) => c.charCodeAt(0));
    const rawDatatype = matches[4];
    if (!isValidSOPSDataType(rawDatatype)) {
      throw new Error(`Invalid SOPS data type: ${rawDatatype}`);
    }
    return { data, datatype: rawDatatype, iv, tag };
  } catch (err) {
    throw new Error(
      `Error decoding base64: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}
async function getSopsEncryptionKey(sops, secretKeys) {
  const errors = [];
  for (const secretKey of secretKeys) {
    try {
      const pubKey = await getPublicAgeKey(secretKey);
      const recipient = (sops.sops.age ?? []).find(
        (config) => config.recipient === pubKey
      );
      if (!recipient) {
        errors.push(`No matching recipient found for key: ${pubKey}`);
        continue;
      }
      return await decryptAgeEncryptionKey(recipient.enc, secretKey);
    } catch (error) {
      errors.push(
        `Failed to decrypt with key ${secretKey.substring(0, 20)}...: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  throw new Error(
    `Failed to decrypt with any available age keys. Errors:
${errors.join("\n")}`
  );
}
function path2gopath(path) {
  return `${path.filter((x) => !/^\d+$/.test(x)).join(":")}:`;
}
function decryptSOPSValue(ciphertext, decryptionKey, path) {
  if (!ciphertext) {
    return "";
  }
  const encryptedValue = parse(ciphertext);
  const aad = path2gopath(path);
  let decrypted;
  try {
    decrypted = decryptAesGcm(
      encryptedValue,
      decryptionKey,
      new TextEncoder().encode(aad)
    );
  } catch (err) {
    throw new Error(
      `AES-GCM decryption failed at path ${JSON.stringify(path)} for value "${ciphertext}": ${err instanceof Error ? err.message : String(err)}`
    );
  }
  const decryptedValue = new TextDecoder().decode(decrypted);
  return convertDecryptedValue(decryptedValue, encryptedValue.datatype);
}
function decryptObject(obj, decryptionKey, path = []) {
  if (typeof obj !== "object" || obj === null) {
    return obj;
  }
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (typeof value === "string" && value.startsWith("ENC[AES256_GCM,data:")) {
      obj[key] = decryptSOPSValue(value, decryptionKey, [...path, key]);
    } else if (typeof value === "object") {
      obj[key] = decryptObject(value, decryptionKey, [...path, key]);
    }
  }
  return obj;
}
async function decrypt(sops, options) {
  const { keyPath, secretKey, dataKey } = options;
  const decryptionKey = dataKey ? validateDataKey(dataKey) : await getSopsEncryptionKeyFromAge(sops, secretKey);
  return decryptWithDataKey(sops, decryptionKey, keyPath);
}
function validateDataKey(dataKey) {
  if (dataKey.length !== 32) {
    throw new Error(
      `Invalid dataKey: expected 32 bytes (AES-256), got ${dataKey.length}`
    );
  }
  return dataKey;
}
async function getSopsEncryptionKeyFromAge(sops, secretKey) {
  if (!sops.sops.age || sops.sops.age.length === 0) {
    throw new Error(
      "This SOPS file has no age recipients. Unwrap its data key with the master key it is encrypted to (e.g. kms:Decrypt of sops.kms[].enc) and pass it as the dataKey option."
    );
  }
  let secretKeys;
  if (secretKey) {
    secretKeys = [secretKey];
  } else {
    try {
      secretKeys = await findAllAgeKeys();
    } catch (error) {
      throw new Error(
        `Failed to find age keys: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    if (secretKeys.length === 0) {
      throw new Error(
        "No age keys found. Provide a secretKey option or set age keys via environment variables, SSH keys, or the default sops keys.txt config file."
      );
    }
  }
  return getSopsEncryptionKey(sops, secretKeys);
}
function decryptWithDataKey(sops, decryptionKey, keyPath) {
  if (keyPath) {
    const value = get__default.default(sops, keyPath);
    if (typeof value !== "string") {
      throw new Error(`Unable to get sops value at keyPath="${keyPath}"`);
    }
    return decryptSOPSValue(value, decryptionKey, toPath__default.default(keyPath));
  }
  const { sops: _, ...data } = sops;
  const cloned = cloneDeep__default.default(data);
  const decryptedData = decryptObject(cloned, decryptionKey);
  if (sops.sops.mac && sops.sops.lastmodified) ;
  return decryptedData;
}

// src/index.ts
async function decryptSops(inputOrOptions, options) {
  if (options && isSopsInput(inputOrOptions)) {
    const sopsData = await parseSops(inputOrOptions, options.fileType);
    return decrypt(sopsData, options);
  }
  if (inputOrOptions && typeof inputOrOptions === "object" && ("path" in inputOrOptions || "url" in inputOrOptions)) {
    const opts = inputOrOptions;
    let sopsData;
    if ("path" in opts) {
      sopsData = await loadSopsFile(opts.path, opts.fileType);
    } else {
      const response = await fetch(opts.url);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const content = await response.text();
      sopsData = await parseSops(content, opts.fileType);
    }
    const { fileType: _, ...decryptOptions } = opts;
    return decrypt(sopsData, decryptOptions);
  }
  if (inputOrOptions && isSopsInput(inputOrOptions)) {
    const sopsData = await parseSops(inputOrOptions);
    return decrypt(sopsData, {});
  }
  throw new Error(
    "Invalid options: when no input given, you must specify one of `path` or `url`"
  );
}
/*! Bundled license information:

@noble/curves/esm/abstract/utils.js:
@noble/curves/esm/abstract/modular.js:
@noble/curves/esm/abstract/montgomery.js:
@noble/curves/esm/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/

exports.decryptSops = decryptSops;
exports.findAllAgeKeys = findAllAgeKeys;
exports.sshKeyFileToAge = sshKeyFileToAge;
exports.sshKeyToAge = sshKeyToAge;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map