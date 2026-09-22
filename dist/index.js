import dotenv from 'dotenv';
import { parse as parse$1 } from 'yaml';
import { z } from 'zod';
import cloneDeep from 'lodash/cloneDeep.js';
import get from 'lodash/get.js';
import toPath from 'lodash/toPath.js';
import * as age from 'age-encryption';
import { gcm } from '@noble/ciphers/aes';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { sha512, sha256 } from '@noble/hashes/sha2';
import { bech32 } from '@scure/base';
import sshpk from 'sshpk';

// src/sops-file.ts

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
var AgeRecipientSchema = z.object({
  enc: z.string(),
  recipient: z.string()
});
var SopsSchema = z.object({
  sops: z.object({
    // age recipients; absent (null) when the file is encrypted only to
    // other master keys (e.g. AWS KMS) — decrypt those with `dataKey`.
    age: z.array(AgeRecipientSchema).nullable().optional(),
    lastmodified: z.string(),
    mac: z.string().optional(),
    unencrypted_suffix: z.string().optional(),
    version: z.string()
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
  return SopsSchema.parse(parse$1(yamlString));
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
  const parsedEnv = dotenv.parse(envString);
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
var X25519_PRIVATE_KEY_HRP = "AGE-SECRET-KEY-1";
async function getPublicAgeKey(privateAgeKey) {
  return age.identityToRecipient(privateAgeKey);
}
async function decryptAgeEncryptionKey(encryptedKey, secretKey) {
  const decoded = age.armor.decode(encryptedKey);
  const decrypter = new age.Decrypter();
  decrypter.addIdentity(secretKey);
  return decrypter.decrypt(decoded, "uint8array");
}
function decryptAesGcm(encryptedValue, key, additionalData) {
  const combined = new Uint8Array(
    encryptedValue.data.length + encryptedValue.tag.length
  );
  combined.set(encryptedValue.data);
  combined.set(encryptedValue.tag, encryptedValue.data.length);
  const aes = gcm(key, encryptedValue.iv, additionalData);
  return aes.decrypt(combined);
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
  const encoded = bech32.encode(
    "AGE-SECRET-KEY-",
    bech32.toWords(privateKeyBytes)
  );
  return encoded.toUpperCase();
}
function convertEd25519SeedToX25519PrivateKey(ed25519Seed) {
  if (ed25519Seed.length !== 32) {
    throw new Error("ed25519 seed must be 32 bytes.");
  }
  const hashedSeed = sha512(ed25519Seed);
  const x25519Sk = hashedSeed.slice(0, 32);
  return x25519Sk;
}
function convertRsaPublicKeyToX25519PrivateKey(rsaN, rsaE) {
  const hasher = sha256.create();
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
    const sshPk = sshpk.parsePrivateKey(keyFileContent, "auto", {
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
  const content = await readFile(filePath, "utf-8");
  return sshKeyToAge(content, filePath);
}

// src/age-key.ts
var execAsync = promisify(exec);
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
  if (platform() === "darwin") {
    const xdgConfigHome = process.env.XDG_CONFIG_HOME;
    if (xdgConfigHome && xdgConfigHome.trim() !== "") return xdgConfigHome;
  }
  switch (platform()) {
    case "win32":
      const appData = process.env.APPDATA;
      if (!appData) throw new Error("APPDATA env var not set");
      return appData;
    case "darwin":
      return join(homedir(), "Library", "Application Support");
    default:
      const xdgConfigHome = process.env.XDG_CONFIG_HOME;
      if (xdgConfigHome && xdgConfigHome.trim() !== "") return xdgConfigHome;
      return join(homedir(), ".config");
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
    const userHomeDir = homedir();
    if (userHomeDir) {
      const defaultSshPaths = [
        join(userHomeDir, ".ssh", "id_ed25519"),
        join(userHomeDir, ".ssh", "id_rsa")
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
      const content = await readFile(ageKeyFileEnv, "utf-8");
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
    const sopsKeysFilePath = join(
      userConfigDirPath,
      SOPS_AGE_KEY_USER_CONFIG_PATH
    );
    try {
      const content = await readFile(sopsKeysFilePath, "utf-8");
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
    const value = get(sops, keyPath);
    if (typeof value !== "string") {
      throw new Error(`Unable to get sops value at keyPath="${keyPath}"`);
    }
    return decryptSOPSValue(value, decryptionKey, toPath(keyPath));
  }
  const { sops: _, ...data } = sops;
  const cloned = cloneDeep(data);
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

export { decryptSops, findAllAgeKeys, sshKeyFileToAge, sshKeyToAge };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map