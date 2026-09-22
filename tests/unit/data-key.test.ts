import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decryptSops } from "../../src/index.js";

// tests/data/kms.enc.json was produced by `sops encrypt --kms <key>` (sops
// 3.13.3); its data key was unwrapped once with kms:Decrypt and recorded so
// this test needs no AWS. The plaintexts are dummies.
const DATA_KEY = Uint8Array.from(
  atob("dPWCsU2WoMxkt638wv7gCNNQriCEZWn/Tzb5O0NLC3o="),
  (c) => c.charCodeAt(0),
);
const fixture = () => readFile(join(__dirname, "../data/kms.enc.json"), "utf8");

describe("dataKey option", () => {
  it("decrypts a KMS-only file (age: null) with a supplied data key", async () => {
    const result = await decryptSops(await fixture(), {
      dataKey: DATA_KEY,
      fileType: "json",
    });
    expect(result).toEqual({
      api: { token: "kms-token", enabled: true, retries: 3, ratio: 0.5 },
      hosts: ["alpha", "beta"],
      nested: { deep: { value: "leaf" } },
      empty: "",
    });
  });

  it("supports keyPath together with dataKey", async () => {
    const value = await decryptSops(await fixture(), {
      dataKey: DATA_KEY,
      fileType: "json",
      keyPath: "nested.deep.value",
    });
    expect(value).toBe("leaf");
  });

  it("rejects a data key that is not 32 bytes", async () => {
    await expect(
      decryptSops(await fixture(), {
        dataKey: new Uint8Array(16),
        fileType: "json",
      }),
    ).rejects.toThrow(/32 bytes/);
  });

  it("explains what to do when a file has no age recipients and no dataKey", async () => {
    await expect(
      decryptSops(await fixture(), {
        secretKey:
          "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH",
        fileType: "json",
      }),
    ).rejects.toThrow(/no age recipients/);
  });

  it("ignores age keys when dataKey is given (wrong secretKey is fine)", async () => {
    const result = await decryptSops(await fixture(), {
      dataKey: DATA_KEY,
      secretKey:
        "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH",
      fileType: "json",
    });
    expect((result as { api: { token: string } }).api.token).toBe("kms-token");
  });
});
