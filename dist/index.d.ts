type SopsInput = object | string | File | Blob | ArrayBufferLike | Uint8Array | Buffer | ReadableStream<Uint8Array>;
type SopsFileType = "env" | "json" | "yaml";

/**
 * Options for decrypting SOPS encrypted data
 */
interface DecryptOptions {
    /**
     * A path to a specific key in the SOPS file to decrypt.
     * See https://lodash.com/docs/#get for format
     */
    keyPath?: string;
    secretKey?: string;
    /**
     * An already-unwrapped SOPS data key (32 bytes). Use this when the file's
     * data key is protected by a master key other than age — for example
     * `sops.kms[].enc` unwrapped with `kms:Decrypt` — and only the value
     * decryption (AES-256-GCM with path-bound additional data) is needed.
     * When set, no age keys are looked up and `secretKey` is ignored.
     */
    dataKey?: Uint8Array;
}

/**
 * Finds all age secret keys (X25519 strings) according to SOPS rules, see:
 * https://github.com/getsops/sops?tab=readme-ov-file#encrypting-using-age
 *
 * - Converts SSH keys (Ed25519, RSA) to X25519 format using either
 * SOPS_AGE_SSH_PRIVATE_KEY_FILE or .ssh/id_ed25519, .ssh/id_rsa.
 *
 * - Uses SOPS_AGE_KEY or SOPS_AGE_KEY_FILE or SOPS_AGE_KEY_CMD to get an
 * age key or keys.
 *
 * - Looks in the sops/age/keys.txt config dir for age keys.
 */
declare function findAllAgeKeys(): Promise<string[]>;

/**
 * Parses SSH private key content, converts to an X25519 Bech32 private key string.
 * Returns the Bech32 string or null if the key is unsupported or file is empty.
 * Throws an error if parsing/conversion fails for a supported type.
 */
declare function sshKeyToAge(keyFileContent: string, filePathForErrorMsg?: string): string | null;
/**
 * Reads an SSH private key file, parses, and converts to age (X25519 Bech32 string).
 */
declare function sshKeyFileToAge(filePath: string): Promise<string | null>;

/**
 * Options for decrypting SOPS data, extending base decrypt options with an optional file type.
 */
interface DecryptSopsOptions extends DecryptOptions {
    /**
     * The type of SOPS file being decrypted ('env', 'json', or 'yaml').
     * If not provided, the type will be auto-detected.
     */
    fileType?: SopsFileType;
}
/**
 * Options for decrypting a SOPS file from the local filesystem.
 */
interface DecryptSopsFileOptions extends DecryptSopsOptions {
    /** Path to the SOPS encrypted file */
    path: string;
}
/**
 * Options for decrypting a SOPS file from a URL.
 */
interface DecryptSopsUrlOptions extends DecryptSopsOptions {
    /** URL of the SOPS encrypted file */
    url: string | URL;
}
/**
 * Decrypts SOPS-encrypted data from various sources.
 *
 * @param input - The SOPS-encrypted content to decrypt (i.e., contents of SOPS file)
 * @param options - Options for decryption including secret key and file type
 * @returns The decrypted data
 *
 * @example
 * // Decrypt from string content
 * const decrypted = await decryptSops(jsonString, {
 *   secretKey: AGE_SECRET_KEY,
 *   fileType: "json"
 * });
 */
declare function decryptSops(input: SopsInput, options?: DecryptSopsOptions): Promise<any>;
/**
 * Decrypts a SOPS-encrypted file from the local filesystem.
 *
 * @param options - Options including file path and decryption settings
 * @returns The decrypted data
 *
 * @example
 * // Decrypt from local file
 * const decrypted = await decryptSops({
 *   path: "/secrets/config.enc.json",
 *   secretKey: AGE_SECRET_KEY
 * });
 */
declare function decryptSops(options: DecryptSopsFileOptions): Promise<any>;
/**
 * Decrypts a SOPS-encrypted file from a URL.
 *
 * @param options - Options including URL and decryption settings
 * @returns The decrypted data
 *
 * @example
 * // Decrypt from URL
 * const decrypted = await decryptSops({
 *   url: "https://example.com/config.enc.json",
 *   secretKey: AGE_SECRET_KEY
 * });
 */
declare function decryptSops(options: DecryptSopsUrlOptions): Promise<any>;

export { type DecryptSopsFileOptions, type DecryptSopsOptions, type DecryptSopsUrlOptions, type SopsFileType, type SopsInput, decryptSops, findAllAgeKeys, sshKeyFileToAge, sshKeyToAge };
