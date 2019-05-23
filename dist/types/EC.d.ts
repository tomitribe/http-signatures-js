export declare class EC {
    private static EC;
    private static SUNEC;
    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    static privateKeyFromPKCS8(pkcs8: ArrayBuffer | Uint8Array): Promise<any>;
    /**
     * Returns a public key constructed from the given DER bytes.
     */
    static publicKeyFrom(derBytes: ArrayBuffer | Uint8Array): Promise<any>;
}
