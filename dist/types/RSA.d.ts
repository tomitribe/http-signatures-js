export declare class RSA {
    private static RSA;
    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    static privateKeyFromPKCS8(pkcs8: ArrayBuffer | Uint8Array): Promise<any>;
    /**
     * Returns a private key constructed from the given DER bytes in PKCS#1 format.
     */
    static privateKeyFromPKCS1(pkcs1: ArrayBuffer | Uint8Array): Promise<any>;
    /**
     * Returns a public key constructed from the given DER bytes.
     */
    static publicKeyFrom(derBytes: ArrayBuffer | Uint8Array): Promise<any>;
}
