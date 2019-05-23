export declare class BufferedReader {
    private str;
    private cursor;
    constructor(str: any);
    readline(cursor?: any): string | null;
}
export declare class PEM {
    static BEGIN_MARKER: string;
    static readPrivateKey(is: string): Promise<any>;
    static readPublicKey(is: string): Promise<any>;
    static readPEMObjects(is: string): PEMObject[];
}
export declare class PEMObject {
    private beginMarker;
    private derBytes;
    constructor(beginMarker: string, derBytes: ArrayBuffer | Uint8Array);
    getBeginMarker(): string;
    getDerBytes(): ArrayBuffer | Uint8Array;
    getPEMObjectType(): PEMObjectType;
}
export declare class PEMObjectType {
    static values: PEMObjectType[];
    static PRIVATE_KEY_PKCS: PEMObjectType;
    static PRIVATE_EC_KEY_PKCS8: PEMObjectType;
    static PRIVATE_KEY_PKCS8: PEMObjectType;
    static PUBLIC_KEY_X509: PEMObjectType;
    static CERTIFICATE_X509: PEMObjectType;
    protected beginMarker: string;
    getBeginMarker(): string;
    constructor(beginMarker: string);
    static fromBeginMarker(beginMarker: string): PEMObjectType;
}
