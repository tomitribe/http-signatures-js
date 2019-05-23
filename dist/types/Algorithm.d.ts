export interface StringAlgorithmMap {
    [key: string]: Algorithm;
}
export declare class Algorithm {
    static values: Algorithm[];
    static aliases: StringAlgorithmMap;
    static HMAC_SHA1: Algorithm;
    static HMAC_SHA224: Algorithm;
    static HMAC_SHA256: Algorithm;
    static HMAC_SHA384: Algorithm;
    static HMAC_SHA512: Algorithm;
    static RSA_SHA1: Algorithm;
    static RSA_SHA256: Algorithm;
    static RSA_SHA384: Algorithm;
    static RSA_SHA512: Algorithm;
    static DSA_SHA1: Algorithm;
    static DSA_SHA224: Algorithm;
    static DSA_SHA256: Algorithm;
    static ECDSA_SHA1: Algorithm;
    static ECDSA_SHA256: Algorithm;
    static ECDSA_SHA384: Algorithm;
    static ECDSA_SHA512: Algorithm;
    private portableName;
    private jmvName;
    type: any;
    getPortableName(): string;
    getJmvName(): string;
    getType(): any;
    static getValues(): Algorithm[];
    static getAliases(): StringAlgorithmMap;
    static toPortableName(name: string): string;
    static toJvmName(name: string): string;
    static get(name: string): Algorithm;
    private static normalize;
    /**
     *
     * @return {string}
     */
    toString(): string;
    constructor(portableName: string, jmvName: string, type: any);
}
