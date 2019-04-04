import { UnsupportedAlgorithmException } from "./UnsupportedAlgorithmException";

interface StringAlgorithmMap {
    [key: string]: Algorithm;
}

class Algorithm {
    HMAC_SHA1 = new Algorithm("HmacSHA1", "hmac-sha1", "Mac.class");
    HMAC_SHA224 = new Algorithm("HmacSHA224", "hmac-sha224", "Mac.class");
    HMAC_SHA256 = new Algorithm("HmacSHA256", "hmac-sha256", "Mac.class");
    HMAC_SHA384 = new Algorithm("HmacSHA384", "hmac-sha384", "Mac.class");
    HMAC_SHA512 = new Algorithm("HmacSHA512", "hmac-sha512", "Mac.class");

    // rsa
    RSA_SHA1 = new Algorithm("SHA1withRSA", "rsa-sha1", "java.security.Signature.class");
    RSA_SHA256 = new Algorithm("SHA256withRSA", "rsa-sha256", "java.security.Signature.class");
    RSA_SHA384 = new Algorithm("SHA384withRSA", "rsa-sha384", "java.security.Signature.class");
    RSA_SHA512 = new Algorithm("SHA512withRSA", "rsa-sha512", "java.security.Signature.class");

    // dsa
    DSA_SHA1 = new Algorithm("SHA1withDSA", "dsa-sha1", "java.security.Signature.class");
    DSA_SHA224 = new Algorithm("SHA224withDSA", "dsa-sha224", "java.security.Signature.class");
    DSA_SHA256 = new Algorithm("SHA256withDSA", "dsa-sha256", "java.security.Signature.class");

    // ecc
    ECDSA_SHA1 = new Algorithm("SHA1withECDSA", "ecdsa-sha1", "java.security.Signature.class");
    ECDSA_SHA256 = new Algorithm("SHA256withECDSA", "ecdsa-sha256", "java.security.Signature.class");
    ECDSA_SHA384 = new Algorithm("SHA384withECDSA", "ecdsa-sha384", "java.security.Signature.class");
    ECDSA_SHA512 = new Algorithm("SHA512withECDSA", "ecdsa-sha512", "java.security.Signature.class");

    private portableName: string;

    private jmvName: string;

    public type: any;

    public values: Algorithm[] = [];
    public aliases: StringAlgorithmMap = {};

    public getPortableName(): string {
        return this.portableName;
    }

    public getJmvName(): string {
        return this.jmvName;
    }

    public getType(): any {
        return this.type;
    }

    public getValues(): Algorithm[] {
        return Algorithm.prototype.values;
    }

    public static toPortableName(name: string): string {
        return Algorithm.get(name).getPortableName();
    }

    public static toJvmName(name: string): string {
        return Algorithm.get(name).getJmvName();
    }

    public static get(name: string): Algorithm {
        let algorithm: Algorithm = /* get */((m, k) => m[k] === undefined ? null : m[k])(Algorithm.prototype.getValues(), Algorithm.normalize(name));
        if (algorithm != null) return algorithm;
        throw new UnsupportedAlgorithmException(name);
    }

    private static normalize(algorithm: string): string {
        //replaceAll
        return algorithm.replace(new RegExp("[^A-Za-z0-9]+", 'g'), "").toLowerCase();
    }

    /**
     *
     * @return {string}
     */
    public toString(): string {
        return this.getPortableName();
    }

    constructor(portableName: string, jmvName: string, type: any) {
        this.portableName = portableName;
        this.jmvName = jmvName;
        this.type = type;
        Algorithm.prototype.values.push(this);
        Algorithm.prototype.aliases[Algorithm.normalize(portableName)] = this;
        Algorithm.prototype.aliases[Algorithm.normalize(jmvName)] = this;
    }
}

export { Algorithm, StringAlgorithmMap }
