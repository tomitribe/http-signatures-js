import { Algorithm } from "./Algorithm";
import { AuthenticationException } from "./AuthenticationException";
import { Join } from "./Join";
import { MissingAlgorithmException } from "./MissingAlgorithmException";
import { MissingKeyIdException } from "./MissingKeyIdException";
import { MissingSignatureException } from "./MissingSignatureException";
import { UnparsableSignatureException } from "./UnparsableSignatureException";

interface Matcher {
    group: string[];
}

export class Signature {
    /**
     * REQUIRED.  The `keyId` field is an opaque string that the server can
     * use to look up the component they need to validate the signature.  It
     * could be an SSH key fingerprint, a URL to machine-readable key data,
     * an LDAP DN, etc.  Management of keys and assignment of `keyId` is out
     * of scope for this document.
     */
    private keyId: string;

    /**
     * REQUIRED.  The `algorithm` parameter is used to specify the digital
     * signature algorithm to use when generating the signature.  Valid
     * values for this parameter can be found in the Signature Algorithms
     * registry located at http://www.iana.org/assignments/signature-
     * algorithms and MUST NOT be marked "deprecated".
     */
    private algorithm: Algorithm;

    /**
     * OPTIONAL.  The `headers` parameter is used to specify the list of
     * HTTP headers included when generating the signature for the message.
     * If specified, it should be a lowercased, quoted list of HTTP header
     * fields, separated by a single space character.  If not specified,
     * implementations MUST operate as if the field were specified with a
     * single value, the `Date` header, in the list of HTTP headers.  Note
     * that the list order is important, and MUST be specified in the order
     * the HTTP header field-value pairs are concatenated together during
     * signing.
     */
    private signature: string;

    /**
     * REQUIRED.  The `signature` parameter is a base 64 encoded digital
     * signature, as described in RFC 4648 [RFC4648], Section 4 [4].  The
     * client uses the `algorithm` and `headers` signature parameters to
     * form a canonicalized `signing string`.  This `signing string` is then
     * signed with the key associated with `keyId` and the algorithm
     * corresponding to `algorithm`.  The `signature` parameter is then set
     * to the base 64 encoding of the signature.
     */
    private headers: Array<string> = ["date"];
    private static RFC_2617_PARAM = /(\\w+)=\"([^\"]*)\""/;

    public constructor(keyId?: any, algorithm?: any, signature?: any, ...headers: any[]) {
        if (keyId == null || /* isEmpty */(keyId.trim().length === 0)) {
            throw new Error("keyId is required.");
        }
        if (algorithm == null) {
            throw new Error("algorithm is required.");
        }
        this.keyId = keyId;
        this.algorithm = typeof algorithm === 'string' ? Signature.getAlgorithm(algorithm) : algorithm;
        this.signature = signature;

        if (headers.length !== 0) {
            if(headers[0] instanceof Array) {
                this.headers =this.lowercase(headers[0])
            } else {
                this.headers = this.lowercase(headers);
            }
        }

        this.headers = this.headers.slice(0); // unmodifiableList
    }

    private static getAlgorithm(algorithm: string): Algorithm {
        if (algorithm == null) throw new Error("Algorithm cannot be null");
        return Algorithm.get(algorithm);
    }

    private lowercase(headers: Array<string>): Array<string> {
        const list: Array<string> = <any>([]);
        for (let header in headers) {
            list.push(header.toLowerCase());
        }
        return list;
    }

    public getKeyId(): string {
        return this.keyId;
    }

    public getAlgorithm(): Algorithm {
        return this.algorithm;
    }

    public getSignature(): string {
        return this.signature;
    }

    public getHeaders(): Array<string> {
        return this.headers;
    }

    public static fromString(authorization: string): Signature | undefined {
        try {
            authorization = Signature.normalize(authorization);
            let map: any = <any>({});

            let matcher: Matcher = { group: [] };
            while ((matcher.group = this.RFC_2617_PARAM.exec(authorization) as Array<string>) !== null) {
                const key: string = matcher.group[1].toLowerCase();
                const value: string = matcher.group[2];
                map.put(key, value);
            }
            let headers: Array<string> = <any>([]);
            let headerString: string = /* get */((m, k) => m[k] === undefined ? null : m[k])(map, "headers");
            if (headerString != null) {
                /* addAll */
                ((l1, l2) => l1.push.apply(l1, l2))(headers, /* asList */headerString.toLowerCase().split(" +").slice(0));
            }
            let keyid: string = /* get */((m, k) => m[k] === undefined ? null : m[k])(map, "keyid");
            if (keyid == null) throw new MissingKeyIdException();
            let algorithm: string = /* get */((m, k) => m[k] === undefined ? null : m[k])(map, "algorithm");
            if (algorithm == null) throw new MissingAlgorithmException();
            let signature: string = /* get */((m, k) => m[k] === undefined ? null : m[k])(map, "signature");
            if (signature == null) throw new MissingSignatureException();
            let parsedAlgorithm: Algorithm = Algorithm.get(algorithm);
            return new Signature(keyid, parsedAlgorithm, signature, headers);
        } catch (__e) {
            if (__e != null && __e instanceof <any>AuthenticationException) {
                let e: AuthenticationException = <AuthenticationException>__e;
                throw e;
            } else if (__e != null && __e instanceof <any>Error) {
                let e: Error = <Error>__e;
                throw new UnparsableSignatureException(authorization, e);
            }
        }
    }

    /*private*/
    static normalize(authorization: string): string {
        let start: string = "signature ";
        let prefix: string = authorization.substring(0, start.length).toLowerCase();
        if (/* equals */(<any>((o1: any, o2: any) => {
            if (o1 && o1.equals) {
                return o1.equals(o2);
            } else {
                return o1 === o2;
            }
        })(prefix, start))) {
            authorization = authorization.substring(start.length);
        }
        return authorization.trim();
    }

    /**
     *
     * @return {string}
     */
    public toString(): string {
        return "Signature " + "keyId=\"" + this.keyId + '\"' +
            ",algorithm=\"" + this.algorithm + '\"' +
            ",headers=\"" + Join.join(" ", this.headers) + '\"' +
            ",signature=\"" + this.signature + '\"';
    }
}
