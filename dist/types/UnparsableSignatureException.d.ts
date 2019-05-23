import { AuthenticationException } from "./AuthenticationException";
export declare class UnparsableSignatureException extends AuthenticationException {
    constructor(message: string, cause: any);
}
