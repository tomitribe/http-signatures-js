import { AuthenticationException } from "./AuthenticationException";
export declare class MissingRequiredHeaderException extends AuthenticationException {
    constructor(key: string);
}
