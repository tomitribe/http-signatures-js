export interface StringMap {
    [key: string]: string;
}
export declare class Signatures {
    static createSigningString(required: Array<string>, method: string, uri: string, headers: StringMap): string;
    private static lowercase$;
    private static lowercase;
}
