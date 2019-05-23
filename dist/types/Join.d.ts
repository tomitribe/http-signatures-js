import { Collection } from "./Collection";
export declare class Join {
    static join(delimiter: string, ...collection: (Collection | string)[]): string;
}
