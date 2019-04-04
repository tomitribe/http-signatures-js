import { Join } from "./Join";
import { MissingRequiredHeaderException } from "./MissingRequiredHeaderException";

interface StringMap {
    [key: string]: string;
}

class Signatures {
    public static createSigningString(required: Array<string>, method: string, uri: string, headers: StringMap): string {
        headers = Signatures.lowercase(headers) as StringMap;
        let list: string[] = [];
        for (let key of required) {
            if ("(request-target)" === key) {
                method = Signatures.lowercase(method) as string;
                list.push(Join.join(" ", "(request-target):", method, uri));
            } else {
                let value: string = headers[key];
                if (value == null) throw new MissingRequiredHeaderException(key);
                list.push(key + ": " + value);
            }
        }
        return Join.join("\n", list);
    }

    private static lowercase$(headers: StringMap): StringMap {
        return Object.keys(headers).reduce(function (newObj, key) {
            const val = headers[key];
            newObj[key.toLowerCase()] = (typeof val === 'object') ? Signatures.lowercase$(val) : val;
            return newObj;
        }, {});
    }

    private static lowercase(headers: (string | StringMap)): (string | StringMap) {
        if (typeof headers === 'string') {
            return headers.toLowerCase() as string;
        } else {
            return Signatures.lowercase$(headers) as StringMap;
        }
    }
}
