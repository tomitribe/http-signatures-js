/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import * as jwkJs from "jwk-js";
import { StringBuilder } from "ts-tomitribe-util";
import { EC } from "./EC";
import { RSA } from "./RSA";

export class BufferedReader {
    private str: string[];
    private cursor: number;

    constructor(str) {
        this.str = str.split(/\r?\n/);
        this.cursor = 0;
    }

    readline(cursor?): string | null {
        if (cursor) {
            this.cursor = cursor;
        }
        const res: string | null = this.str.length > this.cursor ? this.str[this.cursor] : null;
        this.cursor++;
        return res;
    }
}

export class PEM {
    static BEGIN_MARKER: string = "-----BEGIN ";

    public static readPrivateKey(is: string) {
        const objects: PEMObject[] = PEM.readPEMObjects(is);
        for (let object of objects) {
            switch (object.getPEMObjectType()) {
                case PEMObjectType.PRIVATE_KEY_PKCS:
                    return RSA.privateKeyFromPKCS1(object.getDerBytes());
                case PEMObjectType.PRIVATE_EC_KEY_PKCS8:
                    return EC.privateKeyFromPKCS8(object.getDerBytes());
                case PEMObjectType.PRIVATE_KEY_PKCS8:
                    try {
                        return RSA.privateKeyFromPKCS8(object.getDerBytes());
                    } catch (e) {
                        return EC.privateKeyFromPKCS8(object.getDerBytes());
                    }
                default:
                    break;
            }
        }
        throw new Error("Found no private key");
    }

    public static readPublicKey(is: string) {
        const objects: PEMObject[] = PEM.readPEMObjects(is);
        for (let object of objects) {
            switch (object.getPEMObjectType()) {
                case PEMObjectType.PUBLIC_KEY_X509:
                    try {
                        return RSA.publicKeyFrom(object.getDerBytes());
                    } catch (e) {
                        return EC.publicKeyFrom(object.getDerBytes());
                    }
                default:
                    break;
            }
        }
        throw new Error("Found no private key");
    }

    static readPEMObjects(is: string): PEMObject[] {
        let reader: BufferedReader = new BufferedReader(is);
        try {
            let pemContents: PEMObject[] = [];
            let readingContent: boolean = false;
            let beginMarker: string = "";
            let endMarker: string = "";
            let sb: StringBuilder = new StringBuilder();
            let line: string | null;
            while ((line = reader.readline()) != null) {
                {
                    if (readingContent) {
                        if (line.includes(endMarker)) {
                            pemContents.push(new PEMObject(beginMarker, jwkJs.s2AB(sb.toString())));
                            readingContent = false;
                        } else {
                            sb.append(<any>line.trim());
                        }
                    } else {
                        if (line.includes(PEM.BEGIN_MARKER)) {
                            readingContent = true;
                            beginMarker = line.trim();
                            endMarker = beginMarker.replace("BEGIN", "END");
                            sb = new StringBuilder();
                        }
                    }
                }
            }
            return pemContents;
        } finally {
            try {
            } catch (ignore) {
            }
        }
    }
}

export class PEMObject {
    private beginMarker: string;

    private derBytes: ArrayBuffer | Uint8Array;

    public constructor(beginMarker: string, derBytes: ArrayBuffer | Uint8Array) {
        this.beginMarker = beginMarker;
        this.derBytes = derBytes;
    }

    public getBeginMarker(): string {
        return this.beginMarker;
    }

    public getDerBytes(): ArrayBuffer | Uint8Array {
        return this.derBytes[0];
    }

    public getPEMObjectType(): PEMObjectType {
        return PEMObjectType.fromBeginMarker(this.beginMarker);
    }
}

export class PEMObjectType {
    public static PRIVATE_KEY_PKCS = new PEMObjectType("-----BEGIN RSA PRIVATE KEY-----");
    public static PRIVATE_EC_KEY_PKCS8 = new PEMObjectType("-----BEGIN EC PRIVATE KEY-----"); // RFC-5915
    public static PRIVATE_KEY_PKCS8 = new PEMObjectType("-----BEGIN PRIVATE KEY-----");
    public static PUBLIC_KEY_X509 = new PEMObjectType("-----BEGIN PUBLIC KEY-----");
    public static CERTIFICATE_X509 = new PEMObjectType("-----BEGIN CERTIFICATE-----");

    public static values: PEMObjectType[] = [];
    protected beginMarker: string;

    public getBeginMarker(): string {
        return this.beginMarker;
    }

    constructor(beginMarker: string) {
        this.beginMarker = beginMarker;
        PEMObjectType.values.push(this);
    }

    public static fromBeginMarker(beginMarker: string): PEMObjectType {
        return PEMObjectType.values.find(objType => objType.getBeginMarker() === beginMarker) as PEMObjectType;
    }
}

