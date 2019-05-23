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
import { UnsupportedAlgorithmException } from "./UnsupportedAlgorithmException";

export interface StringAlgorithmMap {
    [key: string]: Algorithm;
}

export class Algorithm {
    public static values: Algorithm[] = [];
    public static aliases: StringAlgorithmMap = {};

    public static HMAC_SHA1: Algorithm = new Algorithm("HmacSHA1", "hmac-sha1", "Mac.class");
    public static HMAC_SHA224: Algorithm = new Algorithm("HmacSHA224", "hmac-sha224", "Mac.class");
    public static HMAC_SHA256: Algorithm = new Algorithm("HmacSHA256", "hmac-sha256", "Mac.class");
    public static HMAC_SHA384: Algorithm = new Algorithm("HmacSHA384", "hmac-sha384", "Mac.class");
    public static HMAC_SHA512: Algorithm = new Algorithm("HmacSHA512", "hmac-sha512", "Mac.class");

    // rsa
    public static RSA_SHA1: Algorithm = new Algorithm("SHA1withRSA", "rsa-sha1", "java.security.Signature.class");
    public static RSA_SHA256: Algorithm = new Algorithm("SHA256withRSA", "rsa-sha256", "java.security.Signature.class");
    public static RSA_SHA384: Algorithm = new Algorithm("SHA384withRSA", "rsa-sha384", "java.security.Signature.class");
    public static RSA_SHA512: Algorithm = new Algorithm("SHA512withRSA", "rsa-sha512", "java.security.Signature.class");

    // dsa
    public static DSA_SHA1: Algorithm = new Algorithm("SHA1withDSA", "dsa-sha1", "java.security.Signature.class");
    public static DSA_SHA224: Algorithm = new Algorithm("SHA224withDSA", "dsa-sha224", "java.security.Signature.class");
    public static DSA_SHA256: Algorithm = new Algorithm("SHA256withDSA", "dsa-sha256", "java.security.Signature.class");

    // ecc
    public static ECDSA_SHA1: Algorithm = new Algorithm("SHA1withECDSA", "ecdsa-sha1", "java.security.Signature.class");
    public static ECDSA_SHA256: Algorithm = new Algorithm("SHA256withECDSA", "ecdsa-sha256", "java.security.Signature.class");
    public static ECDSA_SHA384: Algorithm = new Algorithm("SHA384withECDSA", "ecdsa-sha384", "java.security.Signature.class");
    public static ECDSA_SHA512: Algorithm = new Algorithm("SHA512withECDSA", "ecdsa-sha512", "java.security.Signature.class");

    private portableName: string;

    private jmvName: string;

    public type: any;

    public getPortableName(): string {
        return this.portableName;
    }

    public getJmvName(): string {
        return this.jmvName;
    }

    public getType(): any {
        return this.type;
    }

    public static getValues(): Algorithm[] {
        return Algorithm.values || [];
    }

    public static getAliases(): StringAlgorithmMap {
        return Algorithm.aliases || {};
    }
    public static toPortableName(name: string): string {
        return Algorithm.get(name).getPortableName();
    }

    public static toJvmName(name: string): string {
        return Algorithm.get(name).getJmvName();
    }

    public static get(name: string): Algorithm {
        let algorithm: Algorithm = Algorithm.getAliases()[Algorithm.normalize(name)];
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

        Algorithm.values.push(this);
        Algorithm.aliases[Algorithm.normalize(portableName)] = this;
        Algorithm.aliases[Algorithm.normalize(jmvName)] = this;
    }
}
