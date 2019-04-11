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

import jwkJs from "jwk-js";

export class RSA {
    private static RSA: string = "RSA";

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    public static privateKeyFromPKCS8(pkcs8: number[]){
        try {
            return jwkJs.RSA.JWKfromRSA(pkcs8, "private");
        } catch (e) {
            throw new Error(e);
        }
    }

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#1 format.
     */
    public static privateKeyFromPKCS1(pkcs1: number[]){
        try {
            return jwkJs.RSA.JWKfromRSA(pkcs1, "private");
        } catch (e) {
            throw new Error(e);
        }
    }

    /**
     * Returns a public key constructed from the given DER bytes.
     */
    public static publicKeyFrom(derBytes: number[]){
        try {
            return jwkJs.RSA.JWKfromRSA(derBytes, "public");
        } catch (e) {
            throw new Error(e);
        }
    }
}
