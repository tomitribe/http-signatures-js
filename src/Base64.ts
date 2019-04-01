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

import { System } from "./System";

export class Base64 {
    /**
     * Chunk size per RFC 2045 section 6.8.
     *
     * <p>The {@value} character limit does not count the trailing CRLF, but counts
     * all other characters, including any equal signs.</p>
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 6.8</a>
     */
    static CHUNK_SIZE: number = 76;

    /**
     * Chunk separator per RFC 2045 section 2.1.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 2.1</a>
     */
    static CHUNK_SEPARATOR: number[] = ("\r\n").split('').map(s => s.charCodeAt(0));

    /**
     * The base length.
     */
    static BASELENGTH: number = 255;

    /**
     * Lookup length.
     */
    static LOOKUPLENGTH: number = 64;

    /**
     * Used to calculate the number of bits in a byte.
     */
    static EIGHTBIT: number = 8;

    /**
     * Used when encoding something which has fewer than 24 bits.
     */
    static SIXTEENBIT: number = 16;

    /**
     * Used to determine how many bits data contains.
     */
    static TWENTYFOURBITGROUP: number = 24;

    /**
     * Used to get the number of Quadruples.
     */
    static FOURBYTE: number = 4;

    /**
     * Used to test the sign of a byte.
     */
    static SIGN: number = -128;

    /**
     * Byte used to pad output.
     */
    static PAD: number = ('=').charCodeAt(0);

    /**
     * Contains the Base64 values <code>0</code> through <code>63</code> accessed by using character encodings as
     * indices.
     * <p>
     * For example, <code>base64Alphabet['+']</code> returns <code>62</code>.
     * </p>
     * <p>
     * The value of undefined encodings is <code>-1</code>.
     * </p>
     */
    static get base64Alphabet(): number[] {
        const base64Alphabet: number[] = [];
        for (let i: number = 0; i < Base64.BASELENGTH; i++)
            base64Alphabet[i] = (-1 | 0) as number;

        for (let i: number = ('Z').charCodeAt(0); i >= 'A'.charCodeAt(0); i--)
            base64Alphabet[i] = ((i - 'A'.charCodeAt(0)) | 0) as number;

        for (let i: number = ('z').charCodeAt(0); i >= 'a'.charCodeAt(0); i--)
            base64Alphabet[i] = ((i - 'a'.charCodeAt(0) + 26) | 0) as number;

        for (let i: number = ('9').charCodeAt(0); i >= '0'.charCodeAt(0); i--)
            base64Alphabet[i] = ((i - '0'.charCodeAt(0) + 52) | 0) as number;

        base64Alphabet[('+').charCodeAt(0)] = 62;
        base64Alphabet[('/').charCodeAt(0)] = 63;
        return base64Alphabet;
    }

    /**
     * <p>
     * Contains the Base64 encodings <code>A</code> through <code>Z</code>, followed by <code>a</code> through
     * <code>z</code>, followed by <code>0</code> through <code>9</code>, followed by <code>+</code>, and
     * <code>/</code>.
     * </p>
     * <p>
     * This array is accessed by using character values as indices.
     * </p>
     * <p>
     * For example, <code>lookUpBase64Alphabet[62] </code> returns <code>'+'</code>.
     * </p>
     */
    static get lookUpBase64Alphabet(): number[] {
        const lookUpBase64Alphabet: number[] = [];
        for (let i: number = 0; i <= 25; i++)
            lookUpBase64Alphabet[i] = ('A'.charCodeAt(0) + i) | 0 as number;

        for (let i: number = 26, j: number = 0; i <= 51; i++, j++)
            lookUpBase64Alphabet[i] = ('a'.charCodeAt(0) + j) | 0 as number;

        for (let i: number = 52, j: number = 0; i <= 61; i++, j++)
            lookUpBase64Alphabet[i] = ('0'.charCodeAt(0) + j) | 0 as number;

        lookUpBase64Alphabet[62] = ('+').charCodeAt(0);
        lookUpBase64Alphabet[63] = ('/').charCodeAt(0);
        return lookUpBase64Alphabet
    }

    /**
     * Returns whether or not the <code>octect</code> is in the base 64 alphabet.
     *
     * @param {number} octect The value to test
     * @return {boolean} <code>true</code> if the value is defined in the the base 64 alphabet, <code>false</code> otherwise.
     * @private
     */
    private static isBase64(octect: number): boolean {
        if (octect === Base64.PAD) {
            return true;
        } else if (octect < 0 || Base64.base64Alphabet[octect] === -1) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Encodes binary data using the base64 algorithm, optionally
     * chunking the output into 76 character blocks.
     *
     * @param {Array} binaryData Array containing binary data to encode.
     * @param {boolean} isChunked if <code>true</code> this encoder will chunk
     * the base64 output into 76 character blocks
     * @return {Array} Base64-encoded data.
     */
    public static encodeBase64(binaryData: number[], isChunked: boolean = false): number[] {
        let lengthDataBits: number = binaryData.length * Base64.EIGHTBIT;
        let fewerThan24bits: number = lengthDataBits % Base64.TWENTYFOURBITGROUP;
        let numberTriplets: number = (lengthDataBits / Base64.TWENTYFOURBITGROUP | 0);
        let encodedData: number[];
        let encodedDataLength: number = 0;
        let nbrChunks: number = 0;
        if (fewerThan24bits !== 0) {
            encodedDataLength = (numberTriplets + 1) * 4;
        } else {
            encodedDataLength = numberTriplets * 4;
        }
        if (isChunked) {
            nbrChunks = (Base64.CHUNK_SEPARATOR.length === 0 ? 0 : (<number>Math.ceil(<number>encodedDataLength / Base64.CHUNK_SIZE) | 0));
            encodedDataLength += nbrChunks * Base64.CHUNK_SEPARATOR.length;
        }
        encodedData = [];
        let k: number = 0;
        let l: number = 0;
        let b1: number = 0;
        let b2: number = 0;
        let b3: number = 0;
        let encodedIndex: number = 0;
        let dataIndex: number = 0;
        let i: number;
        let nextSeparatorIndex: number = Base64.CHUNK_SIZE;
        let chunksSoFar: number = 0;
        for (i = 0; i < numberTriplets; i++) {
            {
                dataIndex = i * 3;
                b1 = binaryData[dataIndex];
                b2 = binaryData[dataIndex + 1];
                b3 = binaryData[dataIndex + 2];
                l = (<number>(b2 & 15) | 0);
                k = (<number>(b1 & 3) | 0);
                let val1: number = ((b1 & Base64.SIGN) === 0) ? (<number>(b1 >> 2) | 0) : (<number>((b1) >> 2 ^ 192) | 0);
                let val2: number = ((b2 & Base64.SIGN) === 0) ? (<number>(b2 >> 4) | 0) : (<number>((b2) >> 4 ^ 240) | 0);
                let val3: number = ((b3 & Base64.SIGN) === 0) ? (<number>(b3 >> 6) | 0) : (<number>((b3) >> 6 ^ 252) | 0);
                encodedData[encodedIndex] = Base64.lookUpBase64Alphabet[val1];
                encodedData[encodedIndex + 1] = Base64.lookUpBase64Alphabet[val2 | (k << 4)];
                encodedData[encodedIndex + 2] = Base64.lookUpBase64Alphabet[(l << 2) | val3];
                encodedData[encodedIndex + 3] = Base64.lookUpBase64Alphabet[b3 & 63];
                encodedIndex += 4;
                if (isChunked) {
                    if (encodedIndex === nextSeparatorIndex) {
                        System.arraycopy(Base64.CHUNK_SEPARATOR, 0, encodedData, encodedIndex, Base64.CHUNK_SEPARATOR.length);
                        chunksSoFar++;
                        nextSeparatorIndex = (Base64.CHUNK_SIZE * (chunksSoFar + 1)) + (chunksSoFar * Base64.CHUNK_SEPARATOR.length);
                        encodedIndex += Base64.CHUNK_SEPARATOR.length;
                    }
                }
            }
        }
        dataIndex = i * 3;
        if (fewerThan24bits === Base64.EIGHTBIT) {
            b1 = binaryData[dataIndex];
            k = (<number>(b1 & 3) | 0);
            let val1: number = ((b1 & Base64.SIGN) === 0) ? (<number>(b1 >> 2) | 0) : (<number>((b1) >> 2 ^ 192) | 0);
            encodedData[encodedIndex] = Base64.lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = Base64.lookUpBase64Alphabet[k << 4];
            encodedData[encodedIndex + 2] = Base64.PAD;
            encodedData[encodedIndex + 3] = Base64.PAD;
        } else if (fewerThan24bits === Base64.SIXTEENBIT) {
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            l = (<number>(b2 & 15) | 0);
            k = (<number>(b1 & 3) | 0);
            let val1: number = ((b1 & Base64.SIGN) === 0) ? (<number>(b1 >> 2) | 0) : (<number>((b1) >> 2 ^ 192) | 0);
            let val2: number = ((b2 & Base64.SIGN) === 0) ? (<number>(b2 >> 4) | 0) : (<number>((b2) >> 4 ^ 240) | 0);
            encodedData[encodedIndex] = Base64.lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = Base64.lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = Base64.lookUpBase64Alphabet[l << 2];
            encodedData[encodedIndex + 3] = Base64.PAD;
        }
        if (isChunked) {
            if (chunksSoFar < nbrChunks) {
                System.arraycopy(Base64.CHUNK_SEPARATOR, 0, encodedData, encodedDataLength - Base64.CHUNK_SEPARATOR.length, Base64.CHUNK_SEPARATOR.length);
            }
        }
        return encodedData;
    }

    /**
     * Decodes Base64 data into octects
     *
     * @param {Array} base64Data Byte array containing Base64 data
     * @return {Array} Array containing decoded data.
     */
    public static decodeBase64(base64Data: number[]): number[] {
        base64Data = Base64.discardNonBase64(base64Data);
        if (base64Data.length === 0) {
            return [];
        }
        let numberQuadruple: number = (base64Data.length / Base64.FOURBYTE | 0);
        let decodedData: number[];
        let b1: number = 0;
        let b2: number = 0;
        let b3: number = 0;
        let b4: number = 0;
        let marker0: number = 0;
        let marker1: number = 0;
        let encodedIndex: number = 0;
        let dataIndex: number = 0;
        {
            let lastData: number = base64Data.length;
            while ((base64Data[lastData - 1] === Base64.PAD)) {
                {
                    if (--lastData === 0) {
                        return [];
                    }
                }
            }
            decodedData = [];
        }
        for (let i: number = 0; i < numberQuadruple; i++) {
            {
                dataIndex = i * 4;
                marker0 = base64Data[dataIndex + 2];
                marker1 = base64Data[dataIndex + 3];
                b1 = Base64.base64Alphabet[base64Data[dataIndex]];
                b2 = Base64.base64Alphabet[base64Data[dataIndex + 1]];
                if (marker0 !== Base64.PAD && marker1 !== Base64.PAD) {
                    b3 = Base64.base64Alphabet[marker0];
                    b4 = Base64.base64Alphabet[marker1];
                    decodedData[encodedIndex] = (<number>(b1 << 2 | b2 >> 4) | 0);
                    decodedData[encodedIndex + 1] = (<number>(((b2 & 15) << 4) | ((b3 >> 2) & 15)) | 0);
                    decodedData[encodedIndex + 2] = (<number>(b3 << 6 | b4) | 0);
                } else if (marker0 === Base64.PAD) {
                    decodedData[encodedIndex] = (<number>(b1 << 2 | b2 >> 4) | 0);
                } else if (marker1 === Base64.PAD) {
                    b3 = Base64.base64Alphabet[marker0];
                    decodedData[encodedIndex] = (<number>(b1 << 2 | b2 >> 4) | 0);
                    decodedData[encodedIndex + 1] = (<number>(((b2 & 15) << 4) | ((b3 >> 2) & 15)) | 0);
                }
                encodedIndex += 3;
            }
        }
        return decodedData;
    }

    /**
     * Discards any characters outside of the base64 alphabet, per
     * the requirements on page 25 of RFC 2045 - "Any characters
     * outside of the base64 alphabet are to be ignored in base64
     * encoded data."
     *
     * @param {Array} data The base-64 encoded data to groom
     * @return {Array} The data, less non-base64 characters (see RFC 2045).
     */
    static discardNonBase64(data: number[]): number[] {
        let groomedData: number[] = [];
        let bytesCopied: number = 0;
        for (let i: number = 0; i < data.length; i++) {
            {
                if (Base64.isBase64(data[i])) {
                    groomedData[bytesCopied++] = data[i];
                }
            }
        }
        let packedData: number[] = [];
        System.arraycopy(groomedData, 0, packedData, 0, bytesCopied);
        return packedData;
    }
}
