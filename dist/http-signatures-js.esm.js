import crypto from 'crypto';

/*! *****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

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
var RuntimeException = /** @class */ (function (_super) {
    __extends(RuntimeException, _super);
    function RuntimeException(message, cause) {
        var _this = _super.call(this, message) || this;
        _this.cause = cause;
        return _this;
    }
    return RuntimeException;
}(Error));

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
var AuthenticationException = /** @class */ (function (_super) {
    __extends(AuthenticationException, _super);
    function AuthenticationException(message, cause) {
        return _super.call(this, message, cause) || this;
    }
    return AuthenticationException;
}(RuntimeException));

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
var UnsupportedAlgorithmException = /** @class */ (function (_super) {
    __extends(UnsupportedAlgorithmException, _super);
    function UnsupportedAlgorithmException(message, cause) {
        return _super.call(this, message, cause) || this;
    }
    return UnsupportedAlgorithmException;
}(AuthenticationException));

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
var Algorithm = /** @class */ (function () {
    function Algorithm(portableName, jmvName, type) {
        this.portableName = portableName;
        this.jmvName = jmvName;
        this.type = type;
        Algorithm.values.push(this);
        Algorithm.aliases[Algorithm.normalize(portableName)] = this;
        Algorithm.aliases[Algorithm.normalize(jmvName)] = this;
    }
    Algorithm.prototype.getPortableName = function () {
        return this.portableName;
    };
    Algorithm.prototype.getJmvName = function () {
        return this.jmvName;
    };
    Algorithm.prototype.getType = function () {
        return this.type;
    };
    Algorithm.getValues = function () {
        return Algorithm.values || [];
    };
    Algorithm.getAliases = function () {
        return Algorithm.aliases || {};
    };
    Algorithm.toPortableName = function (name) {
        return Algorithm.get(name).getPortableName();
    };
    Algorithm.toJvmName = function (name) {
        return Algorithm.get(name).getJmvName();
    };
    Algorithm.get = function (name) {
        var algorithm = Algorithm.getAliases()[Algorithm.normalize(name)];
        if (algorithm != null)
            return algorithm;
        throw new UnsupportedAlgorithmException(name);
    };
    Algorithm.normalize = function (algorithm) {
        //replaceAll
        return algorithm.replace(new RegExp("[^A-Za-z0-9]+", 'g'), "").toLowerCase();
    };
    /**
     *
     * @return {string}
     */
    Algorithm.prototype.toString = function () {
        return this.getPortableName();
    };
    Algorithm.values = [];
    Algorithm.aliases = {};
    Algorithm.HMAC_SHA1 = new Algorithm("HmacSHA1", "hmac-sha1", "Mac.class");
    Algorithm.HMAC_SHA224 = new Algorithm("HmacSHA224", "hmac-sha224", "Mac.class");
    Algorithm.HMAC_SHA256 = new Algorithm("HmacSHA256", "hmac-sha256", "Mac.class");
    Algorithm.HMAC_SHA384 = new Algorithm("HmacSHA384", "hmac-sha384", "Mac.class");
    Algorithm.HMAC_SHA512 = new Algorithm("HmacSHA512", "hmac-sha512", "Mac.class");
    // rsa
    Algorithm.RSA_SHA1 = new Algorithm("SHA1withRSA", "rsa-sha1", "java.security.Signature.class");
    Algorithm.RSA_SHA256 = new Algorithm("SHA256withRSA", "rsa-sha256", "java.security.Signature.class");
    Algorithm.RSA_SHA384 = new Algorithm("SHA384withRSA", "rsa-sha384", "java.security.Signature.class");
    Algorithm.RSA_SHA512 = new Algorithm("SHA512withRSA", "rsa-sha512", "java.security.Signature.class");
    // dsa
    Algorithm.DSA_SHA1 = new Algorithm("SHA1withDSA", "dsa-sha1", "java.security.Signature.class");
    Algorithm.DSA_SHA224 = new Algorithm("SHA224withDSA", "dsa-sha224", "java.security.Signature.class");
    Algorithm.DSA_SHA256 = new Algorithm("SHA256withDSA", "dsa-sha256", "java.security.Signature.class");
    // ecc
    Algorithm.ECDSA_SHA1 = new Algorithm("SHA1withECDSA", "ecdsa-sha1", "java.security.Signature.class");
    Algorithm.ECDSA_SHA256 = new Algorithm("SHA256withECDSA", "ecdsa-sha256", "java.security.Signature.class");
    Algorithm.ECDSA_SHA384 = new Algorithm("SHA384withECDSA", "ecdsa-sha384", "java.security.Signature.class");
    Algorithm.ECDSA_SHA512 = new Algorithm("SHA512withECDSA", "ecdsa-sha512", "java.security.Signature.class");
    return Algorithm;
}());

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
var System = /** @class */ (function () {
    function System() {
    }
    System.arraycopy = function (srcArr, srcOff, destArr, dstOff, size) {
        if (srcArr !== destArr || dstOff >= srcOff + size) {
            while (--size >= 0)
                destArr[dstOff++] = srcArr[srcOff++];
        }
        else {
            var tmp = srcArr.slice(srcOff, srcOff + size);
            for (var i = 0; i < size; i++)
                destArr[dstOff++] = tmp[i];
        }
    };
    return System;
}());

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
var Base64 = /** @class */ (function () {
    function Base64() {
    }
    Object.defineProperty(Base64, "base64Alphabet", {
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
        get: function () {
            var base64Alphabet = [];
            for (var i = 0; i < Base64.BASELENGTH; i++)
                base64Alphabet[i] = (-1 | 0);
            for (var i = ('Z').charCodeAt(0); i >= 'A'.charCodeAt(0); i--)
                base64Alphabet[i] = ((i - 'A'.charCodeAt(0)) | 0);
            for (var i = ('z').charCodeAt(0); i >= 'a'.charCodeAt(0); i--)
                base64Alphabet[i] = ((i - 'a'.charCodeAt(0) + 26) | 0);
            for (var i = ('9').charCodeAt(0); i >= '0'.charCodeAt(0); i--)
                base64Alphabet[i] = ((i - '0'.charCodeAt(0) + 52) | 0);
            base64Alphabet[('+').charCodeAt(0)] = 62;
            base64Alphabet[('/').charCodeAt(0)] = 63;
            return base64Alphabet;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Base64, "lookUpBase64Alphabet", {
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
        get: function () {
            var lookUpBase64Alphabet = [];
            for (var i = 0; i <= 25; i++)
                lookUpBase64Alphabet[i] = ('A'.charCodeAt(0) + i) | 0;
            for (var i = 26, j = 0; i <= 51; i++, j++)
                lookUpBase64Alphabet[i] = ('a'.charCodeAt(0) + j) | 0;
            for (var i = 52, j = 0; i <= 61; i++, j++)
                lookUpBase64Alphabet[i] = ('0'.charCodeAt(0) + j) | 0;
            lookUpBase64Alphabet[62] = ('+').charCodeAt(0);
            lookUpBase64Alphabet[63] = ('/').charCodeAt(0);
            return lookUpBase64Alphabet;
        },
        enumerable: true,
        configurable: true
    });
    /**
     * Returns whether or not the <code>octect</code> is in the base 64 alphabet.
     *
     * @param {number} octect The value to test
     * @return {boolean} <code>true</code> if the value is defined in the the base 64 alphabet, <code>false</code> otherwise.
     * @private
     */
    Base64.isBase64 = function (octect) {
        if (octect === Base64.PAD) {
            return true;
        }
        else if (octect < 0 || Base64.base64Alphabet[octect] === -1) {
            return false;
        }
        else {
            return true;
        }
    };
    /**
     * Encodes binary data using the base64 algorithm, optionally
     * chunking the output into 76 character blocks.
     *
     * @param {Array} binaryData Array containing binary data to encode.
     * @param {boolean} isChunked if <code>true</code> this encoder will chunk
     * the base64 output into 76 character blocks
     * @return {Array} Base64-encoded data.
     */
    Base64.encodeBase64 = function (binaryData, isChunked) {
        if (isChunked === void 0) { isChunked = false; }
        var lengthDataBits = binaryData.length * Base64.EIGHTBIT;
        var fewerThan24bits = lengthDataBits % Base64.TWENTYFOURBITGROUP;
        var numberTriplets = (lengthDataBits / Base64.TWENTYFOURBITGROUP | 0);
        var encodedData;
        var encodedDataLength = 0;
        var nbrChunks = 0;
        if (fewerThan24bits !== 0) {
            encodedDataLength = (numberTriplets + 1) * 4;
        }
        else {
            encodedDataLength = numberTriplets * 4;
        }
        if (isChunked) {
            nbrChunks = (Base64.CHUNK_SEPARATOR.length === 0 ? 0 : (Math.ceil(encodedDataLength / Base64.CHUNK_SIZE) | 0));
            encodedDataLength += nbrChunks * Base64.CHUNK_SEPARATOR.length;
        }
        encodedData = [];
        var k = 0;
        var l = 0;
        var b1 = 0;
        var b2 = 0;
        var b3 = 0;
        var encodedIndex = 0;
        var dataIndex = 0;
        var i;
        var nextSeparatorIndex = Base64.CHUNK_SIZE;
        var chunksSoFar = 0;
        for (i = 0; i < numberTriplets; i++) {
            {
                dataIndex = i * 3;
                b1 = binaryData[dataIndex];
                b2 = binaryData[dataIndex + 1];
                b3 = binaryData[dataIndex + 2];
                l = ((b2 & 15) | 0);
                k = ((b1 & 3) | 0);
                var val1 = ((b1 & Base64.SIGN) === 0) ? ((b1 >> 2) | 0) : (((b1) >> 2 ^ 192) | 0);
                var val2 = ((b2 & Base64.SIGN) === 0) ? ((b2 >> 4) | 0) : (((b2) >> 4 ^ 240) | 0);
                var val3 = ((b3 & Base64.SIGN) === 0) ? ((b3 >> 6) | 0) : (((b3) >> 6 ^ 252) | 0);
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
            k = ((b1 & 3) | 0);
            var val1 = ((b1 & Base64.SIGN) === 0) ? ((b1 >> 2) | 0) : (((b1) >> 2 ^ 192) | 0);
            encodedData[encodedIndex] = Base64.lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = Base64.lookUpBase64Alphabet[k << 4];
            encodedData[encodedIndex + 2] = Base64.PAD;
            encodedData[encodedIndex + 3] = Base64.PAD;
        }
        else if (fewerThan24bits === Base64.SIXTEENBIT) {
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            l = ((b2 & 15) | 0);
            k = ((b1 & 3) | 0);
            var val1 = ((b1 & Base64.SIGN) === 0) ? ((b1 >> 2) | 0) : (((b1) >> 2 ^ 192) | 0);
            var val2 = ((b2 & Base64.SIGN) === 0) ? ((b2 >> 4) | 0) : (((b2) >> 4 ^ 240) | 0);
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
    };
    /**
     * Decodes Base64 data into octects
     *
     * @param {Array} base64Data Byte array containing Base64 data
     * @return {Array} Array containing decoded data.
     */
    Base64.decodeBase64 = function (base64Data) {
        base64Data = Base64.discardNonBase64(base64Data);
        if (base64Data.length === 0) {
            return [];
        }
        var numberQuadruple = (base64Data.length / Base64.FOURBYTE | 0);
        var decodedData;
        var b1 = 0;
        var b2 = 0;
        var b3 = 0;
        var b4 = 0;
        var marker0 = 0;
        var marker1 = 0;
        var encodedIndex = 0;
        var dataIndex = 0;
        {
            var lastData = base64Data.length;
            while ((base64Data[lastData - 1] === Base64.PAD)) {
                {
                    if (--lastData === 0) {
                        return [];
                    }
                }
            }
            decodedData = [];
        }
        for (var i = 0; i < numberQuadruple; i++) {
            {
                dataIndex = i * 4;
                marker0 = base64Data[dataIndex + 2];
                marker1 = base64Data[dataIndex + 3];
                b1 = Base64.base64Alphabet[base64Data[dataIndex]];
                b2 = Base64.base64Alphabet[base64Data[dataIndex + 1]];
                if (marker0 !== Base64.PAD && marker1 !== Base64.PAD) {
                    b3 = Base64.base64Alphabet[marker0];
                    b4 = Base64.base64Alphabet[marker1];
                    decodedData[encodedIndex] = ((b1 << 2 | b2 >> 4) | 0);
                    decodedData[encodedIndex + 1] = ((((b2 & 15) << 4) | ((b3 >> 2) & 15)) | 0);
                    decodedData[encodedIndex + 2] = ((b3 << 6 | b4) | 0);
                }
                else if (marker0 === Base64.PAD) {
                    decodedData[encodedIndex] = ((b1 << 2 | b2 >> 4) | 0);
                }
                else if (marker1 === Base64.PAD) {
                    b3 = Base64.base64Alphabet[marker0];
                    decodedData[encodedIndex] = ((b1 << 2 | b2 >> 4) | 0);
                    decodedData[encodedIndex + 1] = ((((b2 & 15) << 4) | ((b3 >> 2) & 15)) | 0);
                }
                encodedIndex += 3;
            }
        }
        return decodedData;
    };
    /**
     * Discards any characters outside of the base64 alphabet, per
     * the requirements on page 25 of RFC 2045 - "Any characters
     * outside of the base64 alphabet are to be ignored in base64
     * encoded data."
     *
     * @param {Array} data The base-64 encoded data to groom
     * @return {Array} The data, less non-base64 characters (see RFC 2045).
     */
    Base64.discardNonBase64 = function (data) {
        var groomedData = [];
        var bytesCopied = 0;
        for (var i = 0; i < data.length; i++) {
            {
                if (Base64.isBase64(data[i])) {
                    groomedData[bytesCopied++] = data[i];
                }
            }
        }
        var packedData = [];
        System.arraycopy(groomedData, 0, packedData, 0, bytesCopied);
        return packedData;
    };
    /**
     * Chunk size per RFC 2045 section 6.8.
     *
     * <p>The {@value} character limit does not count the trailing CRLF, but counts
     * all other characters, including any equal signs.</p>
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 6.8</a>
     */
    Base64.CHUNK_SIZE = 76;
    /**
     * Chunk separator per RFC 2045 section 2.1.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 2.1</a>
     */
    Base64.CHUNK_SEPARATOR = ("\r\n").split('').map(function (s) { return s.charCodeAt(0); });
    /**
     * The base length.
     */
    Base64.BASELENGTH = 255;
    /**
     * Lookup length.
     */
    Base64.LOOKUPLENGTH = 64;
    /**
     * Used to calculate the number of bits in a byte.
     */
    Base64.EIGHTBIT = 8;
    /**
     * Used when encoding something which has fewer than 24 bits.
     */
    Base64.SIXTEENBIT = 16;
    /**
     * Used to determine how many bits data contains.
     */
    Base64.TWENTYFOURBITGROUP = 24;
    /**
     * Used to get the number of Quadruples.
     */
    Base64.FOURBYTE = 4;
    /**
     * Used to test the sign of a byte.
     */
    Base64.SIGN = -128;
    /**
     * Byte used to pad output.
     */
    Base64.PAD = ('=').charCodeAt(0);
    return Base64;
}());

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
var Collection = /** @class */ (function (_super) {
    __extends(Collection, _super);
    function Collection() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return Collection;
}(Array));

var max = 10000000000000; // biggest 10^n integer that can still fit 2^53 when multiplied by 256
var Int10 = /** @class */ (function () {
    function Int10(value) {
        this.buf = [+value || 0];
    }
    Int10.prototype.mulAdd = function (m, c) {
        // assert(m <= 256)
        var b = this.buf, l = b.length, i, t;
        for (i = 0; i < l; ++i) {
            t = b[i] * m + c;
            if (t < max)
                c = 0;
            else {
                c = 0 | (t / max);
                t -= c * max;
            }
            b[i] = t;
        }
        if (c > 0)
            b[i] = c;
    };
    Int10.prototype.sub = function (c) {
        // assert(m <= 256)
        var b = this.buf, l = b.length, i, t;
        for (i = 0; i < l; ++i) {
            t = b[i] - c;
            if (t < 0) {
                t += max;
                c = 1;
            }
            else
                c = 0;
            b[i] = t;
        }
        while (b[b.length - 1] === 0)
            b.pop();
    };
    Int10.prototype.toString = function (base) {
        if ((base || 10) != 10)
            throw 'only base 10 is supported';
        var b = this.buf, s = b[b.length - 1].toString();
        for (var i = b.length - 2; i >= 0; --i)
            s += (max + b[i]).toString().substring(1);
        return s;
    };
    Int10.prototype.valueOf = function () {
        var b = this.buf, v = 0;
        for (var i = b.length - 1; i >= 0; --i)
            v = v * max + b[i];
        return v;
    };
    Int10.prototype.simplify = function () {
        var b = this.buf;
        return (b.length == 1) ? b[0] : this;
    };
    return Int10;
}());

var UNSUPPORTED_ALGORITHM = 'Unsupported algorithm name specified! Supported algorithms: "HS256", "HS384", "HS512", "RS256", "RS384", "RS512" and "none".';
var ILLEGAL_ARGUMENT = 'Illegal argument specified!';
function num2hex(memo, i) {
    return memo + ('0' + i.toString(16)).slice(-2);
}
// clean leading zeros
function cleanZeros(b) {
    return b[0] === 0 ? cleanZeros(b.slice(1)) : b;
}
function hex2AB(hex) {
    if (!hex)
        throw new Error(ILLEGAL_ARGUMENT);
    var match = hex.match(/[0-9A-F]{2}/ig);
    if (!match)
        throw new Error(ILLEGAL_ARGUMENT);
    return new Uint8Array(match.map(function (i) { return parseInt(i, 16); }));
}
function AB2hex(buff) {
    if (buff instanceof ArrayBuffer)
        buff = new Uint8Array(buff);
    return buff.reduce(num2hex, '');
}
/**
 * Try running function and replace it's response as Promise.resolve/reject
 *
 * @param {function} fn - fn to call in for response
 *
 * @returns {Promise<any>} resulting Promise
 */
function tryPromise(fn) {
    try {
        return Promise.resolve(fn());
    }
    catch (e) {
        return Promise.reject(e);
    }
}
/**
 * Converts string to ArrayBuffer
 *
 * @param {string} str - data string to convert
 *
 * @returns {ArrayBuffer | Uint8Array} charCode ArrayBuffer
 */
function s2AB(str) {
    var buff = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++)
        buff[i] = str.charCodeAt(i);
    return buff;
}
/**
 * Converts ArrayBuffer to string
 *
 * @param {ArrayBuffer | Uint8Array} buff - charCode ArrayBuffer to convert
 *
 * @returns {string} data string
 */
function AB2s(buff) {
    if (buff instanceof ArrayBuffer)
        buff = new Uint8Array(buff);
    return String.fromCharCode.apply(String, buff);
}
/**
 * Converts string to base64 string
 *
 * @param {string} str - data string to convert
 *
 * @returns {string} decoded data string
 */
function b2s(str) {
    try {
        if (typeof window === 'object' && typeof window.atob === 'function') {
            return window.atob(str);
        }
        else if (typeof Buffer !== 'undefined') {
            return Buffer.from(str, 'base64').toString('binary');
        }
        else
            throw new Error(ILLEGAL_ARGUMENT);
    }
    catch (e) {
        throw new Error(e);
    }
}
/**
 * Converts base64 string to base64url string
 *
 * @param {string} str - data string to convert
 *
 * @returns {string} base64url string
 */
function b2bu(str) {
    if ((typeof str !== 'string') || (str.length % 4 !== 0)) {
        throw new Error(ILLEGAL_ARGUMENT);
    }
    return str
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
/**
 *
 * Converts base64url string to base64 string
 *
 * @param {string} str - data string to convert
 *
 * @returns {string} base64 string
 */
function bu2b(str) {
    if ((typeof str !== 'string') || (str.length % 4 === 1)) {
        throw new Error(ILLEGAL_ARGUMENT);
    }
    for (; (str.length % 4 !== 0);) {
        str += '=';
    }
    return str
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
}
/**
 * Converts base64url string to string
 *
 * @param {string} str - base64url string to convert
 *
 * @returns {string} decoded data string
 */
function bu2s(str) {
    return b2s(bu2b(str));
}
/**
 * Converts base64 string to string
 *
 * @param {string} str - data string to convert
 *
 * @returns {string} base64 string
 */
function s2b(str) {
    try {
        if (typeof window === 'object' && typeof window.atob === 'function') {
            return window.btoa(str);
        }
        else if (typeof Buffer !== 'undefined') {
            return Buffer.from(str).toString('base64');
        }
        else
            throw new Error(ILLEGAL_ARGUMENT);
    }
    catch (e) {
        throw new Error(e);
    }
}
/**
 * Converts string to base64url string
 *
 * @param {string} str - data string to convert
 *
 * @returns {string} base64url string
 */
function s2bu(str) {
    return b2bu(s2b(str));
}

var ellipsis = "\u2026", reTimeS = /^(\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/, reTimeL = /^(\d\d\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
function stringCut(str, len) {
    if (str.length > len)
        str = str.substring(0, len) + ellipsis;
    return str;
}
var Stream = /** @class */ (function () {
    function Stream(enc, pos) {
        if (pos === void 0) { pos = 0; }
        this.hexDigits = "0123456789ABCDEF";
        if (enc instanceof Stream) {
            this.enc = enc.enc;
            this.pos = enc.pos;
        }
        else {
            this.enc = enc;
            this.pos = pos;
        }
    }
    Stream.prototype.get = function (pos) {
        if (pos === undefined)
            pos = this.pos++;
        if (pos >= this.enc.length)
            throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;
        return (typeof this.enc == "string") ? this.enc.charCodeAt(pos) : this.enc[pos];
    };
    Stream.prototype.hexByte = function (b) {
        return this.hexDigits.charAt((b >> 4) & 0xF) + this.hexDigits.charAt(b & 0xF);
    };
    Stream.prototype.hexDump = function (start, end, raw) {
        var s = "";
        for (var i = start; i < end; ++i) {
            s += this.hexByte(this.get(i));
            if (raw !== true)
                switch (i & 0xF) {
                    case 0x7:
                        s += "  ";
                        break;
                    case 0xF:
                        s += "\n";
                        break;
                    default:
                        s += " ";
                }
        }
        return s;
    };
    Stream.prototype.isASCII = function (start, end) {
        for (var i = start; i < end; ++i) {
            var c = this.get(i);
            if (c < 32 || c > 176)
                return false;
        }
        return true;
    };
    Stream.prototype.parseStringISO = function (start, end) {
        var s = "";
        for (var i = start; i < end; ++i)
            s += String.fromCharCode(this.get(i));
        return s;
    };
    Stream.prototype.parseStringUTF = function (start, end) {
        var s = "";
        for (var i = start; i < end;) {
            var c = this.get(i++);
            if (c < 128)
                s += String.fromCharCode(c);
            else if ((c > 191) && (c < 224))
                s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
            else
                s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
        }
        return s;
    };
    Stream.prototype.parseStringBMP = function (start, end) {
        var str = "", hi, lo;
        for (var i = start; i < end;) {
            hi = this.get(i++);
            lo = this.get(i++);
            str += String.fromCharCode((hi << 8) | lo);
        }
        return str;
    };
    Stream.prototype.parseTime = function (start, end, shortYear) {
        var s = this.parseStringISO(start, end), m = (shortYear ? reTimeS : reTimeL).exec(s);
        if (!m)
            return "Unrecognized time: " + s;
        if (shortYear) {
            var t = +m[1], y = (t < 70) ? 2000 : 1900;
            m[1] = y + "";
        }
        s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
        if (m[5]) {
            s += ":" + m[5];
            if (m[6]) {
                s += ":" + m[6];
                if (m[7])
                    s += "." + m[7];
            }
        }
        if (m[8]) {
            s += " UTC";
            if (m[8] != 'Z') {
                s += m[8];
                if (m[9])
                    s += ":" + m[9];
            }
        }
        return s;
    };
    Stream.prototype.parseInteger = function (start, end) {
        var v = this.get(start), neg = (v > 127), pad = neg ? 255 : 0, len, s = '';
        while (v == pad && ++start < end)
            v = this.get(start);
        len = end - start;
        if (len === 0)
            return neg ? -1 : 0;
        if (len > 4) {
            var t = +v;
            len <<= 3;
            while (((t ^ pad) & 0x80) === 0) {
                t <<= 1;
                --len;
            }
            s = "(" + len + " bit)\n";
        }
        if (neg)
            v = v - 256;
        var n = new Int10(v);
        for (var i = start + 1; i < end; ++i)
            n.mulAdd(256, this.get(i));
        return s + n.toString();
    };
    Stream.prototype.parseBitString = function (start, end, maxLength) {
        var unusedBit = this.get(start), lenBit = ((end - start - 1) << 3) - unusedBit, intro = "(" + lenBit + " bit)\n", s = "";
        for (var i = start + 1; i < end; ++i) {
            var b = this.get(i), skip = (i == end - 1) ? unusedBit : 0;
            for (var j = 7; j >= skip; --j)
                s += (b >> j) & 1 ? "1" : "0";
            if (s.length > maxLength)
                return intro + stringCut(s, maxLength);
        }
        return intro + s;
    };
    Stream.prototype.parseOctetString = function (start, end, maxLength) {
        if (this.isASCII(start, end))
            return stringCut(this.parseStringISO(start, end), maxLength);
        var len = end - start, s = "(" + len + " byte)\n";
        maxLength /= 2;
        if (len > maxLength)
            end = start + maxLength;
        for (var i = start; i < end; ++i)
            s += this.hexByte(this.get(i));
        if (len > maxLength)
            s += ellipsis;
        return s;
    };
    Stream.prototype.parseOID = function (start, end, maxLength) {
        var s = '', n = new Int10(), bits = 0;
        for (var i = start; i < end; ++i) {
            var v = this.get(i);
            n.mulAdd(128, v & 0x7F);
            bits += 7;
            if (!(v & 0x80)) {
                if (s === '') {
                    n = n.simplify();
                    if (n instanceof Int10) {
                        n.sub(80);
                        s = "2." + n.toString();
                    }
                    else {
                        var m = n < 80 ? n < 40 ? 0 : 1 : 2;
                        s = m + "." + (n - m * 40);
                    }
                }
                else
                    s += "." + n.toString();
                if (s.length > maxLength)
                    return stringCut(s, maxLength);
                n = new Int10();
                bits = 0;
            }
        }
        if (bits > 0)
            s += ".incomplete";
        return s;
    };
    return Stream;
}());
var ASN1 = /** @class */ (function () {
    function ASN1(stream, header, length, tag, sub) {
        if (!(tag instanceof ASN1Tag))
            throw 'Invalid tag value.';
        this.stream = stream;
        this.header = header;
        this.length = length;
        this.tag = tag;
        this.sub = sub;
    }
    ASN1.decodeLength = function (stream) {
        var buf = stream.get();
        var len = buf & 0x7F;
        if (len == buf)
            return len;
        if (len > 6)
            throw "Length over 48 bits not supported at position " + (stream.pos - 1);
        if (len === 0)
            return null;
        buf = 0;
        for (var i = 0; i < len; ++i)
            buf = (buf * 256) + stream.get();
        return buf;
    };
    ASN1.decode = function (stream) {
        if (!(stream instanceof Stream))
            stream = new Stream(stream, 0);
        var streamStart = new Stream(stream);
        var tag = new ASN1Tag(stream);
        var len = ASN1.decodeLength(stream), sub = null;
        var start = stream.pos;
        var header = start - streamStart.pos;
        var getSub = function () {
            sub = [];
            if (len !== null) {
                var end = start + len;
                while (stream.pos < end)
                    sub[sub.length] = ASN1.decode(stream);
                if (stream.pos != end)
                    throw "Content size is not correct for container starting at offset " + start;
            }
            else {
                try {
                    for (;;) {
                        var s = ASN1.decode(stream);
                        if (s.tag.isEOC())
                            break;
                        sub[sub.length] = s;
                    }
                    len = start - stream.pos;
                }
                catch (e) {
                    throw "Exception while decoding undefined length content: " + e;
                }
            }
        };
        if (tag.tagConstructed) {
            getSub();
        }
        else if (tag.isUniversal() && ((tag.tagNumber == 0x03) || (tag.tagNumber == 0x04))) {
            try {
                if (tag.tagNumber == 0x03)
                    if (stream.get() != 0)
                        throw "BIT STRINGs with unused bits cannot encapsulate.";
                getSub();
                for (var i = 0; i < sub.length; ++i)
                    if (sub[i].tag.isEOC())
                        throw 'EOC is not supposed to be actual content.';
            }
            catch (e) {
                sub = null;
            }
        }
        if (sub === null) {
            if (len === null)
                throw "We can't skip over an invalid tag with undefined length at offset " + start;
            stream.pos = start + Math.abs(len);
        }
        return new ASN1(streamStart, header, len, tag, sub);
    };
    ASN1.prototype.typeName = function () {
        switch (this.tag.tagClass) {
            case 0:
                switch (this.tag.tagNumber) {
                    case 0x00:
                        return "EOC";
                    case 0x01:
                        return "BOOLEAN";
                    case 0x02:
                        return "INTEGER";
                    case 0x03:
                        return "BIT_STRING";
                    case 0x04:
                        return "OCTET_STRING";
                    case 0x05:
                        return "NULL";
                    case 0x06:
                        return "OBJECT_IDENTIFIER";
                    case 0x07:
                        return "ObjectDescriptor";
                    case 0x08:
                        return "EXTERNAL";
                    case 0x09:
                        return "REAL";
                    case 0x0A:
                        return "ENUMERATED";
                    case 0x0B:
                        return "EMBEDDED_PDV";
                    case 0x0C:
                        return "UTF8String";
                    case 0x10:
                        return "SEQUENCE";
                    case 0x11:
                        return "SET";
                    case 0x12:
                        return "NumericString";
                    case 0x13:
                        return "PrintableString";
                    case 0x14:
                        return "TeletexString";
                    case 0x15:
                        return "VideotexString";
                    case 0x16:
                        return "IA5String";
                    case 0x17:
                        return "UTCTime";
                    case 0x18:
                        return "GeneralizedTime";
                    case 0x19:
                        return "GraphicString";
                    case 0x1A:
                        return "VisibleString";
                    case 0x1B:
                        return "GeneralString";
                    case 0x1C:
                        return "UniversalString";
                    case 0x1E:
                        return "BMPString";
                }
                return "Universal_" + this.tag.tagNumber.toString();
            case 1:
                return "Application_" + this.tag.tagNumber.toString();
            case 2:
                return "[" + this.tag.tagNumber.toString() + "]";
            case 3:
                return "Private_" + this.tag.tagNumber.toString();
        }
    };
    ASN1.prototype.content = function (maxLength) {
        if (this.tag === undefined)
            return null;
        if (maxLength === undefined)
            maxLength = Infinity;
        var content = this.posContent(), len = Math.abs(this.length);
        if (!this.tag.isUniversal()) {
            if (this.sub !== null)
                return "(" + this.sub.length + " elem)";
            return this.stream.parseOctetString(content, content + len, maxLength);
        }
        switch (this.tag.tagNumber) {
            case 0x01:
                return (this.stream.get(content) === 0) ? "false" : "true";
            case 0x02:
                return this.stream.parseInteger(content, content + len);
            case 0x03:
                return this.sub ? "(" + this.sub.length + " elem)" :
                    this.stream.parseBitString(content, content + len, maxLength);
            case 0x04:
                return this.sub ? "(" + this.sub.length + " elem)" :
                    this.stream.parseOctetString(content, content + len, maxLength);
            case 0x06:
                return this.stream.parseOID(content, content + len, maxLength);
            case 0x10:
            case 0x11:
                if (this.sub !== null)
                    return "(" + this.sub.length + " elem)";
                else
                    return "(no elem)";
            case 0x0C:
                return stringCut(this.stream.parseStringUTF(content, content + len), maxLength);
            case 0x12:
            case 0x13:
            case 0x14:
            case 0x15:
            case 0x16:
            case 0x1A:
                return stringCut(this.stream.parseStringISO(content, content + len), maxLength);
            case 0x1E:
                return stringCut(this.stream.parseStringBMP(content, content + len), maxLength);
            case 0x17:
            case 0x18:
                return this.stream.parseTime(content, content + len, (this.tag.tagNumber == 0x17));
        }
        return null;
    };
    ASN1.prototype.toString = function () {
        return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub === null) ? 'null' : this.sub.length) + "]";
    };
    ASN1.prototype.posStart = function () {
        return this.stream.pos;
    };
    ASN1.prototype.posContent = function () {
        return this.stream.pos + this.header;
    };
    ASN1.prototype.posEnd = function () {
        return this.stream.pos + this.header + Math.abs(this.length);
    };
    ASN1.prototype.toHexString = function (root) {
        return this.stream.hexDump(this.posStart(), this.posEnd(), true);
    };
    ASN1.prototype.getHex = function () {
        return this.stream.hexDump(this.posContent(), this.posEnd(), true);
    };
    ASN1.prototype.getAB = function (clean) {
        if (clean === void 0) { clean = true; }
        return clean ? cleanZeros(hex2AB(this.getHex())) : hex2AB(this.getHex());
    };
    return ASN1;
}());
var ASN1Tag = /** @class */ (function () {
    function ASN1Tag(stream) {
        var buf = stream.get();
        this.tagClass = buf >> 6;
        this.tagConstructed = ((buf & 0x20) !== 0);
        this.tagNumber = buf & 0x1F;
        if (this.tagNumber == 0x1F) {
            var n = new Int10();
            do {
                buf = stream.get();
                n.mulAdd(128, buf & 0x7F);
            } while (buf & 0x80);
            this.tagNumber = n.simplify();
        }
    }
    ASN1Tag.prototype.isUniversal = function () {
        return this.tagClass === 0x00;
    };
    ASN1Tag.prototype.isEOC = function () {
        return this.tagClass === 0x00 && this.tagNumber === 0x00;
    };
    return ASN1Tag;
}());

var PEM = /** @class */ (function () {
    function PEM(secret) {
        var _this = this;
        if (typeof secret !== 'string') {
            throw new Error(ILLEGAL_ARGUMENT);
        }
        this.type = 'public';
        var ignore = function (line) {
            if (ignoreLinesPriv.some(function (ign) { return line.toUpperCase().indexOf(ign) > -1; })) {
                _this.type = 'private';
                return false;
            }
            return !ignoreLinesPub.some(function (ign) { return line.toUpperCase().indexOf(ign) > -1; });
        };
        var lines = secret.split('\n'), ignoreLinesPriv = [
            '-BEGIN PRIVATE KEY-',
            '-END PRIVATE KEY-',
            '-BEGIN EC PRIVATE KEY-',
            '-END EC PRIVATE KEY-',
            '-BEGIN RSA PRIVATE KEY-',
            '-END RSA PRIVATE KEY-'
        ], ignoreLinesPub = [
            '-BEGIN RSA PUBLIC KEY-',
            '-BEGIN EC PUBLIC KEY-',
            '-BEGIN PUBLIC KEY-',
            '-END PUBLIC KEY-',
            '-END EC PUBLIC KEY-',
            '-END RSA PUBLIC KEY-'
        ], body = lines.map(function (line) { return line.trim(); }).filter(function (line) {
            return line.length && ignore(line);
        }).join('');
        if (body.length) {
            this.body = s2AB(b2s(bu2b(body)));
            return this;
        }
        else {
            throw new Error(ILLEGAL_ARGUMENT);
        }
    }
    return PEM;
}());

var ECCurves = [
    {
        name: "p-256",
        curve: "1.2.840.10045.3.1.7",
        coordinateLength: 32
    },
    {
        name: "p-384",
        curve: "1.3.132.0.34",
        coordinateLength: 48
    },
    {
        name: "p-384",
        curve: "1.3.132.0.35",
        coordinateLength: 66
    }
];
var EC = /** @class */ (function () {
    function EC() {
    }
    EC.ASN1fromPEM = function (body) {
        if (!body)
            throw new Error(ILLEGAL_ARGUMENT);
        if (body instanceof ArrayBuffer)
            body = new Uint8Array(body);
        var asn1 = ASN1.decode(body);
        var res = {};
        if (asn1.sub.length === 3) {
            res['version'] = asn1.sub[0].content(); // int
            res['keyType'] = asn1.sub[1].sub[0].content(); // string
            res['namedCurve'] = asn1.sub[1].sub[1].content(); // string
            res['versionSub'] = asn1.sub[2].sub[0].sub[0].content(); // int
            res['privateKey'] = asn1.sub[2].sub[0].sub[2].getAB(); // ArrayBuffer
            res['curveTypeSub'] = asn1.sub[2].sub[0].sub[2].sub[0].content(); // string
            res['publicKey'] = asn1.sub[2].sub[0].sub[3].sub[0].getAB(); // ArrayBuffer
        }
        else if (asn1.sub.length === 2) {
            res['keyType'] = asn1.sub[0].sub[0].content(); // string
            res['namedCurve'] = asn1.sub[0].sub[1].content(); // string
            res['publicKey'] = asn1.sub[1].getAB(); // int
        }
        return asn1;
    };
    EC.JWKfromASN1 = function (asn1, type, extra) {
        var pemTypes = ['public', 'private'];
        if (!asn1)
            throw new Error(ILLEGAL_ARGUMENT);
        type = ((typeof type === 'string') && type.toLowerCase())
            || pemTypes[!!asn1.privateKey ? 1 : 0];
        if (type === 'private' && !asn1.privateKey) {
            throw new Error(ILLEGAL_ARGUMENT);
        }
        var crv = ECCurves.find(function (c) { return c.curve === asn1.namedCurve; });
        if (!crv) {
            throw new Error(ILLEGAL_ARGUMENT);
        }
        var publicKey = asn1.publicKey;
        if (publicKey.readInt8(0) !== 4) {
            throw new Error(ILLEGAL_ARGUMENT);
        }
        var jwk = Object.assign({ kty: 'EC', crv: crv.name }, extra, {
            x: s2bu(AB2s(publicKey.slice(1, crv.coordinateLength))),
            y: s2bu(AB2s(publicKey.slice(crv.coordinateLength + 1, 2 * (crv.coordinateLength + 1))))
        });
        if (type === 'private') {
            Object.assign(jwk, {
                d: s2bu(AB2s(asn1.privateKey))
            });
        }
        return jwk;
    };
    EC.JWKfromEC = function (secret, type, extra) {
        return tryPromise(function () {
            var pem = new PEM(secret);
            return EC.JWKfromASN1(EC.ASN1fromPEM(pem.body), type, extra);
        });
    };
    return EC;
}());

/*! *****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

var webCrypto = typeof window === "object" && (window.crypto || window['msCrypto']);
var webCryptoSubtle = webCrypto && (webCrypto.subtle || webCrypto['webkitSubtle'] || webCrypto['Subtle']);
var HMAC = /** @class */ (function () {
    function HMAC() {
    }
    HMAC.createSigner = function (name, secret) {
        return __awaiter(this, void 0, void 0, function () {
            var keyData;
            return __generator(this, function (_a) {
                if (webCryptoSubtle) {
                    keyData = s2AB(secret);
                    return [2 /*return*/, webCryptoSubtle.importKey('raw', keyData, { name: 'HMAC', hash: { name: name } }, true, ['sign']).then(function (key) {
                            return {
                                update: function (thing) {
                                    return __awaiter(this, void 0, void 0, function () {
                                        return __generator(this, function (_a) {
                                            return [2 /*return*/, webCryptoSubtle.sign('HMAC', key, s2AB(thing))];
                                        });
                                    });
                                }
                            };
                        })];
                }
                else {
                    return [2 /*return*/, !!crypto && crypto.createHmac ? Promise.resolve(crypto.createHmac(name.replace('SHA-', 'sha'), secret)) : Promise.reject(webCrypto)];
                }
                return [2 /*return*/];
            });
        });
    };
    HMAC.sign = function (bits) {
        return function sign(thing, secret) {
            return __awaiter(this, void 0, void 0, function () {
                var hmac, _a, _b, _c, _d, _e, _f;
                return __generator(this, function (_g) {
                    switch (_g.label) {
                        case 0: return [4 /*yield*/, HMAC.createSigner('SHA-' + bits, secret)];
                        case 1:
                            hmac = _g.sent();
                            _b = (_a = Promise).resolve;
                            if (!webCryptoSubtle) return [3 /*break*/, 4];
                            _d = s2bu;
                            _e = AB2s;
                            _f = hmac;
                            if (!_f) return [3 /*break*/, 3];
                            return [4 /*yield*/, hmac.update(thing)];
                        case 2:
                            _f = (_g.sent());
                            _g.label = 3;
                        case 3:
                            _c = _d.apply(void 0, [_e.apply(void 0, [_f])]);
                            return [3 /*break*/, 5];
                        case 4:
                            _c = b2bu(hmac && hmac.update(thing).digest('base64'));
                            _g.label = 5;
                        case 5: return [2 /*return*/, _b.apply(_a, [_c])];
                    }
                });
            });
        };
    };
    HMAC.verify = function (bits) {
        return function verify(thing, signature, secret) {
            return __awaiter(this, void 0, void 0, function () {
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0: return [4 /*yield*/, HMAC.sign(bits)(thing, secret)];
                        case 1: return [2 /*return*/, (_a.sent()) === signature];
                    }
                });
            });
        };
    };
    return HMAC;
}());

var webCrypto$1 = typeof window === "object" && (window.crypto || window['msCrypto']);
var webCryptoSubtle$1 = webCrypto$1 && (webCrypto$1.subtle || webCrypto$1['webkitSubtle'] || webCrypto$1['Subtle']);
var RSA = /** @class */ (function () {
    function RSA() {
    }
    RSA.ASN1fromPEM = function (body) {
        if (!body)
            throw new Error(ILLEGAL_ARGUMENT);
        if (body instanceof ArrayBuffer)
            body = new Uint8Array(body);
        var asn1 = ASN1.decode(body), res = {};
        if (asn1.sub.length === 3) {
            asn1 = asn1.sub[2].sub[0];
        }
        if (asn1.sub.length === 9) {
            // Parse the private key.
            res['modulus'] = asn1.sub[1].getAB(); // ArrayBuffer
            res['publicExponent'] = parseInt(asn1.sub[2].getHex(), 16); // int
            res['privateExponent'] = asn1.sub[3].getAB(); // ArrayBuffer
            res['prime1'] = asn1.sub[4].getAB(); // ArrayBuffer
            res['prime2'] = asn1.sub[5].getAB(); // ArrayBuffer
            res['exponent1'] = asn1.sub[6].getAB(); // ArrayBuffer
            res['exponent2'] = asn1.sub[7].getAB(); // ArrayBuffer
            res['coefficient'] = asn1.sub[8].getAB(); // ArrayBuffer
        }
        else if (asn1.sub.length === 2) {
            // Parse the public key.
            asn1 = asn1.sub[1].sub[0];
            res['modulus'] = asn1.sub[0].getAB(); // ArrayBuffer
            res['publicExponent'] = parseInt(asn1.sub[1].getHex(), 16); // int
        }
        res['bits'] = (res['modulus'].length - 1) * 8 + Math.ceil(Math.log(res['modulus'][0] + 1) / Math.log(2));
        if (!res['bits']) {
            throw new Error(ILLEGAL_ARGUMENT);
        }
        return res;
    };
    RSA.JWKfromASN1 = function (asn1, type, extra) {
        var pemTypes = ['public', 'private'];
        if (!asn1)
            throw new Error(ILLEGAL_ARGUMENT);
        type = ((typeof type === 'string') && type.toLowerCase())
            || pemTypes[!!asn1.privateExponent ? 1 : 0];
        if (type === 'private' && !asn1.privateExponent) {
            throw new Error(ILLEGAL_ARGUMENT);
        }
        var v = asn1.publicExponent;
        var expSize = Math.ceil(Math.log(v) / Math.log(256));
        var exp = new Uint8Array(expSize).map(function (el) {
            el = v % 256;
            v = Math.floor(v / 256);
            return el;
        }).reverse();
        var jwk = Object.assign({ kty: 'RSA' }, extra, {
            n: s2bu(AB2s(asn1.modulus)),
            e: s2bu(AB2s(exp)),
        });
        if (type === 'private') {
            Object.assign(jwk, {
                d: s2bu(AB2s(asn1.privateExponent)),
                p: s2bu(AB2s(asn1.prime1)),
                q: s2bu(AB2s(asn1.prime2)),
                dp: s2bu(AB2s(asn1.exponent1)),
                dq: s2bu(AB2s(asn1.exponent2)),
                qi: s2bu(AB2s(asn1.coefficient))
            });
        }
        return jwk;
    };
    RSA.JWKfromRSA = function (secret, type, extra) {
        return tryPromise(function () {
            var pem = new PEM(secret);
            return RSA.JWKfromASN1(RSA.ASN1fromPEM(pem.body), type, extra);
        });
    };
    RSA.createSigner = function (name) {
        if (webCryptoSubtle$1) {
            return {
                update: function (thing) {
                    return {
                        sign: function (secret, encoding) {
                            return __awaiter(this, void 0, void 0, function () {
                                var _this = this;
                                return __generator(this, function (_a) {
                                    return [2 /*return*/, RSA.JWKfromRSA(secret, 'private', {
                                            key_ops: ['sign'],
                                            alg: name.replace('SHA-', 'RS')
                                        }).then(function (keyData) { return __awaiter(_this, void 0, void 0, function () {
                                            var _this = this;
                                            return __generator(this, function (_a) {
                                                return [2 /*return*/, webCryptoSubtle$1.importKey('jwk', keyData, { name: 'RSASSA-PKCS1-v1_5', hash: { name: name } }, true, ['sign']).then(function (key) { return __awaiter(_this, void 0, void 0, function () {
                                                        return __generator(this, function (_a) {
                                                            return [2 /*return*/, webCryptoSubtle$1.sign({ name: 'RSASSA-PKCS1-v1_5', hash: { name: name } }, key, s2AB(thing)).then(AB2s).then(s2b)];
                                                        });
                                                    }); })];
                                            });
                                        }); })];
                                });
                            });
                        }
                    };
                }
            };
        }
        else {
            if (crypto && crypto.createSign) {
                return crypto.createSign(name.replace('SHA-', 'RSA-SHA'));
            }
            else {
                throw new Error(ILLEGAL_ARGUMENT);
            }
        }
    };
    RSA.sign = function (bits) {
        return function sign(thing, privateKey) {
            return __awaiter(this, void 0, void 0, function () {
                return __generator(this, function (_a) {
                    return [2 /*return*/, tryPromise(function () {
                            return RSA.createSigner('SHA-' + bits)
                                .then(function (res) { return res
                                .update(thing)
                                .sign(privateKey, 'base64')
                                .then(b2bu); });
                        })];
                });
            });
        };
    };
    RSA.createVerifier = function (name) {
        if (webCryptoSubtle$1) {
            return {
                update: function (thing) {
                    return {
                        verify: function (secret, signature, encoding) {
                            return __awaiter(this, void 0, void 0, function () {
                                var _this = this;
                                return __generator(this, function (_a) {
                                    return [2 /*return*/, RSA.JWKfromRSA(secret, 'public', {
                                            key_ops: ['verify'],
                                            alg: name.replace('SHA-', 'RS')
                                        }).then(function (_a) {
                                            var kty = _a.kty, n = _a.n, e = _a.e;
                                            return __awaiter(_this, void 0, void 0, function () {
                                                return __generator(this, function (_b) {
                                                    return [2 /*return*/, webCryptoSubtle$1.importKey('jwk', { kty: kty, n: n, e: e }, { name: 'RSASSA-PKCS1-v1_5', hash: { name: name } }, false, ['verify']).then(function (key) {
                                                            return webCryptoSubtle$1.verify('RSASSA-PKCS1-v1_5', key, s2AB(bu2s(signature)), s2AB(thing));
                                                        })];
                                                });
                                            });
                                        })];
                                });
                            });
                        }
                    };
                }
            };
        }
        else {
            if (crypto && crypto.createVerify) {
                return crypto.createVerify(name.replace('SHA-', 'RSA-SHA'));
            }
            else {
                throw new Error(ILLEGAL_ARGUMENT);
            }
        }
    };
    RSA.verify = function (bits) {
        return function verify(thing, signature, publicKey) {
            return __awaiter(this, void 0, void 0, function () {
                var e_1;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0:
                            _a.trys.push([0, 2, , 3]);
                            return [4 /*yield*/, RSA.createVerifier('SHA-' + bits)
                                    .then(function (res) { return res
                                    .update(thing)
                                    .verify(publicKey, bu2b(signature), 'base64'); })];
                        case 1: return [2 /*return*/, _a.sent()];
                        case 2:
                            e_1 = _a.sent();
                            return [2 /*return*/, Promise.reject(new Error(e_1.message))];
                        case 3: return [2 /*return*/];
                    }
                });
            });
        };
    };
    return RSA;
}());

var jwkJs = {
    ASN1: ASN1,
    EC: EC,
    PEM: PEM,
    RSA: RSA,
    HMAC: HMAC,
    ILLEGAL_ARGUMENT: ILLEGAL_ARGUMENT,
    UNSUPPORTED_ALGORITHM: UNSUPPORTED_ALGORITHM,
    tryPromise: tryPromise,
    AB2hex: AB2hex,
    AB2s: AB2s,
    b2bu: b2bu,
    b2s: b2s,
    bu2b: bu2b,
    bu2s: bu2s,
    cleanZeros: cleanZeros,
    hex2AB: hex2AB,
    num2hex: num2hex,
    s2AB: s2AB,
    s2b: s2b,
    s2bu: s2bu
};

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
var EC$1 = /** @class */ (function () {
    function EC() {
    }
    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    EC.privateKeyFromPKCS8 = function (pkcs8) {
        try {
            return jwkJs.EC.JWKfromEC(jwkJs.AB2s(pkcs8), "private");
        }
        catch (e) {
            throw new Error(e);
        }
    };
    /**
     * Returns a public key constructed from the given DER bytes.
     */
    EC.publicKeyFrom = function (derBytes) {
        try {
            return jwkJs.EC.JWKfromEC(jwkJs.AB2s(derBytes), "public");
        }
        catch (e) {
            throw new Error(e);
        }
    };
    EC.EC = "EC";
    EC.SUNEC = "SunEC"; // Sun's ECC provider
    return EC;
}());

function equalsIgnoreCase(a, b) {
    return !!a && !!b && a.toUpperCase() === b.toUpperCase();
}

var StringBuilder = /** @class */ (function () {
    function StringBuilder() {
        this.str = "";
    }
    Object.defineProperty(StringBuilder.prototype, "length", {
        get: function () {
            return this.str.length;
        },
        enumerable: true,
        configurable: true
    });
    StringBuilder.prototype.toString = function () {
        return this.str;
    };
    StringBuilder.prototype.toNumber = function () {
        return +this.str;
    };
    StringBuilder.prototype.lastIndexOf = function (str) {
        return this.str.lastIndexOf(str);
    };
    StringBuilder.prototype.append = function (str) {
        if (!!str && str.toString)
            this.str = this.str.concat(str.toString());
        return this;
    };
    StringBuilder.prototype.deleteCharAt = function (i) {
        this.str = this.str.slice(0, i) + this.str.slice(i + 1, this.str.length);
        return this;
    };
    StringBuilder.prototype.insert = function (i, str) {
        this.str = this.str.slice(0, i) + str + this.str.slice(i, this.str.length);
        return this;
    };
    return StringBuilder;
}());

var TimeUnitEnum;
(function (TimeUnitEnum) {
    TimeUnitEnum[TimeUnitEnum["NANOSECONDS"] = 0] = "NANOSECONDS";
    TimeUnitEnum[TimeUnitEnum["MICROSECONDS"] = 1] = "MICROSECONDS";
    TimeUnitEnum[TimeUnitEnum["MILLISECONDS"] = 2] = "MILLISECONDS";
    TimeUnitEnum[TimeUnitEnum["SECONDS"] = 3] = "SECONDS";
    TimeUnitEnum[TimeUnitEnum["MINUTES"] = 4] = "MINUTES";
    TimeUnitEnum[TimeUnitEnum["HOURS"] = 5] = "HOURS";
    TimeUnitEnum[TimeUnitEnum["DAYS"] = 6] = "DAYS";
})(TimeUnitEnum || (TimeUnitEnum = {}));
var TimeUnitValue;
(function (TimeUnitValue) {
    TimeUnitValue[TimeUnitValue["NANOSECONDS"] = 1] = "NANOSECONDS";
    TimeUnitValue[TimeUnitValue["MICROSECONDS"] = 1000] = "MICROSECONDS";
    TimeUnitValue[TimeUnitValue["MILLISECONDS"] = 1000000] = "MILLISECONDS";
    TimeUnitValue[TimeUnitValue["SECONDS"] = 1000000000] = "SECONDS";
    TimeUnitValue[TimeUnitValue["MINUTES"] = 60000000000] = "MINUTES";
    TimeUnitValue[TimeUnitValue["HOURS"] = 3600000000000] = "HOURS";
    TimeUnitValue[TimeUnitValue["DAYS"] = 86400000000000] = "DAYS";
})(TimeUnitValue || (TimeUnitValue = {}));
var TimeUnit = /** @class */ (function () {
    function TimeUnit(timeOrdinal) {
        if (TimeUnit.ordinals().indexOf(timeOrdinal) > -1) {
            this.timeOrdinal = timeOrdinal;
            this.timeUnit = TimeUnitEnum[timeOrdinal];
        }
        else if (TimeUnit.values().indexOf(timeOrdinal) > -1) {
            this.timeOrdinal = TimeUnit.values().indexOf(timeOrdinal);
            this.timeUnit = timeOrdinal;
        }
    }
    TimeUnit.prototype.name = function () {
        return this.timeUnit;
    };
    Object.defineProperty(TimeUnit.prototype, "ordinal", {
        get: function () {
            return this.timeOrdinal;
        },
        enumerable: true,
        configurable: true
    });
    TimeUnit.ordinals = function () {
        return Object.keys(TimeUnitEnum).filter(function (i) {
            return (typeof TimeUnitEnum[i] === "string") && isFinite(+i);
        }).map(function (i) { return parseInt(i); });
    };
    TimeUnit.values = function () {
        return this.ordinals().map(function (i) {
            return new TimeUnit(i);
        });
    };
    TimeUnit.prototype.valueOf = function () {
        return TimeUnitValue[this.timeUnit];
    };
    TimeUnit.prototype.toNanos = function (duration) {
        // another alternative would have been
        // return Math.trunc((duration * this.toNumber()) / TimeUnitValue.NANOSECONDS);
        return TimeUnit.NANOSECONDS.convert(duration, this);
    };
    TimeUnit.prototype.toMicros = function (duration) {
        return TimeUnit.MICROSECONDS.convert(duration, this);
    };
    TimeUnit.prototype.toMillis = function (duration) {
        return TimeUnit.MILLISECONDS.convert(duration, this);
    };
    TimeUnit.prototype.toSeconds = function (duration) {
        return TimeUnit.SECONDS.convert(duration, this);
    };
    TimeUnit.prototype.toMinutes = function (duration) {
        return TimeUnit.MINUTES.convert(duration, this);
    };
    TimeUnit.prototype.toHours = function (duration) {
        return TimeUnit.HOURS.convert(duration, this);
    };
    TimeUnit.prototype.toDays = function (duration) {
        return TimeUnit.DAYS.convert(duration, this);
    };
    TimeUnit.prototype.convert = function (duration, sourceUnit) {
        return Math.trunc((duration * sourceUnit.valueOf()) / this.valueOf());
    };
    TimeUnit.NANOSECONDS = new TimeUnit(TimeUnitEnum.NANOSECONDS);
    TimeUnit.MICROSECONDS = new TimeUnit(TimeUnitEnum.MICROSECONDS);
    TimeUnit.MILLISECONDS = new TimeUnit(TimeUnitEnum.MILLISECONDS);
    TimeUnit.SECONDS = new TimeUnit(TimeUnitEnum.SECONDS);
    TimeUnit.MINUTES = new TimeUnit(TimeUnitEnum.MINUTES);
    TimeUnit.HOURS = new TimeUnit(TimeUnitEnum.HOURS);
    TimeUnit.DAYS = new TimeUnit(TimeUnitEnum.DAYS);
    return TimeUnit;
}());

var TimeUtils = /** @class */ (function () {
    function TimeUtils() {
    }
    TimeUtils.formatNanos = function (duration, min, max) {
        if (min === void 0) { min = TimeUtils.min(); }
        if (max === void 0) { max = TimeUtils.max(); }
        return TimeUtils.format(duration, TimeUnit.NANOSECONDS, min, max);
    };
    TimeUtils.formatMillis = function (duration, min, max) {
        if (min === void 0) { min = TimeUtils.min(); }
        if (max === void 0) { max = TimeUtils.max(); }
        return TimeUtils.format(duration, TimeUnit.MILLISECONDS, min, max);
    };
    TimeUtils.format = function (duration, sourceUnit, min, max) {
        if (min === void 0) { min = TimeUtils.min(); }
        if (max === void 0) { max = TimeUtils.max(); }
        var res = new StringBuilder();
        var suffix = "";
        if (duration < 0) {
            duration = duration * -1;
            suffix = " ago";
        }
        var current = max;
        while (duration > 0) {
            var temp = current.convert(duration, sourceUnit);
            if (temp > 0) {
                duration -= sourceUnit.convert(temp, current);
                res.append(temp.toString()).append(" ").append(current.name().toLowerCase());
                if (temp < 2) {
                    res.deleteCharAt(res.length - 1);
                }
                res.append(", ");
            }
            if (current.ordinal === min.ordinal) {
                break;
            }
            current = TimeUnit.values()[current.ordinal - 1];
        }
        // we never got a hit, the time is lower than we care about
        if (res.lastIndexOf(", ") < 0) {
            return "0 " + min.name().toLowerCase();
        }
        // yank trailing  ", "
        res.deleteCharAt(res.length - 1);
        res.deleteCharAt(res.length - 1);
        //  convert last ", " to " and"
        var i = res.lastIndexOf(", ");
        if (i > 0) {
            res.deleteCharAt(i);
            res.insert(i, " and");
        }
        res.append(suffix);
        return res.toString();
    };
    TimeUtils.formatHighest = function (duration, max, min) {
        if (min === void 0) { min = this.min(); }
        var units = TimeUnit.values();
        var res = new StringBuilder();
        var current = max;
        while (duration > 0) {
            var temp = current.convert(duration, TimeUnit.MILLISECONDS);
            if (temp > 0) {
                duration -= current.toMillis(temp);
                res.append(temp.toString()).append(" ").append(current.name().toLowerCase());
                if (temp < 2) {
                    res.deleteCharAt(res.length - 1);
                }
                break;
            }
            if (current.ordinal === min.ordinal) {
                break;
            }
            current = units[(current.ordinal - 1)];
        }
        // we never got a hit, the time is lower than we care about
        return res.toString();
    };
    TimeUtils.max = function () {
        var values = TimeUnit.values();
        return values[values.length - 1];
    };
    TimeUtils.min = function () {
        var values = TimeUnit.values();
        return values[0];
    };
    TimeUtils.abbreviateString = function (time) {
        time = time.replace(new RegExp(" days?", 'ig'), "d");
        time = time.replace(new RegExp(" hours?", 'ig'), "hr");
        time = time.replace(new RegExp(" minutes?", 'ig'), "m");
        time = time.replace(new RegExp(" seconds?", 'ig'), "s");
        time = time.replace(new RegExp(" milliseconds?", 'ig'), "ms");
        return time;
    };
    TimeUtils.abbreviate = function (duration, sourceUnit, min, max) {
        if (min === void 0) { min = TimeUtils.min(); }
        if (max === void 0) { max = TimeUtils.max(); }
        if (sourceUnit && typeof duration === "number") {
            var format = TimeUtils.format(duration, sourceUnit, min, max);
            return TimeUtils.abbreviateString(format);
        }
        else if (typeof duration === "string") {
            return TimeUtils.abbreviateString(duration);
        }
        else {
            return 'Wrong duration argument type ' + typeof duration;
            // error wrong abbreviate usage
        }
    };
    return TimeUtils;
}());

var LongDuration = /** @class */ (function () {
    function LongDuration(text, consumer) {
        /*private*/
        this.time = 0;
        this.defaultErrorHandler = function (e) {
            throw e;
        };
        if (((typeof text === 'string') || !text) && ((typeof consumer === 'function' && consumer.length == 1) || !consumer)) {
            this.parseLongDuration(text, (consumer));
        }
        else if (((typeof text === 'number') || !text) && ((typeof consumer === 'number') || !consumer)) {
            this.time = text;
            this.unit = new TimeUnit(consumer);
        }
        else if ((typeof text === 'number') && (consumer instanceof TimeUnit)) {
            this.time = text;
            this.unit = consumer;
        }
        else
            this.invalidFormat(text, this.defaultErrorHandler);
    }
    LongDuration.prototype.valueOf = function () {
        if (!!this.unit) {
            return this.time * this.unit.valueOf();
        }
        else {
            throw new Error('No timme unit');
        }
    };
    LongDuration.prototype.parseLongDuration = function (string, consumer) {
        var strings = string.split(new RegExp(",| and ", 'ig'));
        var total = new LongDuration(0, TimeUnit.MILLISECONDS);
        for (var index = 0; index < strings.length; index++) {
            var value = strings[index];
            {
                var part = new LongDuration(0, TimeUnit.MILLISECONDS);
                var trimedValue = value.trim();
                var number = new StringBuilder();
                var unit = new StringBuilder();
                var i = 0;
                for (; i < trimedValue.length; i++) {
                    var c = trimedValue.charAt(i);
                    if ( /* isDigit *//\d/.test(c[0]) || i === 0 && (function (c) { return c.charCodeAt == null ? c : c.charCodeAt(0); })(c) == '-'.charCodeAt(0)) {
                        number.append(c);
                    }
                    else {
                        break;
                    }
                }
                if (number.length === 0) {
                    this.invalidFormat(trimedValue, this.defaultErrorHandler);
                    return;
                }
                for (; i < trimedValue.length; i++) {
                    var c = trimedValue.charAt(i);
                    if ( /* isLetter *//[a-zA-Z ]/.test(c[0])) {
                        unit.append(c);
                    }
                    else {
                        this.invalidFormat(trimedValue, this.defaultErrorHandler);
                        return;
                    }
                }
                part.time = parseInt(number.toString());
                part.unit = this.parseUnit(unit.toString().trim(), this.defaultErrorHandler);
                if (part.unit == null) {
                    part.unit = TimeUnit.MILLISECONDS;
                }
                total = total.add(part);
            }
        }
        this.time = total.time;
        this.unit = total.unit;
    };
    LongDuration.prototype.getTime = function (unit) {
        return unit.convert(this.time, this.unit);
    };
    /**
     *
     * @param {*} o
     * @return {boolean}
     */
    LongDuration.prototype.equals = function (o) {
        if (this === o) {
            return true;
        }
        if (o == null || this.constructor !== o.constructor) {
            return false;
        }
        var that = o;
        var n = new LongDuration.Normalize(this, that);
        return n.a === n.b;
    };
    /**
     *
     * @return {number}
     */
    LongDuration.prototype.hashCode = function () {
        var result = ((this.time ^ (this.time >>> 32)) | 0);
        result = 31 * result + this.unit.ordinal;
        return result;
    };
    LongDuration.prototype.add = function (that) {
        var n = new LongDuration.Normalize(this, that);
        return new LongDuration(n.a + n.b, n.base);
    };
    LongDuration.prototype.subtract = function (that) {
        var n = new LongDuration.Normalize(this, that);
        return new LongDuration(n.a - n.b, n.base);
    };
    LongDuration.prototype.invalidFormat = function (text, errorHandler) {
        (function (target) { return (typeof target === 'function') ? target(Object.defineProperty(new Error("Illegal duration format: \'" + text + "\'.  Valid examples are \'10s\' or \'10 seconds\'."), '__classes', {
            configurable: true,
            value: ['java.lang.Throwable', 'java.lang.Object', 'java.lang.RuntimeException', 'java.lang.IllegalArgumentException', 'java.lang.Exception']
        })) : target.accept(Object.defineProperty(new Error("Illegal duration format: \'" + text + "\'.  Valid examples are \'10s\' or \'10 seconds\'."), '__classes', {
            configurable: true,
            value: ['java.lang.Throwable', 'java.lang.Object', 'java.lang.RuntimeException', 'java.lang.IllegalArgumentException', 'java.lang.Exception']
        })); })(errorHandler);
    };
    /**
     *
     * @return {string}
     */
    LongDuration.prototype.toString = function () {
        var sb = new StringBuilder();
        sb.append(this.time);
        if (this.unit != null) {
            sb.append(" ");
            sb.append(this.unit);
        }
        return sb.toString();
    };
    /**
     * Converts time to a human readable format within the specified range
     *
     * @param {TimeUnit} max      the highest time unit of interest
     * @return {string}
     */
    LongDuration.prototype.formatHighest = function (max) {
        if (max === void 0) { max = TimeUtils.max(); }
        return TimeUtils.format(this.time, this.unit, TimeUnit.MILLISECONDS, max);
    };
    LongDuration.prototype.parseUnit = function (u, errorHandler) {
        if (u.length === 0) {
            throw new Error('Invalid unit');
        }
        if (equalsIgnoreCase("NANOSECONDS", u))
            return TimeUnit.NANOSECONDS;
        if (equalsIgnoreCase("NANOSECOND", u))
            return TimeUnit.NANOSECONDS;
        if (equalsIgnoreCase("NANOS", u))
            return TimeUnit.NANOSECONDS;
        if (equalsIgnoreCase("NANO", u))
            return TimeUnit.NANOSECONDS;
        if (equalsIgnoreCase("NS", u))
            return TimeUnit.NANOSECONDS;
        if (equalsIgnoreCase("MICROSECONDS", u))
            return TimeUnit.MICROSECONDS;
        if (equalsIgnoreCase("MICROSECOND", u))
            return TimeUnit.MICROSECONDS;
        if (equalsIgnoreCase("MICROS", u))
            return TimeUnit.MICROSECONDS;
        if (equalsIgnoreCase("MICRO", u))
            return TimeUnit.MICROSECONDS;
        if (equalsIgnoreCase("MILLISECONDS", u))
            return TimeUnit.MILLISECONDS;
        if (equalsIgnoreCase("MILLISECOND", u))
            return TimeUnit.MILLISECONDS;
        if (equalsIgnoreCase("MILLIS", u))
            return TimeUnit.MILLISECONDS;
        if (equalsIgnoreCase("MILLI", u))
            return TimeUnit.MILLISECONDS;
        if (equalsIgnoreCase("MS", u))
            return TimeUnit.MILLISECONDS;
        if (equalsIgnoreCase("SECONDS", u))
            return TimeUnit.SECONDS;
        if (equalsIgnoreCase("SECOND", u))
            return TimeUnit.SECONDS;
        if (equalsIgnoreCase("SEC", u))
            return TimeUnit.SECONDS;
        if (equalsIgnoreCase("S", u))
            return TimeUnit.SECONDS;
        if (equalsIgnoreCase("MINUTES", u))
            return TimeUnit.MINUTES;
        if (equalsIgnoreCase("MINUTE", u))
            return TimeUnit.MINUTES;
        if (equalsIgnoreCase("MIN", u))
            return TimeUnit.MINUTES;
        if (equalsIgnoreCase("M", u))
            return TimeUnit.MINUTES;
        if (equalsIgnoreCase("HOURS", u))
            return TimeUnit.HOURS;
        if (equalsIgnoreCase("HOUR", u))
            return TimeUnit.HOURS;
        if (equalsIgnoreCase("HRS", u))
            return TimeUnit.HOURS;
        if (equalsIgnoreCase("HR", u))
            return TimeUnit.HOURS;
        if (equalsIgnoreCase("H", u))
            return TimeUnit.HOURS;
        if (equalsIgnoreCase("DAYS", u))
            return TimeUnit.DAYS;
        if (equalsIgnoreCase("DAY", u))
            return TimeUnit.DAYS;
        if (equalsIgnoreCase("D", u))
            return TimeUnit.DAYS;
        this.invalidFormat(u, errorHandler);
        throw new Error('Invalid format');
    };
    return LongDuration;
}());
(function (LongDuration) {
    var Normalize = /** @class */ (function () {
        function Normalize(a, b) {
            this.a = 0;
            this.b = 0;
            this.base = Normalize.lowest(a, b);
            this.a = a.unit == null ? a.time : this.base.convert(a.time, a.unit);
            this.b = b.unit == null ? b.time : this.base.convert(b.time, b.unit);
        }
        Normalize.lowest = function (a, b) {
            if (a.time === 0 || a.unit == null)
                return b.unit;
            if (b.time === 0 || b.unit == null)
                return a.unit;
            return TimeUnit.values()[Math.min(a.unit.ordinal, b.unit.ordinal)];
        };
        return Normalize;
    }());
    LongDuration.Normalize = Normalize;
})(LongDuration || (LongDuration = {}));

/**
 * @ngdoc overview
 * @name ts-tomitribe-util
 * @function
 *
 * @description
 * Tomitribe utilities converted for ts usage
 *
 * @example
      import { TimeUnit, LongDuration } from 'ts-tomitribe-util';

      let duration = new LongDuration("30 minutes, 20 seconds and 15 nanoseconds");
 */

/**
 * @module
 * @description
 * Tomitribe-utils package.
 */

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
var Join = /** @class */ (function () {
    function Join() {
    }
    Join.join = function (delimiter) {
        var collection = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            collection[_i - 1] = arguments[_i];
        }
        if (collection.length === 0) {
            return "";
        }
        else if (collection[0] instanceof Array) {
            collection = collection[0];
        }
        var sb = new StringBuilder();
        for (var _a = 0, collection_1 = collection; _a < collection_1.length; _a++) {
            var obj = collection_1[_a];
            sb.append(obj).append(delimiter);
        }
        return sb.toString().substring(0, sb.length - delimiter.length);
    };
    return Join;
}());

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
var MissingAlgorithmException = /** @class */ (function (_super) {
    __extends(MissingAlgorithmException, _super);
    function MissingAlgorithmException() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return MissingAlgorithmException;
}(AuthenticationException));

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
var MissingKeyIdException = /** @class */ (function (_super) {
    __extends(MissingKeyIdException, _super);
    function MissingKeyIdException() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return MissingKeyIdException;
}(AuthenticationException));

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
var MissingRequiredHeaderException = /** @class */ (function (_super) {
    __extends(MissingRequiredHeaderException, _super);
    function MissingRequiredHeaderException(key) {
        return _super.call(this, key) || this;
    }
    return MissingRequiredHeaderException;
}(AuthenticationException));

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
var MissingSignatureException = /** @class */ (function (_super) {
    __extends(MissingSignatureException, _super);
    function MissingSignatureException() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return MissingSignatureException;
}(AuthenticationException));

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
var RSA$1 = /** @class */ (function () {
    function RSA() {
    }
    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    RSA.privateKeyFromPKCS8 = function (pkcs8) {
        try {
            return jwkJs.RSA.JWKfromRSA(jwkJs.AB2s(pkcs8), "private");
        }
        catch (e) {
            throw new Error(e);
        }
    };
    /**
     * Returns a private key constructed from the given DER bytes in PKCS#1 format.
     */
    RSA.privateKeyFromPKCS1 = function (pkcs1) {
        try {
            return jwkJs.RSA.JWKfromRSA(jwkJs.AB2s(pkcs1), "private");
        }
        catch (e) {
            throw new Error(e);
        }
    };
    /**
     * Returns a public key constructed from the given DER bytes.
     */
    RSA.publicKeyFrom = function (derBytes) {
        try {
            return jwkJs.RSA.JWKfromRSA(jwkJs.AB2s(derBytes), "public");
        }
        catch (e) {
            throw new Error(e);
        }
    };
    RSA.RSA = "RSA";
    return RSA;
}());

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
var BufferedReader = /** @class */ (function () {
    function BufferedReader(str) {
        this.str = str.split(/\r?\n/);
        this.cursor = 0;
    }
    BufferedReader.prototype.readline = function (cursor) {
        if (cursor) {
            this.cursor = cursor;
        }
        var res = this.str.length > this.cursor ? this.str[this.cursor] : null;
        this.cursor++;
        return res;
    };
    return BufferedReader;
}());
var PEM$1 = /** @class */ (function () {
    function PEM() {
    }
    PEM.readPrivateKey = function (is) {
        var objects = PEM.readPEMObjects(is);
        for (var _i = 0, objects_1 = objects; _i < objects_1.length; _i++) {
            var object = objects_1[_i];
            switch (object.getPEMObjectType()) {
                case PEMObjectType.PRIVATE_KEY_PKCS:
                    return RSA$1.privateKeyFromPKCS1(object.getDerBytes());
                case PEMObjectType.PRIVATE_EC_KEY_PKCS8:
                    return EC$1.privateKeyFromPKCS8(object.getDerBytes());
                case PEMObjectType.PRIVATE_KEY_PKCS8:
                    try {
                        return RSA$1.privateKeyFromPKCS8(object.getDerBytes());
                    }
                    catch (e) {
                        return EC$1.privateKeyFromPKCS8(object.getDerBytes());
                    }
                default:
                    break;
            }
        }
        throw new Error("Found no private key");
    };
    PEM.readPublicKey = function (is) {
        var objects = PEM.readPEMObjects(is);
        for (var _i = 0, objects_2 = objects; _i < objects_2.length; _i++) {
            var object = objects_2[_i];
            switch (object.getPEMObjectType()) {
                case PEMObjectType.PUBLIC_KEY_X509:
                    try {
                        return RSA$1.publicKeyFrom(object.getDerBytes());
                    }
                    catch (e) {
                        return EC$1.publicKeyFrom(object.getDerBytes());
                    }
                default:
                    break;
            }
        }
        throw new Error("Found no private key");
    };
    PEM.readPEMObjects = function (is) {
        var reader = new BufferedReader(is);
        try {
            var pemContents = [];
            var readingContent = false;
            var beginMarker = "";
            var endMarker = "";
            var sb = new StringBuilder();
            var line = void 0;
            while ((line = reader.readline()) != null) {
                {
                    if (readingContent) {
                        if (line.includes(endMarker)) {
                            pemContents.push(new PEMObject(beginMarker, jwkJs.s2AB(sb.toString())));
                            readingContent = false;
                        }
                        else {
                            sb.append(line.trim());
                        }
                    }
                    else {
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
        }
        finally {
        }
    };
    PEM.BEGIN_MARKER = "-----BEGIN ";
    return PEM;
}());
var PEMObject = /** @class */ (function () {
    function PEMObject(beginMarker, derBytes) {
        this.beginMarker = beginMarker;
        this.derBytes = derBytes;
    }
    PEMObject.prototype.getBeginMarker = function () {
        return this.beginMarker;
    };
    PEMObject.prototype.getDerBytes = function () {
        return this.derBytes[0];
    };
    PEMObject.prototype.getPEMObjectType = function () {
        return PEMObjectType.fromBeginMarker(this.beginMarker);
    };
    return PEMObject;
}());
var PEMObjectType = /** @class */ (function () {
    function PEMObjectType(beginMarker) {
        this.beginMarker = beginMarker;
        PEMObjectType.values.push(this);
    }
    PEMObjectType.prototype.getBeginMarker = function () {
        return this.beginMarker;
    };
    PEMObjectType.fromBeginMarker = function (beginMarker) {
        return PEMObjectType.values.find(function (objType) { return objType.getBeginMarker() === beginMarker; });
    };
    PEMObjectType.values = [];
    PEMObjectType.PRIVATE_KEY_PKCS = new PEMObjectType("-----BEGIN RSA PRIVATE KEY-----");
    PEMObjectType.PRIVATE_EC_KEY_PKCS8 = new PEMObjectType("-----BEGIN EC PRIVATE KEY-----"); // RFC-5915
    PEMObjectType.PRIVATE_KEY_PKCS8 = new PEMObjectType("-----BEGIN PRIVATE KEY-----");
    PEMObjectType.PUBLIC_KEY_X509 = new PEMObjectType("-----BEGIN PUBLIC KEY-----");
    PEMObjectType.CERTIFICATE_X509 = new PEMObjectType("-----BEGIN CERTIFICATE-----");
    return PEMObjectType;
}());

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
var UnparsableSignatureException = /** @class */ (function (_super) {
    __extends(UnparsableSignatureException, _super);
    function UnparsableSignatureException(message, cause) {
        return _super.call(this, message, cause) || this;
    }
    return UnparsableSignatureException;
}(AuthenticationException));

var Signature = /** @class */ (function () {
    function Signature(keyId, algorithm, signature) {
        var headers = [];
        for (var _i = 3; _i < arguments.length; _i++) {
            headers[_i - 3] = arguments[_i];
        }
        /**
         * REQUIRED.  The `signature` parameter is a base 64 encoded digital
         * signature, as described in RFC 4648 [RFC4648], Section 4 [4].  The
         * client uses the `algorithm` and `headers` signature parameters to
         * form a canonicalized `signing string`.  This `signing string` is then
         * signed with the key associated with `keyId` and the algorithm
         * corresponding to `algorithm`.  The `signature` parameter is then set
         * to the base 64 encoding of the signature.
         */
        this.headers = ["date"];
        if (keyId == null || /* isEmpty */ (keyId.trim().length === 0)) {
            throw new Error("keyId is required.");
        }
        if (algorithm == null) {
            throw new Error("algorithm is required.");
        }
        this.keyId = keyId;
        this.algorithm = typeof algorithm === 'string' ? Signature.getAlgorithm(algorithm) : algorithm;
        this.signature = signature;
        if (headers.length !== 0) {
            if (headers[0] instanceof Array) {
                this.headers = this.lowercase(headers[0]);
            }
            else {
                this.headers = this.lowercase(headers);
            }
        }
        this.headers = this.headers.slice(0); // unmodifiableList
    }
    Signature.getAlgorithm = function (algorithm) {
        if (algorithm == null)
            throw new Error("Algorithm cannot be null");
        return Algorithm.get(algorithm);
    };
    Signature.prototype.lowercase = function (headers) {
        var list = ([]);
        for (var header in headers) {
            list.push(header.toLowerCase());
        }
        return list;
    };
    Signature.prototype.getKeyId = function () {
        return this.keyId;
    };
    Signature.prototype.getAlgorithm = function () {
        return this.algorithm;
    };
    Signature.prototype.getSignature = function () {
        return this.signature;
    };
    Signature.prototype.getHeaders = function () {
        return this.headers;
    };
    Signature.fromString = function (authorization) {
        try {
            authorization = Signature.normalize(authorization);
            var map = ({});
            var matcher = { group: [] };
            while ((matcher.group = this.RFC_2617_PARAM.exec(authorization)) !== null) {
                var key = matcher.group[1].toLowerCase();
                var value = matcher.group[2];
                map.put(key, value);
            }
            var headers = ([]);
            var headerString = (function (m, k) { return m[k] === undefined ? null : m[k]; })(map, "headers");
            if (headerString != null) {
                /* addAll */
                (function (l1, l2) { return l1.push.apply(l1, l2); })(headers, /* asList */ headerString.toLowerCase().split(" +").slice(0));
            }
            var keyid = (function (m, k) { return m[k] === undefined ? null : m[k]; })(map, "keyid");
            if (keyid == null)
                throw new MissingKeyIdException();
            var algorithm = (function (m, k) { return m[k] === undefined ? null : m[k]; })(map, "algorithm");
            if (algorithm == null)
                throw new MissingAlgorithmException();
            var signature = (function (m, k) { return m[k] === undefined ? null : m[k]; })(map, "signature");
            if (signature == null)
                throw new MissingSignatureException();
            var parsedAlgorithm = Algorithm.get(algorithm);
            return new Signature(keyid, parsedAlgorithm, signature, headers);
        }
        catch (__e) {
            if (__e != null && __e instanceof AuthenticationException) {
                var e = __e;
                throw e;
            }
            else if (__e != null && __e instanceof Error) {
                var e = __e;
                throw new UnparsableSignatureException(authorization, e);
            }
        }
    };
    /*private*/
    Signature.normalize = function (authorization) {
        var start = "signature ";
        var prefix = authorization.substring(0, start.length).toLowerCase();
        if ( /* equals */(function (o1, o2) {
            if (o1 && o1.equals) {
                return o1.equals(o2);
            }
            else {
                return o1 === o2;
            }
        })(prefix, start)) {
            authorization = authorization.substring(start.length);
        }
        return authorization.trim();
    };
    /**
     *
     * @return {string}
     */
    Signature.prototype.toString = function () {
        return "Signature " + "keyId=\"" + this.keyId + '\"' +
            ",algorithm=\"" + this.algorithm + '\"' +
            ",headers=\"" + Join.join(" ", this.headers) + '\"' +
            ",signature=\"" + this.signature + '\"';
    };
    Signature.RFC_2617_PARAM = /(\\w+)=\"([^\"]*)\""/;
    return Signature;
}());

var Signatures = /** @class */ (function () {
    function Signatures() {
    }
    Signatures.createSigningString = function (required, method, uri, headers) {
        headers = Signatures.lowercase(headers);
        var list = [];
        for (var _i = 0, required_1 = required; _i < required_1.length; _i++) {
            var key = required_1[_i];
            if ("(request-target)" === key) {
                method = Signatures.lowercase(method);
                list.push(Join.join(" ", "(request-target):", method, uri));
            }
            else {
                var value = headers[key];
                if (value == null)
                    throw new MissingRequiredHeaderException(key);
                list.push(key + ": " + value);
            }
        }
        return Join.join("\n", list);
    };
    Signatures.lowercase$ = function (headers) {
        return Object.keys(headers).reduce(function (newObj, key) {
            var val = headers[key];
            newObj[key.toLowerCase()] = (typeof val === 'object') ? Signatures.lowercase$(val) : val;
            return newObj;
        }, {});
    };
    Signatures.lowercase = function (headers) {
        if (typeof headers === 'string') {
            return headers.toLowerCase();
        }
        else {
            return Signatures.lowercase$(headers);
        }
    };
    return Signatures;
}());

//export * from "./Verifier";

export { Algorithm, AuthenticationException, Base64, BufferedReader, Collection, EC$1 as EC, Join, MissingAlgorithmException, MissingKeyIdException, MissingRequiredHeaderException, MissingSignatureException, PEM$1 as PEM, PEMObject, PEMObjectType, RSA$1 as RSA, RuntimeException, Signature, Signatures, System, UnparsableSignatureException, UnsupportedAlgorithmException };
//# sourceMappingURL=http-signatures-js.esm.js.map
