export declare class Base64 {
    /**
     * Chunk size per RFC 2045 section 6.8.
     *
     * <p>The {@value} character limit does not count the trailing CRLF, but counts
     * all other characters, including any equal signs.</p>
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 6.8</a>
     */
    static CHUNK_SIZE: number;
    /**
     * Chunk separator per RFC 2045 section 2.1.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 2.1</a>
     */
    static CHUNK_SEPARATOR: number[];
    /**
     * The base length.
     */
    static BASELENGTH: number;
    /**
     * Lookup length.
     */
    static LOOKUPLENGTH: number;
    /**
     * Used to calculate the number of bits in a byte.
     */
    static EIGHTBIT: number;
    /**
     * Used when encoding something which has fewer than 24 bits.
     */
    static SIXTEENBIT: number;
    /**
     * Used to determine how many bits data contains.
     */
    static TWENTYFOURBITGROUP: number;
    /**
     * Used to get the number of Quadruples.
     */
    static FOURBYTE: number;
    /**
     * Used to test the sign of a byte.
     */
    static SIGN: number;
    /**
     * Byte used to pad output.
     */
    static PAD: number;
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
    static readonly base64Alphabet: number[];
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
    static readonly lookUpBase64Alphabet: number[];
    /**
     * Returns whether or not the <code>octect</code> is in the base 64 alphabet.
     *
     * @param {number} octect The value to test
     * @return {boolean} <code>true</code> if the value is defined in the the base 64 alphabet, <code>false</code> otherwise.
     * @private
     */
    private static isBase64;
    /**
     * Encodes binary data using the base64 algorithm, optionally
     * chunking the output into 76 character blocks.
     *
     * @param {Array} binaryData Array containing binary data to encode.
     * @param {boolean} isChunked if <code>true</code> this encoder will chunk
     * the base64 output into 76 character blocks
     * @return {Array} Base64-encoded data.
     */
    static encodeBase64(binaryData: number[], isChunked?: boolean): number[];
    /**
     * Decodes Base64 data into octects
     *
     * @param {Array} base64Data Byte array containing Base64 data
     * @return {Array} Array containing decoded data.
     */
    static decodeBase64(base64Data: number[]): number[];
    /**
     * Discards any characters outside of the base64 alphabet, per
     * the requirements on page 25 of RFC 2045 - "Any characters
     * outside of the base64 alphabet are to be ignored in base64
     * encoded data."
     *
     * @param {Array} data The base-64 encoded data to groom
     * @return {Array} The data, less non-base64 characters (see RFC 2045).
     */
    static discardNonBase64(data: number[]): number[];
}
