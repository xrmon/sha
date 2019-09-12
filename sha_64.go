package sha

import (
    "encoding/binary"
)

/* Functions for SHA2 functions with 64-bit words (SHA-384 & SHA-512) */

// SHA-384 & SHA-512 constants
var K_64 = [80]uint64{0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817}

func PadMessage64(M []byte) []byte {
    /* Takes a message, M and adds padding bits to a multiple of 1024 */
    // Get the length in bits of the input
    var l int = len(M) * 8
    // Calculate smallest non-negative k such that l + 1 + k = 896 (mod 1024)
    var k int = -1
    for p := 0; k < 0; p++ {
        k = 896 - l + 1024*p
    }
    // Extend M to contain space for padding
    M = append(M, make([]uint8, (k + 1 + 128)/8)...)
    // Add a '1' bit followed by k '0' bits
    M[l/8] = 0x80
    for i := 1+l/8; i < 1+(l+k-7)/8; i++ {
        M[i] = 0
    }
    // Add the value of 'l' as a 128-bit big-endian integer
    binary.BigEndian.PutUint64(M[(l+k+1)/8:], uint64(l >> 64))
    binary.BigEndian.PutUint64(M[8+(l+k+1)/8:], uint64(l % 0x100000000))
    return M
}

func ParseMessage64(M []byte) [][16]uint64 {
    /* Takes a padded message, M (whose length is a multiple of 1024),
     * and splits it into N blocks of 1024 bits (16 64-bit words) */
    var word uint64
    var pos int
    // Calculate the number of blocks needed
    N := len(M)/128
    // Create a splice of 1024-bit blocks
    blocks := make([][16]uint64, N)
    // Process each block
    for i := 0; i < N; i++ {
        // Process each 64-bit word in the block
        for j := 0; j < 16; j++ {
            pos  = i*128 + j*8
            word = binary.BigEndian.Uint64(M[pos:pos+8])
            blocks[i][j] = word
        }
    }
    return blocks
}

func SHA2_64(input []byte, H0 [8]uint64) [64]byte {
    /* Takes an input, and the initial hash value, then computes a
     * SHA2 hash using 64-bit words (used for SHA384 & SHA512)
     */
    /* PREPROCESSING */
    // Copy the input into a new slice
    message := make([]byte, len(input))
    copy(message, input)
    // Pad the message
    message = PadMessage64(message)
    // Parse the message into a series of 512-bit blocks
    var M [][16]uint64
    M = ParseMessage64(message)
    // Initialize the hash value, H, to the initial hash value
    var H [8]uint64
    copy(H[:], H0[:])
    /* HASH COMPUTATION */
    // All additions are automatically performed modulo 2^32
    var W [80]uint64  // Message schedule
    var a, b, c, d, e, f, g, h uint64  // Working variables
    var T1, T2 uint64  // Temporary words
    N := len(M)  // Number of blocks

    for i := 0; i < N; i++ {
        // Prepare message schedule
        for t := 0; t < 80; t++ {
            if t < 16 {
                W[t] = M[i][t]
            } else {
                W[t] = SmallSigma1_64(W[t-2]) + W[t-7] + SmallSigma0_64(W[t-15]) + W[t-16]
            }
        }
        // Initialize working variables
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]
        // Manipulate working variables
        for t := 0; t < 80; t++ {
            T1 = h + BigSigma1_64(e) + Ch_64(e, f, g) + K_64[t] + W[t]
            T2 = BigSigma0_64(a) + Maj_64(a, b, c)
            h = g
            g = f
            f = e
            e = d + T1
            d = c
            c = b
            b = a
            a = T1 + T2
        }
        // Compute intermediate hash values
        H[0] = a + H[0]
        H[1] = b + H[1]
        H[2] = c + H[2]
        H[3] = d + H[3]
        H[4] = e + H[4]
        H[5] = f + H[5]
        H[6] = g + H[6]
        H[7] = h + H[7]
    }
    // Combine final H values into the output hash
    var output [64]byte
    for i := 0; i < 8; i++ {
        pos := i*8
        binary.BigEndian.PutUint64(output[pos:pos+8], H[i])
    }
    return output
}

func SHA384(input []byte) [48]byte {
    /* Takes an input and returns the SHA384 hash */
    // Initial hash value
    var H = [8]uint64{0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4}
    // Calculate full 512-bit hash
    var hash [64]byte = SHA2_64(input, H)
    // Truncate to 384 bits
    var output [48]byte
    copy(output[:], hash[:48])
    return output
}

func SHA512(input []byte) [64]byte {
    /* Takes an input and returns the SHA512 hash */
    // Initial hash value
    var H = [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}
    // Calculate hash and return
    return SHA2_64(input, H)
}
