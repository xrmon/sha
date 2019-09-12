package sha

import (
    "encoding/binary"
)

/* Functions for algorithms with 32-bit words (SHA-1, SHA-224 & SHA-256) */

// SHA-224 & SHA-256 constants
var K = [64]uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

func PadMessage32(M []byte) []byte {
    /* Takes a message, M and adds padding bits to a multiple of 512 */
    // Get the length in bits of the input
    var l int = len(M) * 8
    // Calculate smallest non-negative k such that l + 1 + k = 448 (mod 512)
    var k int = -1
    for p := 0; k < 0; p++ {
        k = 447 - l + 512*p
    }
    // Extend M to contain space for padding
    M = append(M, make([]uint8, (k + 1 + 64)/8)...)
    // Add a '1' bit followed by k '0' bits
    M[l/8] = 0x80
    for i := 1+l/8; i < 1+(l+k-7)/8; i++ {
        M[i] = 0
    }
    // Add the value of 'l' as a 64-bit big-endian integer
    binary.BigEndian.PutUint64(M[(l+k+1)/8:], uint64(l))
    return M
}

func ParseMessage32(M []byte) [][16]uint32 {
    /* Takes a padded message, M (whose length is a multiple of 512),
     * and splits it into N blocks of 512 bits (16 32-bit words) */
    var word uint32
    var pos int
    // Calculate the number of blocks needed
    N := len(M)/64
    // Create a splice of 512-bit blocks
    blocks := make([][16]uint32, N)
    // Process each block
    for i := 0; i < N; i++ {
        // Process each 32-bit word in the block
        for j := 0; j < 16; j++ {
            pos  = i*64 + j*4
            word = binary.BigEndian.Uint32(M[pos:pos+4])
            blocks[i][j] = word
        }
    }
    return blocks
}

func SHA2_32(input []byte, H0 [8]uint32) [32]byte {
    /* Takes an input, and the initial hash value, then computes a
     * SHA2 hash using 32-bit words (used for SHA224 & SHA256)
     */
    /* PREPROCESSING */
    // Copy the input into a new slice
    message := make([]byte, len(input))
    copy(message, input)
    // Pad the message
    message = PadMessage32(message)
    // Parse the message into a series of 512-bit blocks
    var M [][16]uint32
    M = ParseMessage32(message)
    // Initialize the hash value, H, to the initial hash value
    var H [8]uint32
    copy(H[:], H0[:])
    /* HASH COMPUTATION */
    // All additions are automatically performed modulo 2^32
    var W [64]uint32  // Message schedule
    var a, b, c, d, e, f, g, h uint32  // Working variables
    var T1, T2 uint32  // Temporary words
    N := len(M)  // Number of blocks

    for i := 0; i < N; i++ {
        // Prepare message schedule
        for t := 0; t < 64; t++ {
            if t < 16 {
                W[t] = M[i][t]
            } else {
                W[t] = SmallSigma1(W[t-2]) + W[t-7] + SmallSigma0(W[t-15]) + W[t-16]
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
        for t := 0; t < 64; t++ {
            T1 = h + BigSigma1(e) + Ch(e, f, g) + K[t] + W[t]
            T2 = BigSigma0(a) + Maj(a, b, c)
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
    var output [32]byte
    for i := 0; i < 8; i++ {
        pos := i*4
        binary.BigEndian.PutUint32(output[pos:pos+4], H[i])
    }
    return output
}

func SHA224(input []byte) [28]byte {
    /* Takes an input and returns the SHA224 hash */
    // Initial hash value
    var H = [8]uint32{0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4}
    // Calculate full 256-bit hash
    var hash [32]byte = SHA2_32(input, H)
    // Truncate to 224 bits
    var output [28]byte
    copy(output[:], hash[:28])
    return output
}

func SHA256(input []byte) [32]byte {
    /* Takes an input and returns the SHA256 hash */
    // Initial hash value
    var H = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
    // Calculate hash and return
    return SHA2_32(input, H)
}

func SHA1_K(t int) uint32 {
    /* Returns the SHA1 constant for a given value of t */
    if t < 20 {
        return 0x5a827999
    } else if t < 40 {
        return 0x6ed9eba1
    } else if t < 60 {
        return 0x8f1bbcdc
    } else {
        return 0xca62c1d6
    }
}

func SHA1(input []byte) [20]byte {
    /* Takes an input and returns the SHA1 hash */
    /* PREPROCESSING */
    // Copy the input into a new slice
    message := make([]byte, len(input))
    copy(message, input)
    // Pad the message
    message = PadMessage32(message)
    // Parse the message into a series of 512-bit blocks
    var M [][16]uint32
    M = ParseMessage32(message)
    // Set the initial hash value
    var H = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
    /* HASH COMPUTATION */
    // All additions are automatically performed modulo 2^32
    var W [80]uint32  // Message schedule
    var a, b, c, d, e uint32  // Working variables
    var T uint32  // Temporary word
    N := len(M)  // Number of blocks

    for i := 0; i < N; i++ {
        // Prepare message schedule
        for t := 0; t < 80; t++ {
            if t < 16 {
                W[t] = M[i][t]
            } else {
                W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)
            }
        }
        // Initialize working variables
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        // Manipulate working variables
        for t := 0; t < 80; t++ {
            T = ROTL(a, 5) + F(b, c, d, t) + e + SHA1_K(t) + W[t]
            e = d
            d = c
            c = ROTL(b, 30)
            b = a
            a = T
        }
        // Compute intermediate hash values
        H[0] = a + H[0]
        H[1] = b + H[1]
        H[2] = c + H[2]
        H[3] = d + H[3]
        H[4] = e + H[4]
    }
    // Combine final H values into the output hash
    var output [20]byte
    for i := 0; i < 5; i++ {
        pos := i*4
        binary.BigEndian.PutUint32(output[pos:pos+4], H[i])
    }
    return output
}
