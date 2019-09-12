package sha

// Primitives needed for SHA1 & SHA2 functions

/* Primitives for 32-bit words */

func SHR(x uint32, n uint32) uint32 {
    /* Zero shift right by n bits */
    return x >> n
}

func ROTR(x uint32, n uint32) uint32 {
    /* Circular shift x right by n bits */
    return (x >> n) | (x << (32 - n))
}

func ROTL(x uint32, n uint32) uint32 {
    /* Circular shift x left by n bits */
    return (x << n) | (x >> (32 - n))
}

func Ch(x uint32, y uint32, z uint32) uint32 {
    return (x & y) ^ (^x & z)
}

func Maj(x uint32, y uint32, z uint32) uint32 {
    return (x & y) ^ (x & z) ^ (y & z)
}

func BigSigma0(x uint32) uint32 {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
}

func BigSigma1(x uint32) uint32 {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
}

func SmallSigma0(x uint32) uint32 {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)
}

func SmallSigma1(x uint32) uint32 {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)
}

func Parity(x uint32, y uint32, z uint32) uint32 {
    return x ^ y ^ z
}

func F(x uint32, y uint32, z uint32, t int) uint32 {
    if t < 20 {
        return Ch(x, y, z)
    } else if t < 40 {
        return Parity(x, y, z)
    } else if t < 60 {
        return Maj(x, y, z)
    } else {
        return Parity(x, y, z)
    }
}

/* Primitives for 64-bit words */

func SHR_64(x uint64, n uint64) uint64 {
    /* Zero shift right by n bits */
    return x >> n
}

func ROTR_64(x uint64, n uint64) uint64 {
    /* Circular shift x right by n bits */
    return (x >> n) | (x << (64 - n))
}

func ROTL_64(x uint64, n uint64) uint64 {
    /* Circular shift x left by n bits */
    return (x << n) | (x >> (64 - n))
}

func Ch_64(x uint64, y uint64, z uint64) uint64 {
    return (x & y) ^ (^x & z)
}

func Maj_64(x uint64, y uint64, z uint64) uint64 {
    return (x & y) ^ (x & z) ^ (y & z)
}

func BigSigma0_64(x uint64) uint64 {
    return ROTR_64(x, 28) ^ ROTR_64(x, 34) ^ ROTR_64(x, 39)
}

func BigSigma1_64(x uint64) uint64 {
    return ROTR_64(x, 14) ^ ROTR_64(x, 18) ^ ROTR_64(x, 41)
}

func SmallSigma0_64(x uint64) uint64 {
    return ROTR_64(x, 1) ^ ROTR_64(x, 8) ^ SHR_64(x, 7)
}

func SmallSigma1_64(x uint64) uint64 {
    return ROTR_64(x, 19) ^ ROTR_64(x, 61) ^ SHR_64(x, 6)
}
