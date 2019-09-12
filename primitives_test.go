package sha

import "testing"

/* Tests for primitives using 32-bit words */

func TestSHR(t *testing.T) {
    x := uint32(0xFF)  // Input:    0000 0000 0000 0000 0000 0000 1111 1111
    n := uint32(4)
    x = SHR(x, n)      // Expected: 0000 0000 0000 0000 0000 0000 0000 1111
    if x != 0xF {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x0000000F\n", x)
    }
}

func TestROTR(t *testing.T) {
    x := uint32(5)  // Input:    0000 0000 0000 0000 0000 0000 0000 0101
    n := uint32(2)
    x = ROTR(x, n)  // Expected: 0100 0000 0000 0000 0000 0000 0000 0001
    if x != 0x40000001 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x40000001\n", x)
    }

}

func TestROTL(t *testing.T) {
    x := uint32(0x10000000) // Input: 0001 0000 0000 0000 0000 0000 0000 0000
    n := uint32(4)
    x = ROTL(x, n)       // Expected: 0000 0000 0000 0000 0000 0000 0000 0001
    if x != 1 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x00000001\n", x)
    }

}

func TestCh(t *testing.T) {
    x := uint32(0xFFFF0000)    // x: 1111 1111 1111 1111 0000 0000 0000 0000
    y := uint32(0x33333333)    // y: 0011 0011 0011 0011 0011 0011 0011 0011
    z := uint32(0xCCCCCCCC)    // z: 1100 1100 1100 1100 1100 1100 1100 1100
    result := Ch(x,y,z) // Expected: 0011 0011 0011 0011 1100 1100 1100 1100
    if result != 0x3333CCCC {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x3333CCCC\n", result)
    }
}

func TestMaj(t *testing.T) {
    x := uint32(0xFF00FF00)     // x: 1111 1111 0000 0000 1111 1111 0000 0000
    y := uint32(0xA0A0A0A0)     // y: 1010 0000 1010 0000 1010 0000 1010 0000
    z := uint32(0x0B0B0B0B)     // z: 0000 1011 0000 1011 0000 1011 0000 1011
    result := Maj(x,y,z) // Expected: 1010 1011 0000 0000 1010 1011 0000 0000
    if result != 0xAB00AB00 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0xAB00AB00\n", result)
    }
}

func TestBigSigma0(t *testing.T) {
    x := uint32(1)    // Input:    0000 0000 0000 0000 0000 0000 0000 0001
    x = BigSigma0(x)  // Expected: 0100 0000 0000 1000 0000 0100 0000 0000
    if x != 0x40080400 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x40080400\n", x)
    }
}

func TestBigSigma1(t *testing.T) {
    x := uint32(1)    // Input:    0000 0000 0000 0000 0000 0000 0000 0001
    x = BigSigma1(x)  // Expected: 0000 0100 0010 0000 0000 0000 1000 0000
    if x != 0x04200080 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x04200080\n", x)
    }
}

func TestSmallSigma0(t *testing.T) {
    x := uint32(0x80)   // Input:    0000 0000 0000 0000 0000 0000 1000 0000
    x = SmallSigma0(x)  // Expected: 0000 0000 0010 0000 0000 0000 0001 0001
    if x != 0x00200011 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x00200011\n", x)
    }
}

func TestSmallSigma1(t *testing.T) {
    x := uint32(0x80)   // Input:    0000 0000 0000 0000 0000 0000 1000 0000
    x = SmallSigma1(x)  // Expected: 0000 0000 0101 0000 0000 0000 0000 0000
    if x != 0x00500000 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0x00500000\n", x)
    }
}

func TestParity(t *testing.T) {
    x := uint32(0xABFFFF12)  // x: 1010 1011 1111 1111 1111 1111 0001 0010
    y := uint32(0xFFCDFF34)  // y: 1111 1111 1100 1101 1111 1111 0011 0100
    z := uint32(0xFFFFEF56)  // z: 1111 1111 1111 1111 1110 1111 0101 0110
                      // Expected: 1010 1011 1100 1101 1110 1111 0111 0000
    result := Parity(x, y, z)
    if result != 0xABCDEF70 {
        t.Errorf("\nResult:   0x%08X\nExpected: 0xABCDEF70\n", result)
    }
}

func TestF(t *testing.T) {
    for i := 0; i < 20; i++ {
        result := F(1, 2, uint32(i), i)
        expected := Ch(1, 2, uint32(i))
        if result != expected {
            t.Errorf("\nTest: F(1, 2, %d, %d)\nResult:   0x%08X\nExpected: 0x%08X\n", i, i, result, expected)
        }
    }
    for i := 20; i < 40; i++ {
        result := F(3, 4, uint32(i), i)
        expected := Parity(3, 4, uint32(i))
        if result != expected {
            t.Errorf("\nTest: F(3, 4, %d, %d)\nResult:   0x%08X\nExpected: 0x%08X\n", i, i, result, expected)
        }
    }
    for i := 40; i < 60; i++ {
        result := F(5, 6, uint32(i), i)
        expected := Maj(5, 6, uint32(i))
        if result != expected {
            t.Errorf("\nTest: F(5, 6, %d, %d)\nResult:   0x%08X\nExpected: 0x%08X\n", i, i, result, expected)
        }
    }
    for i := 60; i < 80; i++ {
        result := F(7, 8, uint32(i), i)
        expected := Parity(7, 8, uint32(i))
        if result != expected {
            t.Errorf("\nTest: F(7, 8, %d, %d)\nResult:   0x%08X\nExpected: 0x%08X\n", i, i, result, expected)
        }
    }
}

/* Tests for primitives using 64-bit words */

func TestSHR_64(t *testing.T) {
    x := uint64(0xFF)  // Input:    0000 0000 0000 0000 ... 0000 0000 1111 1111
    n := uint64(4)
    x = SHR_64(x, n)      // Expected: 0000 0000 0000 0000  ... 0000 0000 0000 1111
    if x != 0xF {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x000000000000000F\n", x)
    }
}

func TestROTR_64(t *testing.T) {
    x := uint64(5)  // Input:    0000 0000 0000 0000 ... 0000 0000 0000 0101
    n := uint64(2)
    x = ROTR_64(x, n)  // Expected: 0100 0000 0000 0000 ... 0000 0000 0000 0001
    if x != 0x4000000000000001 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x4000000000000001\n", x)
    }

}

func TestROTL_64(t *testing.T) {
    x := uint64(0x1000000000000000) // Input: 0001 0000 0000 0000 ... 0000 0000 0000 0000
    n := uint64(4)
    x = ROTL_64(x, n)       // Expected: 0000 0000 0000 0000 ... 0000 0000 0000 0001
    if x != 1 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x0000000000000001\n", x)
    }

}

func TestCh_64(t *testing.T) {
    // x: 1111 ... 1111 0000 ... 0000
    // y: 0011 ... 0011
    // z: 1100 ... 1100
    x := uint64(0xFFFFFFFF00000000)
    y := uint64(0x3333333333333333)
    z := uint64(0xCCCCCCCCCCCCCCCC)
    result := Ch_64(x,y,z)
    // Expected: 0011 ... 0011 1100 ... 1100
    if result != 0x33333333CCCCCCCC {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x33333333CCCCCCCC\n", result)
    }
}

func TestMaj_64(t *testing.T) {
    // x: 1111 ... 1111 0000 ... 0000 1111 ... 1111 0000 ... 0000
    // y: 1010 1010 0000 0000 1010 1010 0000 0000 ...
    // z: 0000 0000 1011 1011 0000 0000 1011 1011 ...
    x := uint64(0xFFFF0000FFFF0000)
    y := uint64(0xAA00AA00AA00AA00)
    z := uint64(0x00BB00BB00BB00BB)
    result := Maj_64(x,y,z)
    // Expected: 1010 1010 1011 1011 0000 0000 0000 0000 ...
    if result != 0xAABB0000AABB0000 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0xAABB0000AABB0000\n", result)
    }
}

func TestBigSigma0_64(t *testing.T) {
    x := uint64(1)    // Input: 0000 ... 0000 0001
    x = BigSigma0_64(x)
    // Expected: 0000 0000 0000 0000 0000 0000 0001 0000 0100 0010 0000 ...
    if x != 0x0000001042000000 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x0000001042000000\n", x)
    }
}

func TestBigSigma1_64(t *testing.T) {
    x := uint64(1)    // Input: 0000 ... 0000 0001
    x = BigSigma1_64(x)
    // Expected: 0000 0000 0000 0100 0100 0000 ... 0000 1000 0000 ...
    if x != 0x0004400000800000 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x0004400008000000\n", x)
    }
}

func TestSmallSigma0_64(t *testing.T) {
    x := uint64(0x40)   // Input: 0000 ... 0000 0100 0000
    x = SmallSigma0_64(x)
    // Expected: 0100 0000 ... 0000 0010 0000
    if x != 0x4000000000000020 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x4000000000000020\n", x)
    }
}

func TestSmallSigma1_64(t *testing.T) {
    x := uint64(0x40)   // Input: 0000 ... 0000 0100 0000
    x = SmallSigma1_64(x)
    // Expected: 0000 0000 0000 1000 0000 ... 0000 0010 0000 0001
    if x != 0x0008000000000201 {
        t.Errorf("\nResult:   0x%016X\nExpected: 0x0008000000000201\n", x)
    }
}
