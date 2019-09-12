package sha

import (
    "testing"
    "bytes"
    "reflect"
)

func TestPadMessage32(t *testing.T) {
    // Input: 01100001 01100010 01100011
    M := []byte("abc")
    // Expected: 01100001 01100010 01100011 10000000 00000000*59 00011000
    expected := append(M, make([]byte, 61)...)
    expected[3] = 0x80
    expected[63] = 24
    result := PadMessage32(M)
    if !bytes.Equal(result, expected) {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestParseMessage32(t *testing.T) {
    // Input: 0 1 2 3 4...
    input := make([]byte, 256)
    for i := 0; i < 256; i++ {
            input[i] = byte(i)
    }
    // Expected: 00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617...
    expected := make([][16]uint32, 4)
    var v, word uint32
    for i := 0; i < 4; i++ {
        for j := 0; j < 16; j++ {
            word = (v << 24) + ((v+1) << 16) + ((v+2) << 8) + v+3
            v += 4
            expected[i][j] = word
        }
    }
    result := ParseMessage32(input)
    if !reflect.DeepEqual(result, expected) {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestSHA224(t *testing.T) {
    // Input: 41 42 43 44 45 46 47
    input := []byte("ABCDEFG")
    // Expected: bae3735e5822d8c30fafd70736316e7807f7cccf65e6e73c15f32a60
    expected := [28]byte{0xba, 0xe3, 0x73, 0x5e, 0x58, 0x22, 0xd8, 0xc3, 0x0f, 0xaf, 0xd7, 0x07, 0x36, 0x31, 0x6e, 0x78, 0x07, 0xf7, 0xcc, 0xcf, 0x65, 0xe6, 0xe7, 0x3c, 0x15, 0xf3, 0x2a, 0x60}
    result := SHA224(input)
    if result != expected {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestSHA256(t *testing.T) {
    // Input: 61 62 63 64 65 66 67
    input := []byte("abcdefg")
    // Expected: 7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a
    expected := [32]byte{0x7d, 0x1a, 0x54, 0x12, 0x7b, 0x22, 0x25, 0x02, 0xf5, 0xb7, 0x9b, 0x5f, 0xb0, 0x80, 0x30, 0x61, 0x15, 0x2a, 0x44, 0xf9, 0x2b, 0x37, 0xe2, 0x3c, 0x65, 0x27, 0xba, 0xf6, 0x65, 0xd4, 0xda, 0x9a}
    result := SHA256(input)
    if result != expected {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestSHA1(t *testing.T) {
    // Input: 68 69 6A 6B 6C 6D 6E
    input := []byte("hijklmn")
    // Expected: 1c4baea71a9122e859c17e729be59f49b5f09904
    expected := [20]byte{0x1c, 0x4b, 0xae, 0xa7, 0x1a, 0x91, 0x22, 0xe8, 0x59, 0xc1, 0x7e, 0x72, 0x9b, 0xe5, 0x9f, 0x49, 0xb5, 0xf0, 0x99, 0x04}
    result := SHA1(input)
    if result != expected {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestPadMessage64(t *testing.T) {
    // Input: 01100001 01100010 01100011
    M := []byte("abc")
    // Expected: 01100001 01100010 01100011 10000000 00000000*123 00011000
    expected := append(M, make([]byte, 125)...)
    expected[3] = 0x80
    expected[127] = 24
    result := PadMessage64(M)
    if !bytes.Equal(result, expected) {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestParseMessage64(t *testing.T) {
    // Input: 0 1 2 3 4...
    input := make([]byte, 256)
    for i := 0; i < 256; i++ {
            input[i] = byte(i)
    }
    // Expected: 0001020304050607 08090A0B0C0D0E0F 1011121314151617...
    expected := make([][16]uint64, 2)
    var v, word uint64
    for i := 0; i < 2; i++ {
        for j := 0; j < 16; j++ {
            word =  (v << 56) + ((v+1) << 48) + ((v+2) << 40) + ((v+3) << 32)
            word += ((v+4) << 24) + ((v+5) << 16) + ((v+6) << 8) + v+7
            v += 8
            expected[i][j] = word
        }
    }
    result := ParseMessage64(input)
    if !reflect.DeepEqual(result, expected) {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestSHA384(t *testing.T) {
    // Input: 31 32 33 34 35 36 37
    input := []byte("1234567")
    // Expected: 826227b9dfb593ae4ddbd3f5b7e24b6cb92e342c951cce56546fa68a2e56557b5ebac824a5e778438a7f35c985dfe082
    expected := [48]byte{0x82, 0x62, 0x27, 0xb9, 0xdf, 0xb5, 0x93, 0xae, 0x4d, 0xdb, 0xd3, 0xf5, 0xb7, 0xe2, 0x4b, 0x6c, 0xb9, 0x2e, 0x34, 0x2c, 0x95, 0x1c, 0xce, 0x56, 0x54, 0x6f, 0xa6, 0x8a, 0x2e, 0x56, 0x55, 0x7b, 0x5e, 0xba, 0xc8, 0x24, 0xa5, 0xe7, 0x78, 0x43, 0x8a, 0x7f, 0x35, 0xc9, 0x85, 0xdf, 0xe0, 0x82}
    result := SHA384(input)
    if result != expected {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}

func TestSHA512(t *testing.T) {
    // Input: 39 38 37 36 35 34 33
    input := []byte("9876543")
    // Expected: e263c0a5edaa7f354bb001c6b10f584c51970bb15a760ed4cefce741f9262ff21a6325899ba994f494bf34496abf3f8f2e316d52dd5eaacad55c470bf45f8896
    expected := [64]byte{0xe2, 0x63, 0xc0, 0xa5, 0xed, 0xaa, 0x7f, 0x35, 0x4b, 0xb0, 0x01, 0xc6, 0xb1, 0x0f, 0x58, 0x4c, 0x51, 0x97, 0x0b, 0xb1, 0x5a, 0x76, 0x0e, 0xd4, 0xce, 0xfc, 0xe7, 0x41, 0xf9, 0x26, 0x2f, 0xf2, 0x1a, 0x63, 0x25, 0x89, 0x9b, 0xa9, 0x94, 0xf4, 0x94, 0xbf, 0x34, 0x49, 0x6a, 0xbf, 0x3f, 0x8f, 0x2e, 0x31, 0x6d, 0x52, 0xdd, 0x5e, 0xaa, 0xca, 0xd5, 0x5c, 0x47, 0x0b, 0xf4, 0x5f, 0x88, 0x96}
    result := SHA512(input)
    if result != expected {
        t.Errorf("\nResult:   %x\nExpected: %x\n", result, expected)
    }
}
