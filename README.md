# SHA implementation in Go
Simple implementations of SHA-1, SHA-224, SHA-256, SHA-384 & SHA-512 in Go.

Similar to my [AES implementation](https://github.com/xrmon/aes), I wrote this to learn about the internals of the algorithms. It is built according to [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), and includes a full suite of tests for the implementation. Most internal functions are exposed, so this may be useful for solving CTF challenges and learning about the algorithms. However, this is not intended for use in real-world crypto - use a tried and tested implementation if you need that!

Import by placing the following at the top of your Go program:

```go
import "github.com/xrmon/sha"
```

Then run the command:

```
go get github.com/xrmon/sha
```

The five algorithms can be accessed with the following functions:

```go
func SHA1(input []byte) [20]byte {}
func SHA224(input []byte) [28]byte {}
func SHA256(input []byte) [32]byte {}
func SHA384(input []byte) [48]byte {}
func SHA512(input []byte) [64]byte {}
```

Each takes a slice of bytes as input, and returns an array of the appropriate size as output. SHA-224 and SHA-384 are simply truncated versions of SHA-256 and SHA-512 respectively, with different starting constants.

### File Structure

*primitives.go*: Primitives needed including the functions for shift, rotate, Ch, Maj, Sigma, Parity and f. Most have variants for 32-bit words (SHA-1, SHA-224 & SHA-256) and 64-bit words (SHA-384 & SHA-512).

*primitives_test.go*: Test suite for the functions in primitives.go

*sha_32.go*: Code for SHA algorithms using 32-bit words (SHA-1, SHA-224 & SHA-256)

*sha_64.go*: Code for SHA algorithms using 64-bit words (SHA-384 & SHA-512)

*sha_test.go*: Test suite for the functions in sha_32.go and sha_64.go

### Tests

Tests can be ran using the standard go command in the project directory:

```
go test
```
