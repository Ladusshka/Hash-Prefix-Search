# BitHunt: Hash Prefix Search

Find a message whose hash begins with a specified bit prefix. The search function supports SHA-256 by default and can be extended to any hash algorithm supported by OpenSSL.

## The Challenge

Implement a function (or set of functions, not a complete program) that finds any message whose hash starts with the requested sequence of bits.

```cpp
int findHash(
    const uint8_t prefix[],
    const unsigned int prefixBitLen,
    std::unique_ptr<uint8_t[]>& outputMessage,
    size_t& outputMessageLen,
    std::unique_ptr<uint8_t[]>& outputHash,
    size_t& outputHashLen,
    const char hashName[] = "sha256"
);
```

## Parameters

| Parameter | Description |
| --- | --- |
| `prefix` | Binary data containing the desired hash prefix. |
| `prefixBitLen` | Length of the prefix to match, in bits. |
| `hashName` | Hash algorithm name accepted by OpenSSL's `EVP_get_digestbyname`. |
| `outputMessage` | Receives the discovered message as binary data. |
| `outputMessageLen` | Length of the returned message, in bytes. |
| `outputHash` | Receives the message hash as binary data. |
| `outputHashLen` | Length of the returned hash, in bytes. |

## Binary Data and Lengths

`prefix`, `outputMessage`, and `outputHash` are byte arrays, not hexadecimal text or null-terminated C strings. Allocate output arrays to the required size (for example, with `std::make_unique<uint8_t[]>(size)`) and return them through the provided `std::unique_ptr` references. The test harness owns the returned arrays and releases them automatically.

Output lengths are measured in bytes, so returned messages and hashes must be byte-aligned. For example, `outputMessageLen == 1` represents an 8-bit message.

## Prefix Bit Order

Compare bytes in array order (`prefix[0]`, `prefix[1]`, ...), checking the most significant bit first within each byte (`0x80`, `0x40`, ...). If the requested prefix length is not byte-aligned, only the leading bits of the final byte are significant.

For example, with a 10-bit prefix:

```text
prefix        = 00010010 00110000  // {0x12, 0x30}
prefixBitLen  = 10
prefixBitMask = 11111111 11000000  // the first 10 bits are checked

validHash     = 00010010 00000101  // first 10 bits match
invalidHash   = 00010010 10110000  // ninth bit differs
```

## Implementation Notes

- For valid input, `prefix` contains enough bytes to cover `prefixBitLen`.
- If the function returns `EXIT_FAILURE`, it must leave all output parameters unchanged.

## Scoring

The assignment has two implementation targets:

- **2 points:** Support only the default SHA-256 algorithm. Return `EXIT_FAILURE` for other hash algorithms.
- **3 points:** Support any hash algorithm available through the requested hash name.

For part-time students, the score is doubled: 4 points for SHA-256 only, or 6 points for support of arbitrary hashes.

Progtest may report fractional scores to two decimal places; instructors may round them. Tests labeled **"Multiple hash functions"** may show **87.36%** when that requirement is not met. Three such tests combine to approximately $0.8736^3 = 0.6667$, resulting in about $0.6667 \times 3 = 2$ points.