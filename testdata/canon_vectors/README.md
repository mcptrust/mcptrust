# Canonicalization Test Vectors

Test vectors for verifying MCPTrust canonicalization implementations.

## Files

| File | Description |
|------|-------------|
| `input.json` | Input JSON (pretty-printed, unsorted keys) |
| `canon_v1.json` | Expected v1 output (Go string sort, compact) |
| `canon_v2.json` | Expected v2/JCS output (UTF-16 sort, compact) |
| `sha256_v1.txt` | SHA-256 hash of `canon_v1.json` |
| `sha256_v2.txt` | SHA-256 hash of `canon_v2.json` |

## v1 Rules (mcptrust-canon-v1)

1. Keys sorted alphabetically (Go `sort.Strings`, UTF-8 byte order)
2. Compact JSON (no whitespace)
3. Standard JSON string escaping
4. Numbers preserved as-is

## v2 Rules (JCS, RFC 8785)

1. Keys sorted by UTF-16 code unit comparison
2. Compact JSON
3. ES6-style number formatting
4. Control chars as `\uXXXX`

## Usage

```go
// Parse with UseNumber to preserve exact numbers
dec := json.NewDecoder(bytes.NewReader(input))
dec.UseNumber()

var data interface{}
dec.Decode(&data)

// Canonicalize
v1, _ := CanonicalizeJSONv1(data)
v2, _ := CanonicalizeJSONv2(data)
```
