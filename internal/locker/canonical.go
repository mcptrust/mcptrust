package locker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// CanonVersion enum
type CanonVersion string

const (
	// CanonV1 original (sorted keys, std json)
	CanonV1 CanonVersion = "v1"
	// CanonV2 JCS (RFC 8785)
	CanonV2 CanonVersion = "v2"
)

// DefaultCanonVersion is v1 (legacy compatible)
const DefaultCanonVersion = CanonV1

// CanonicalizeJSONWithVersion helper
func CanonicalizeJSONWithVersion(v interface{}, version CanonVersion) ([]byte, error) {
	switch version {
	case CanonV1:
		return CanonicalizeJSONv1(v)
	case CanonV2:
		return CanonicalizeJSONv2(v)
	default:
		return nil, fmt.Errorf("unknown canonicalization version: %s", version)
	}
}

// CanonicalizeJSONv1 original
func CanonicalizeJSONv1(v interface{}) ([]byte, error) {
	canonical := canonicalizeValueV1(v)
	return json.Marshal(canonical)
}

// CanonicalizeJSONv2 JCS/RFC8785
func CanonicalizeJSONv2(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeJCSValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- v1 implementation ---

func canonicalizeValueV1(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return canonicalizeMapV1(val)
	case []interface{}:
		return canonicalizeSliceV1(val)
	default:
		return v
	}
}

func canonicalizeMapV1(m map[string]interface{}) *orderedMapV1 {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	om := &orderedMapV1{
		keys:   keys,
		values: make(map[string]interface{}, len(m)),
	}
	for k, v := range m {
		om.values[k] = canonicalizeValueV1(v)
	}
	return om
}

func canonicalizeSliceV1(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		result[i] = canonicalizeValueV1(v)
	}
	return result
}

type orderedMapV1 struct {
	keys   []string
	values map[string]interface{}
}

func (om *orderedMapV1) MarshalJSON() ([]byte, error) {
	if len(om.keys) == 0 {
		return []byte("{}"), nil
	}

	result := "{"
	for i, key := range om.keys {
		if i > 0 {
			result += ","
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		valueJSON, err := json.Marshal(om.values[key])
		if err != nil {
			return nil, err
		}
		result += string(keyJSON) + ":" + string(valueJSON)
	}
	result += "}"
	return []byte(result), nil
}

// --- v2 JCS (RFC 8785) implementation ---

// writeJCSValue recursive
func writeJCSValue(buf *bytes.Buffer, v interface{}) error {
	if v == nil {
		buf.WriteString("null")
		return nil
	}

	switch val := v.(type) {
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		s, err := jcsFormatNumber(val)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case json.Number:
		// parse and reformat
		f, err := val.Float64()
		if err != nil {
			return err
		}
		s, err := jcsFormatNumber(f)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case int:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
	case string:
		writeJCSString(buf, val)
	case []interface{}:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCSValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		if err := writeJCSObject(buf, val); err != nil {
			return err
		}
	default:
		// fallback: use standard JSON encoding
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// writeJCSObject sorted keys
func writeJCSObject(buf *bytes.Buffer, m map[string]interface{}) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	// JCS requires sorting by UTF-16 code unit comparison
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i], keys[j]) < 0
	})

	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJCSString(buf, key)
		buf.WriteByte(':')
		if err := writeJCSValue(buf, m[key]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// compareUTF16 helper
func compareUTF16(a, b string) int {
	aRunes := []rune(a)
	bRunes := []rune(b)

	aUnits := utf16.Encode(aRunes)
	bUnits := utf16.Encode(bRunes)

	minLen := len(aUnits)
	if len(bUnits) < minLen {
		minLen = len(bUnits)
	}

	for i := 0; i < minLen; i++ {
		if aUnits[i] < bUnits[i] {
			return -1
		}
		if aUnits[i] > bUnits[i] {
			return 1
		}
	}

	return len(aUnits) - len(bUnits)
}

// writeJCSString escaped
func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				// control characters must be escaped as \uXXXX
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// jcsFormatNumber RFC8785
func jcsFormatNumber(f float64) (string, error) {
	// check for special values - these are not valid JSON numbers
	if f != f { // NaN check (NaN != NaN is always true)
		return "", fmt.Errorf("NaN is not a valid JSON number")
	}
	// Infinity check
	if f > 1.7976931348623157e+308 || f < -1.7976931348623157e+308 {
		return "", fmt.Errorf("infinity is not a valid JSON number")
	}

	// handle -0 -> output as "0" per RFC 8785
	if f == 0 {
		return "0", nil
	}

	// check if it's an integer within safe range
	if f == float64(int64(f)) && f >= -9007199254740991 && f <= 9007199254740991 {
		return strconv.FormatInt(int64(f), 10), nil
	}

	// use ES6 number formatting
	// strconv.FormatFloat with 'g' format produces shortest representation
	s := strconv.FormatFloat(f, 'g', -1, 64)
	return s, nil
}
