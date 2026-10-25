// Package auth implements Nodetide native SSO (see "Authentication (SSO)" in
// identity-system.md): sigchain verification, AuthRequest/AuthAssertion
// verification, and the challenge/verify HTTP handlers.
package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// DecodeJSON decodes JSON keeping numbers as json.Number so integers survive
// a decode/canonicalize round trip exactly.
func DecodeJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

// Canonical serializes v exactly like Python's
// json.dumps(v, sort_keys=True, separators=(",", ":")) with the default
// ensure_ascii=True. Signatures and event hashes are computed over this form,
// so it must stay byte-identical to the Python implementation.
//
// v must consist of nil, bool, json.Number (integers only), string, []any and
// map[string]any, which is what DecodeJSON produces.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("non-integer number not supported: %s", s)
		}
		buf.WriteString(s)
	case string:
		writeCanonicalString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// UTF-8 byte order equals Unicode code point order, which is what
		// Python's sort_keys uses.
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

const hexDigits = "0123456789abcdef"

func writeUnicodeEscape(buf *bytes.Buffer, r rune) {
	buf.WriteString(`\u`)
	buf.WriteByte(hexDigits[(r>>12)&0xf])
	buf.WriteByte(hexDigits[(r>>8)&0xf])
	buf.WriteByte(hexDigits[(r>>4)&0xf])
	buf.WriteByte(hexDigits[r&0xf])
}

// writeCanonicalString mirrors Python's ensure_ascii escaping: everything
// outside space..~ is escaped, non-BMP characters as surrogate pairs.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			buf.WriteByte(byte(r))
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			writeUnicodeEscape(buf, r1)
			writeUnicodeEscape(buf, r2)
		default:
			writeUnicodeEscape(buf, r)
		}
	}
	buf.WriteByte('"')
}
