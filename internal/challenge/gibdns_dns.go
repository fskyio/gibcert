// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 FSKY <development@fsky.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package challenge

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

var gibDNSKnownTypes = map[string]int{
	"A": 1, "NS": 2, "MD": 3, "MF": 4, "CNAME": 5, "SOA": 6,
	"MB": 7, "MG": 8, "MR": 9, "NULL": 10, "WKS": 11, "PTR": 12,
	"HINFO": 13, "MINFO": 14, "MX": 15, "TXT": 16, "RP": 17,
	"AFSDB": 18, "X25": 19, "ISDN": 20, "RT": 21, "NSAP": 22,
	"NSAP-PTR": 23, "SIG": 24, "KEY": 25, "PX": 26, "GPOS": 27,
	"AAAA": 28, "LOC": 29, "NXT": 30, "EID": 31, "NIMLOC": 32,
	"SRV": 33, "ATMA": 34, "NAPTR": 35, "KX": 36, "CERT": 37,
	"A6": 38, "DNAME": 39, "SINK": 40, "OPT": 41, "APL": 42,
	"DS": 43, "SSHFP": 44, "IPSECKEY": 45, "RRSIG": 46, "NSEC": 47,
	"DNSKEY": 48, "DHCID": 49, "NSEC3": 50, "NSEC3PARAM": 51,
	"TLSA": 52, "SMIMEA": 53, "HIP": 55, "NINFO": 56, "RKEY": 57,
	"TALINK": 58, "CDS": 59, "CDNSKEY": 60, "OPENPGPKEY": 61,
	"CSYNC": 62, "ZONEMD": 63, "SVCB": 64, "HTTPS": 65, "DSYNC": 66,
	"HHIT": 67, "BRID": 68, "UNECE": 69, "ISO": 70, "SPF": 99, "UINFO": 100, "UID": 101,
	"GID": 102, "UNSPEC": 103, "NID": 104, "L32": 105, "L64": 106,
	"LP": 107, "EUI48": 108, "EUI64": 109, "NXNAME": 128,
	"TKEY": 249, "TSIG": 250,
	"IXFR": 251, "AXFR": 252, "MAILB": 253, "MAILA": 254, "ANY": 255,
	"URI": 256, "CAA": 257, "AVC": 258, "DOA": 259, "AMTRELAY": 260,
	"RESINFO": 261, "WALLET": 262, "CLA": 263, "IPN": 264,
	"TA": 32768, "DLV": 32769,
}

func gibDNSTypeCode(recordType string) (int, error) {
	if code, ok := gibDNSKnownTypes[recordType]; ok {
		if gibDNSDisallowedTypeCode(code) {
			return 0, fmt.Errorf("type %s is a meta-type, query type, or reserved", recordType)
		}
		return code, nil
	}
	if !strings.HasPrefix(recordType, "TYPE") || len(recordType) == len("TYPE") {
		return 0, fmt.Errorf("unsupported or malformed type %q", recordType)
	}
	digits := strings.TrimPrefix(recordType, "TYPE")
	if len(digits) > 1 && digits[0] == '0' {
		return 0, fmt.Errorf("type code has a leading zero")
	}
	code, err := strconv.Atoi(digits)
	if err != nil || code < 1 || code > 65534 {
		return 0, fmt.Errorf("type code %q is outside the permitted range", digits)
	}
	if gibDNSDisallowedTypeCode(code) {
		return 0, fmt.Errorf("type code %d is a meta-type, query type, or reserved", code)
	}
	return code, nil
}

func gibDNSDisallowedTypeCode(code int) bool {
	return code == 41 || (code >= 100 && code <= 103) ||
		(code >= 129 && code <= 255) || (code >= 61440 && code <= 65279)
}

// parseGibDNSName returns a case-folded wire-format name suitable for equality
// comparison. Compression pointers are not valid in presentation names.
func parseGibDNSName(name string) ([]byte, error) {
	if name == "." {
		return []byte{0}, nil
	}
	if name == "" || name[len(name)-1] != '.' {
		return nil, fmt.Errorf("name %q is not absolute", name)
	}
	var wire []byte
	var label []byte
	for i := 0; i < len(name)-1; i++ {
		b := name[i]
		if b >= 0x80 {
			return nil, fmt.Errorf("name %q is not ASCII presentation syntax", name)
		}
		if b == '.' {
			if len(label) == 0 {
				return nil, fmt.Errorf("name %q contains an empty label", name)
			}
			if len(label) > 63 {
				return nil, fmt.Errorf("name %q contains a label longer than 63 octets", name)
			}
			wire = append(wire, byte(len(label)))
			wire = append(wire, label...)
			label = label[:0]
			continue
		}
		if b == '\\' {
			i++
			if i >= len(name)-1 {
				return nil, fmt.Errorf("name %q ends with an incomplete escape", name)
			}
			b = name[i]
			if b >= '0' && b <= '9' {
				if i+2 >= len(name)-1 || !isASCIIDigit(name[i+1]) || !isASCIIDigit(name[i+2]) {
					return nil, fmt.Errorf("name %q contains an incomplete decimal escape", name)
				}
				value := int(b-'0')*100 + int(name[i+1]-'0')*10 + int(name[i+2]-'0')
				if value > 255 {
					return nil, fmt.Errorf("name %q contains a decimal escape above 255", name)
				}
				b = byte(value)
				i += 2
			}
		} else if b <= 0x20 || b == 0x7f {
			return nil, fmt.Errorf("name %q contains unescaped whitespace or a control character", name)
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		label = append(label, b)
	}
	if len(label) == 0 {
		return nil, fmt.Errorf("name %q contains an empty label", name)
	}
	if len(label) > 63 {
		return nil, fmt.Errorf("name %q contains a label longer than 63 octets", name)
	}
	wire = append(wire, byte(len(label)))
	wire = append(wire, label...)
	wire = append(wire, 0)
	if len(wire) > 255 {
		return nil, fmt.Errorf("name %q is longer than 255 wire octets", name)
	}
	return wire, nil
}

func gibDNSSemanticRData(recordType, presentation string) ([]byte, error) {
	if presentation == "" || strings.TrimSpace(presentation) != presentation ||
		strings.ContainsAny(presentation, "\r\n\x00") {
		return nil, fmt.Errorf("rdata has forbidden whitespace or control characters")
	}
	code, err := gibDNSTypeCode(recordType)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(presentation, `\#`) {
		wire, err := parseGibDNSGenericRData(presentation)
		if err != nil {
			return nil, err
		}
		if err := validateGibDNSWireRData(code, wire); err != nil {
			return nil, err
		}
		return wire, nil
	}
	switch code {
	case 16:
		return parseGibDNSTXTRData(presentation)
	case 52:
		return parseGibDNSTLSARData(presentation)
	default:
		return nil, fmt.Errorf("type-specific rdata parsing for %s is not supported by gibcert", recordType)
	}
}

func parseGibDNSGenericRData(presentation string) ([]byte, error) {
	fields := strings.Fields(presentation)
	if len(fields) < 2 || fields[0] != `\#` {
		return nil, fmt.Errorf("malformed RFC 3597 rdata")
	}
	length, err := strconv.Atoi(fields[1])
	if err != nil || length < 0 || length > 65535 {
		return nil, fmt.Errorf("invalid RFC 3597 rdata length")
	}
	if length == 0 {
		if len(fields) != 2 {
			return nil, fmt.Errorf("zero-length RFC 3597 rdata must omit hex data")
		}
		return []byte{}, nil
	}
	if len(fields) != 3 || len(fields[2]) != length*2 {
		return nil, fmt.Errorf("RFC 3597 hex data does not match declared length")
	}
	wire, err := hex.DecodeString(fields[2])
	if err != nil {
		return nil, fmt.Errorf("invalid RFC 3597 hex data")
	}
	return wire, nil
}

func validateGibDNSWireRData(code int, wire []byte) error {
	switch code {
	case 16:
		for offset := 0; offset < len(wire); {
			length := int(wire[offset])
			offset++
			if offset+length > len(wire) {
				return fmt.Errorf("invalid generic TXT rdata")
			}
			offset += length
		}
		if len(wire) == 0 {
			return fmt.Errorf("TXT rdata must contain at least one character-string")
		}
	case 52:
		if len(wire) < 3 {
			return fmt.Errorf("generic TLSA rdata is shorter than three octets")
		}
	}
	return nil
}

func parseGibDNSTXTRData(presentation string) ([]byte, error) {
	var wire []byte
	for i := 0; ; {
		for i < len(presentation) && (presentation[i] == ' ' || presentation[i] == '\t') {
			i++
		}
		if i == len(presentation) {
			break
		}
		if presentation[i] != '"' {
			return nil, fmt.Errorf("TXT character-string must be quoted")
		}
		i++
		var value []byte
		closed := false
		for i < len(presentation) {
			b := presentation[i]
			i++
			if b == '"' {
				closed = true
				break
			}
			if b == '\\' {
				if i >= len(presentation) {
					return nil, fmt.Errorf("TXT rdata ends with an incomplete escape")
				}
				b = presentation[i]
				i++
				if isASCIIDigit(b) {
					if i+1 >= len(presentation) || !isASCIIDigit(presentation[i]) || !isASCIIDigit(presentation[i+1]) {
						return nil, fmt.Errorf("TXT rdata contains an incomplete decimal escape")
					}
					decimal := int(b-'0')*100 + int(presentation[i]-'0')*10 + int(presentation[i+1]-'0')
					if decimal > 255 {
						return nil, fmt.Errorf("TXT rdata contains a decimal escape above 255")
					}
					b = byte(decimal)
					i += 2
				}
			}
			value = append(value, b)
			if len(value) > 255 {
				return nil, fmt.Errorf("TXT character-string exceeds 255 octets")
			}
		}
		if !closed {
			return nil, fmt.Errorf("TXT rdata contains an unterminated character-string")
		}
		wire = append(wire, byte(len(value)))
		wire = append(wire, value...)
		if i < len(presentation) && presentation[i] != ' ' && presentation[i] != '\t' {
			return nil, fmt.Errorf("TXT character-strings must be separated by whitespace")
		}
	}
	if len(wire) == 0 {
		return nil, fmt.Errorf("TXT rdata must contain at least one character-string")
	}
	return wire, nil
}

func parseGibDNSTLSARData(presentation string) ([]byte, error) {
	fields := strings.Fields(presentation)
	if len(fields) != 4 {
		return nil, fmt.Errorf("TLSA rdata requires four fields")
	}
	wire := make([]byte, 3)
	for i := 0; i < 3; i++ {
		value, err := strconv.Atoi(fields[i])
		if err != nil || value < 0 || value > 255 {
			return nil, fmt.Errorf("TLSA numeric field %d is outside 0..255", i+1)
		}
		wire[i] = byte(value)
	}
	data, err := hex.DecodeString(fields[3])
	if err != nil || len(fields[3])%2 != 0 {
		return nil, fmt.Errorf("TLSA association data is not hexadecimal")
	}
	wire = append(wire, data...)
	return wire, nil
}

func quoteGibDNSTXT(value string) string {
	if value == "" {
		return `""`
	}
	var out strings.Builder
	for offset := 0; offset < len(value); {
		end := min(offset+255, len(value))
		if offset != 0 {
			out.WriteByte(' ')
		}
		out.WriteByte('"')
		for _, b := range []byte(value[offset:end]) {
			switch {
			case b == '"' || b == '\\':
				out.WriteByte('\\')
				out.WriteByte(b)
			case b < 0x20 || b >= 0x7f:
				fmt.Fprintf(&out, "\\%03d", b)
			default:
				out.WriteByte(b)
			}
		}
		out.WriteByte('"')
		offset = end
	}
	return out.String()
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func gibDNSNameWithin(owner, zone string) bool {
	ownerWire, err := parseGibDNSName(owner)
	if err != nil {
		return false
	}
	zoneWire, err := parseGibDNSName(zone)
	if err != nil {
		return false
	}
	ownerLabels := gibDNSWireLabels(ownerWire)
	zoneLabels := gibDNSWireLabels(zoneWire)
	if len(zoneLabels) > len(ownerLabels) {
		return false
	}
	offset := len(ownerLabels) - len(zoneLabels)
	for i := range zoneLabels {
		if !bytes.Equal(ownerLabels[offset+i], zoneLabels[i]) {
			return false
		}
	}
	return true
}

func gibDNSWireLabels(wire []byte) [][]byte {
	var labels [][]byte
	for offset := 0; offset < len(wire) && wire[offset] != 0; {
		length := int(wire[offset])
		offset++
		labels = append(labels, wire[offset:offset+length])
		offset += length
	}
	return labels
}
