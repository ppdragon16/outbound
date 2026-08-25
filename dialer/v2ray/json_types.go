/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package v2ray

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// FlexibleBool unmarshals a JSON value that may be a bool, a number
// (non-zero = true) or a string ("true"/"1"/… = true, ""/"0"/"false" = false).
// It restores the lenient bool decoding that jsoniter's fuzzy decoder used to
// provide for vmess share-link JSON.
type FlexibleBool bool

func (b *FlexibleBool) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	switch {
	case s == "null":
		*b = false
	case s == "true":
		*b = true
	case s == "false":
		*b = false
	case len(s) >= 2 && s[0] == '"': // string
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		switch str {
		case "", "0", "false":
			*b = false
		default:
			*b = true
		}
	default: // number
		var f float64
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("fuzzy bool: %v", err)
		}
		*b = FlexibleBool(f != 0)
	}
	return nil
}

// FlexibleInt unmarshals a JSON value that may be an integer, a float
// (truncated), a bool (1/0) or a numeric string. It restores the lenient
// integer decoding that jsoniter's fuzzy decoder used to provide.
type FlexibleInt int

func (i *FlexibleInt) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	switch {
	case s == "null":
		*i = 0
	case s == "true":
		*i = 1
	case s == "false":
		*i = 0
	case len(s) >= 2 && s[0] == '"': // string
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		if str == "" {
			*i = 0
			return nil
		}
		v, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return fmt.Errorf("fuzzy int: invalid string %q", str)
		}
		*i = FlexibleInt(int(v))
	default: // number (int or float)
		var f float64
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("fuzzy int: %v", err)
		}
		*i = FlexibleInt(int(f))
	}
	return nil
}

// FlexibleString unmarshals a JSON value that may be a string or a number
// (coerced to its string representation), restoring the lenient string
// decoding that jsoniter's fuzzy decoder used to provide.
type FlexibleString string

func (s *FlexibleString) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = FlexibleString(str)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		*s = FlexibleString(n.String())
		return nil
	}
	if strings.TrimSpace(string(data)) == "null" {
		*s = ""
		return nil
	}
	return fmt.Errorf("fuzzy string: invalid value %s", data)
}

// parseFlexibleBool parses a boolean string, returning false on parse failure.
func parseFlexibleBool(s string) FlexibleBool {
	b, _ := strconv.ParseBool(s)
	return FlexibleBool(b)
}

// parseFlexibleInt parses an integer string, returning 0 on parse failure.
func parseFlexibleInt(s string) FlexibleInt {
	n, _ := strconv.Atoi(s)
	return FlexibleInt(n)
}
