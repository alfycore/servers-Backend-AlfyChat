// ==========================================
// ALFYCHAT - CONVERSIONS JAVASCRIPT
// String(v), Number(v), parseInt et opérateurs binaires sur des valeurs JSON
// décodées (*Object, []any, string, float64, bool, nil, Undefined).
// ==========================================

package platform

import (
	"math"
	"strconv"
	"strings"
)

// JSString reproduit String(v) (template literal) : null → "null".
func JSString(v any) string {
	switch x := v.(type) {
	case undefinedT:
		return "undefined"
	case nil:
		return "null"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil && e != Undefined {
				parts[i] = JSString(e)
			}
		}
		return strings.Join(parts, ",")
	}
	return evString(v)
}

// ToNumber reproduit Number(v).
func ToNumber(v any) float64 {
	switch x := v.(type) {
	case undefinedT:
		return math.NaN()
	case nil:
		return 0
	case bool:
		if x {
			return 1
		}
		return 0
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		return stringToNumber(x)
	case []any:
		return stringToNumber(JSString(x))
	}
	return math.NaN()
}

func stringToNumber(s string) float64 {
	s = strings.TrimFunc(s, isJSSpace)
	if s == "" {
		return 0
	}
	switch s {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(n)
		}
	}
	// Grammaire décimale JS : pas de "_", pas de hex flottant, pas de "inf".
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
			return math.NaN()
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f
		}
		return math.NaN()
	}
	return f
}

// ToInt32 reproduit la conversion des opérandes de & | ^ ~ en JS.
func ToInt32(f float64) int32 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	f = math.Trunc(f)
	m := math.Mod(f, 4294967296)
	if m < 0 {
		m += 4294967296
	}
	return int32(uint32(m))
}

// IsInteger reproduit Number.isInteger(n).
func IsInteger(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

// ParseIntOr : parseInt(String(v)) || def.
func ParseIntOr(v any, def float64) float64 {
	n := JSParseInt(JSString(v))
	if math.IsNaN(n) || n == 0 {
		return def
	}
	return n
}

// SQLParam convertit une valeur JSON en paramètre SQL comme mysql2 :
// objets et tableaux sérialisés en JSON, booléens en 1/0.
func SQLParam(v any) any {
	switch x := v.(type) {
	case undefinedT:
		return nil
	case *Object, []any:
		b, _ := marshalNoEscape(x)
		return string(b)
	case bool:
		if x {
			return 1
		}
		return 0
	}
	return v
}

// StrictEqual reproduit a === b sur des valeurs JSON décodées : les objets et
// tableaux ne sont égaux qu'à eux-mêmes.
func StrictEqual(a, b any) bool {
	if x, ok := jsNumberValue(a); ok {
		y, ok := jsNumberValue(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	case undefinedT:
		return b == Undefined
	case *Object:
		y, ok := b.(*Object)
		return ok && x == y
	}
	return false
}

// jsNumberValue : les entiers lus en base (int64) et les nombres JSON (float64)
// sont tous des Number en JS.
func jsNumberValue(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	}
	return 0, false
}
