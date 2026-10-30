// ==========================================
// ALFYCHAT - VALIDATION (équivalent express-validator 7.3 / validator 13.15)
// Mêmes règles que la bibliothèque JS :
//   - tous les validateurs d'une chaîne s'exécutent (pas d'arrêt au premier) ;
//   - withMessage() s'applique au dernier validateur ;
//   - optional() saute la chaîne si la valeur est undefined (null avec Nullable) ;
//   - les validateurs « standard » convertissent la valeur en chaîne et, si
//     elle est un tableau, valident chaque élément ;
//   - les sanitizers (trim, toInt, normalizeEmail) réécrivent la requête.
// ==========================================

package platform

import (
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
)

// undefinedT représente `undefined` (clé absente), distinct de null.
type undefinedT struct{}

// Undefined est la valeur d'un champ absent.
var Undefined = undefinedT{}

const (
	optNone = iota
	optUndefined
	optNull
	optFalsy
)

type itemKind int

const (
	kindCustom itemKind = iota
	kindStandard
	kindSanitizer
)

type chainItem struct {
	kind     itemKind
	negated  bool
	custom   func(v any) bool
	standard func(s string) bool
	sanitize func(s string) any
	msg      string
}

// Chain est une chaîne de validation sur un champ.
type Chain struct {
	location string
	path     string
	optional int
	negate   bool
	items    []*chainItem
}

func newChain(location, path string) *Chain { return &Chain{location: location, path: path} }

// Body / Param / Query créent une chaîne sur req.body, req.params, req.query.
func BodyField(path string) *Chain  { return newChain("body", path) }
func ParamField(path string) *Chain { return newChain("params", path) }
func QueryField(path string) *Chain { return newChain("query", path) }

func (c *Chain) add(it *chainItem) *Chain {
	it.negated = c.negate
	c.negate = false
	c.items = append(c.items, it)
	return c
}

// Optional : la chaîne est ignorée si la valeur est undefined.
func (c *Chain) Optional() *Chain { c.optional = optUndefined; return c }

// OptionalNullable : optional({ nullable: true }), ignore undefined et null.
func (c *Chain) OptionalNullable() *Chain { c.optional = optNull; return c }

// OptionalFalsy : optional({ checkFalsy: true }).
func (c *Chain) OptionalFalsy() *Chain { c.optional = optFalsy; return c }

// Not inverse le validateur suivant.
func (c *Chain) Not() *Chain { c.negate = true; return c }

// WithMessage remplace le message du dernier validateur.
func (c *Chain) WithMessage(msg string) *Chain {
	if n := len(c.items); n > 0 {
		c.items[n-1].msg = msg
	}
	return c
}

// Custom ajoute un validateur sur la valeur brute.
func (c *Chain) Custom(fn func(v any) bool) *Chain {
	return c.add(&chainItem{kind: kindCustom, custom: fn})
}

// Standard ajoute un validateur sur la valeur convertie en chaîne.
func (c *Chain) Standard(fn func(s string) bool) *Chain {
	return c.add(&chainItem{kind: kindStandard, standard: fn})
}

// ── Validateurs « custom » (valeur brute) ─────────────────────────────────

func (c *Chain) Exists() *Chain {
	return c.Custom(func(v any) bool { return v != Undefined })
}

func (c *Chain) IsString() *Chain {
	return c.Custom(func(v any) bool { _, ok := v.(string); return ok })
}

// IsArray : min/max < 0 = sans borne.
func (c *Chain) IsArray(min, max int) *Chain {
	return c.Custom(func(v any) bool {
		a, ok := v.([]any)
		return ok && (min < 0 || len(a) >= min) && (max < 0 || len(a) <= max)
	})
}

// IsObject : isObject({ strict: true }), ni null ni tableau.
func (c *Chain) IsObject() *Chain {
	return c.Custom(func(v any) bool { _, ok := v.(*Object); return ok })
}

// ── Validateurs standard ──────────────────────────────────────────────────

func (c *Chain) NotEmpty() *Chain {
	c.negate = true
	return c.Standard(func(s string) bool { return s == "" })
}

// IsLength : max < 0 = sans borne.
func (c *Chain) IsLength(min, max int) *Chain {
	return c.Standard(func(s string) bool { return IsLength(s, min, max) })
}

func (c *Chain) IsUUID() *Chain { return c.Standard(IsUUID) }

func (c *Chain) IsIn(values ...string) *Chain {
	return c.Standard(func(s string) bool {
		for _, v := range values {
			if v == s {
				return true
			}
		}
		return false
	})
}

func (c *Chain) Equals(want string) *Chain {
	return c.Standard(func(s string) bool { return s == want })
}

func (c *Chain) IsInt(b ...Bound) *Chain {
	return c.Standard(func(s string) bool { return IsInt(s, b...) })
}

func (c *Chain) IsFloat(b ...Bound) *Chain {
	return c.Standard(func(s string) bool { return IsFloat(s, b...) })
}

func (c *Chain) IsBoolean() *Chain {
	return c.Standard(func(s string) bool { return s == "true" || s == "false" || s == "1" || s == "0" })
}

func (c *Chain) IsEmail() *Chain { return c.Standard(IsEmail) }

func (c *Chain) IsURL(opts ...func(*URLOptions)) *Chain {
	o := DefaultURLOptions()
	for _, f := range opts {
		f(&o)
	}
	return c.Standard(func(s string) bool { return IsURL(s, o) })
}

func (c *Chain) Matches(re *regexp.Regexp) *Chain {
	return c.Standard(re.MatchString)
}

// ── Sanitizers ────────────────────────────────────────────────────────────

func (c *Chain) Trim() *Chain {
	return c.add(&chainItem{kind: kindSanitizer, sanitize: func(s string) any { return JSTrim(s) }})
}

func (c *Chain) ToInt() *Chain {
	return c.add(&chainItem{kind: kindSanitizer, sanitize: func(s string) any { return JSParseInt(s) }})
}

func (c *Chain) NormalizeEmail() *Chain {
	return c.add(&chainItem{kind: kindSanitizer, sanitize: func(s string) any {
		if out, ok := NormalizeEmail(s); ok {
			return out
		}
		return false
	}})
}

// ── Exécution ─────────────────────────────────────────────────────────────

// Validate exécute les chaînes dans l'ordre et renvoie les erreurs au format
// d'express-validator ({ type, value, msg, path, location }).
func Validate(r *http.Request, chains ...*Chain) []*Object {
	errs := []*Object{}
	for _, c := range chains {
		errs = append(errs, c.run(r)...)
	}
	return errs
}

func (c *Chain) skip(v any) bool {
	switch c.optional {
	case optUndefined:
		return v == Undefined
	case optNull:
		return v == Undefined || v == nil
	case optFalsy:
		return v == Undefined || !Truthy(v)
	}
	return false
}

// fieldInst est un champ concret visé par une chaîne : un chemin sans joker, ou
// un élément d'un chemin « a.* » (tableau → a[0], objet → a.clé).
type fieldInst struct {
	path string   // chemin affiché dans les erreurs
	segs []string // clés concrètes
}

// instances résout les jokers « * » comme express-validator : tableau et objet
// sont parcourus, toute autre valeur (ou valeur absente) ne donne aucune instance.
func (c *Chain) instances(r *http.Request) []fieldInst {
	segs := strings.Split(c.path, ".")
	if !strings.Contains(c.path, "*") || c.location == "params" {
		return []fieldInst{{path: c.path, segs: segs}}
	}
	var out []fieldInst
	var walk func(node any, i int, prefix string, done []string)
	walk = func(node any, i int, prefix string, done []string) {
		if i == len(segs) {
			out = append(out, fieldInst{path: prefix, segs: done})
			return
		}
		seg := segs[i]
		join := func(key string, isIndex bool) string {
			switch {
			case isIndex:
				return prefix + "[" + key + "]"
			case prefix == "":
				return key
			}
			return prefix + "." + key
		}
		if seg != "*" {
			var next any = Undefined
			switch n := node.(type) {
			case *Object:
				if n.Has(seg) {
					next = n.Get(seg)
				}
			case []any:
				if idx, err := strconv.Atoi(seg); err == nil && idx >= 0 && idx < len(n) {
					next = n[idx]
				}
			}
			walk(next, i+1, join(seg, false), append(append([]string{}, done...), seg))
			return
		}
		switch n := node.(type) {
		case []any:
			for idx, el := range n {
				k := strconv.Itoa(idx)
				walk(el, i+1, join(k, true), append(append([]string{}, done...), k))
			}
		case *Object:
			for _, k := range n.Keys() {
				walk(n.Get(k), i+1, join(k, false), append(append([]string{}, done...), k))
			}
		}
	}
	walk(locationRoot(r, c.location), 0, "", nil)
	return out
}

func locationRoot(r *http.Request, location string) any {
	switch location {
	case "body":
		return RawBody(r)
	case "query":
		return Query(r)
	}
	return nil
}

func getBySegs(root any, segs []string) any {
	cur := root
	for _, seg := range segs {
		switch n := cur.(type) {
		case *Object:
			if !n.Has(seg) {
				return Undefined
			}
			cur = n.Get(seg)
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(n) {
				return Undefined
			}
			cur = n[idx]
		default:
			return Undefined
		}
	}
	return cur
}

func setBySegs(root any, segs []string, v any) {
	cur := root
	for i, seg := range segs {
		last := i == len(segs)-1
		switch n := cur.(type) {
		case *Object:
			if last {
				n.Set(seg, v)
				return
			}
			next, ok := n.Get(seg).(*Object)
			if !ok {
				if arr, isArr := n.Get(seg).([]any); isArr {
					cur = arr
					continue
				}
				next = O()
				n.Set(seg, next)
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(n) {
				return
			}
			if last {
				n[idx] = v
				return
			}
			cur = n[idx]
		default:
			return
		}
	}
}

func (c *Chain) run(r *http.Request) []*Object {
	var errs []*Object
	insts := c.instances(r)
	addErr := func(it *chainItem, inst fieldInst, v any) {
		msg := it.msg
		if msg == "" {
			msg = "Invalid value"
		}
		e := O("type", "field")
		if v != Undefined {
			e.Set("value", v)
		}
		e.Set("msg", msg).Set("path", inst.path).Set("location", c.location)
		errs = append(errs, e)
	}

	for _, it := range c.items {
		for _, inst := range insts {
			var v any
			if c.location == "params" {
				v = fieldValue(r, c.location, c.path)
			} else {
				v = getBySegs(locationRoot(r, c.location), inst.segs)
			}
			if c.skip(v) {
				continue
			}
			switch it.kind {
			case kindCustom:
				if it.custom(v) == it.negated {
					addErr(it, inst, v)
				}
			case kindStandard:
				values := []any{v}
				if a, ok := v.([]any); ok {
					values = a
				}
				for _, x := range values {
					if it.standard(evString(x)) == it.negated {
						addErr(it, inst, x)
					}
				}
			case kindSanitizer:
				var out any
				if a, ok := v.([]any); ok {
					arr := make([]any, len(a))
					for i, x := range a {
						arr[i] = it.sanitize(evString(x))
					}
					out = arr
				} else {
					out = it.sanitize(evString(v))
				}
				if c.location == "params" {
					setFieldValue(r, c.location, c.path, out)
				} else {
					setBySegs(locationRoot(r, c.location), inst.segs, out)
				}
			}
		}
	}
	return errs
}

// Query renvoie req.query (valeurs répétées → tableau), modifiable par les sanitizers.
func Query(r *http.Request) *Object {
	if q, ok := r.Context().Value(ctxQuery).(*Object); ok {
		return q
	}
	return parseQuery(r)
}

func parseQuery(r *http.Request) *Object {
	q := O()
	for k, vs := range r.URL.Query() {
		if len(vs) == 1 {
			q.Set(k, vs[0])
		} else {
			arr := make([]any, len(vs))
			for i, v := range vs {
				arr[i] = v
			}
			q.Set(k, arr)
		}
	}
	return q
}

func fieldValue(r *http.Request, location, path string) any {
	switch location {
	case "body":
		return GetPath(RawBody(r), path)
	case "query":
		return GetPath(Query(r), path)
	case "params":
		if v := r.PathValue(path); v != "" {
			return v
		}
		return Undefined
	}
	return Undefined
}

func setFieldValue(r *http.Request, location, path string, v any) {
	switch location {
	case "body":
		if o, ok := RawBody(r).(*Object); ok {
			SetPath(o, path, v)
		}
	case "query":
		SetPath(Query(r), path, v)
	case "params":
		r.SetPathValue(path, evString(v))
	}
}

// GetPath lit un chemin "a.b.0" comme lodash _.get ; Undefined si absent.
func GetPath(root any, path string) any {
	cur := root
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case *Object:
			if !node.Has(part) {
				return Undefined
			}
			cur = node.Get(part)
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return Undefined
			}
			cur = node[i]
		default:
			return Undefined
		}
	}
	return cur
}

// SetPath écrit un chemin "a.b" en créant les objets intermédiaires.
func SetPath(root *Object, path string, v any) {
	parts := strings.Split(path, ".")
	cur := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur.Get(part).(*Object)
		if !ok {
			next = O()
			cur.Set(part, next)
		}
		cur = next
	}
	cur.Set(parts[len(parts)-1], v)
}

// ── Conversions JavaScript ────────────────────────────────────────────────

// evString reproduit le toString() d'express-validator (null/undefined → "").
func evString(v any) string {
	switch x := v.(type) {
	case undefinedT, nil:
		return ""
	case string:
		return x
	case float64:
		if math.IsNaN(x) {
			return ""
		}
		return JSNumber(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case *Object:
		return "[object Object]"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil && e != Undefined {
				parts[i] = evString(e)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

// JSNumber formate un nombre comme Number.prototype.toString().
func JSNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[0]
		exp = strings.TrimLeft(exp[1:], "0")
		return mant + "e" + string(sign) + exp
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// isJSSpace : classe \s des expressions régulières JavaScript.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// JSTrim : validator.trim() sans caractères (espaces JS).
func JSTrim(s string) string { return strings.TrimFunc(s, isJSSpace) }

// JSParseInt : parseInt(str, 10), NaN si aucun chiffre.
func JSParseInt(s string) float64 {
	s = strings.TrimLeftFunc(s, isJSSpace)
	sign := 1.0
	if strings.HasPrefix(s, "-") {
		sign, s = -1, s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return math.NaN()
	}
	f, _ := strconv.ParseFloat(s[:end], 64)
	return sign * f
}

// utf16Units découpe une chaîne en unités UTF-16, comme String.length.
func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// JSLength renvoie String.length (unités UTF-16).
func JSLength(s string) int { return len(utf16Units(s)) }

// IsLength : longueur hors paires de substitution et sélecteurs de variante.
func IsLength(s string, min, max int) bool {
	u := utf16Units(s)
	pres := 0
	for i := 0; i+1 < len(u); {
		if u[i] != 0xFE0F && u[i] != 0xFE0E && (u[i+1] == 0xFE0F || u[i+1] == 0xFE0E) {
			pres++
			i += 2
		} else {
			i++
		}
	}
	surr := 0
	for i := 0; i+1 < len(u); {
		if u[i] >= 0xD800 && u[i] <= 0xDBFF && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF {
			surr++
			i += 2
		} else {
			i++
		}
	}
	n := len(u) - pres - surr
	return n >= min && (max < 0 || n <= max)
}

var uuidAllRe = regexp.MustCompile(`(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$`)

// IsUUID : isUUID() avec la version par défaut 'all'.
func IsUUID(s string) bool { return uuidAllRe.MatchString(s) }

// Bound porte les options min/max/gt/lt de isInt et isFloat.
type Bound struct {
	min, max, gt, lt             float64
	hasMin, hasMax, hasGt, hasLt bool
}

func Min(n float64) Bound         { return Bound{min: n, hasMin: true} }
func Max(n float64) Bound         { return Bound{max: n, hasMax: true} }
func MinMax(lo, hi float64) Bound { return Bound{min: lo, max: hi, hasMin: true, hasMax: true} }
func Gt(n float64) Bound          { return Bound{gt: n, hasGt: true} }
func Lt(n float64) Bound          { return Bound{lt: n, hasLt: true} }

func (b Bound) ok(v float64) bool {
	return (!b.hasMin || v >= b.min) && (!b.hasMax || v <= b.max) &&
		(!b.hasGt || v > b.gt) && (!b.hasLt || v < b.lt)
}

var intRe = regexp.MustCompile(`^[-+]?[0-9]+$`)

// IsInt : isInt() avec allow_leading_zeroes (défaut) et bornes.
func IsInt(s string, bounds ...Bound) bool {
	if !intRe.MatchString(s) {
		return false
	}
	v, _ := strconv.ParseFloat(s, 64)
	for _, b := range bounds {
		if !b.ok(v) {
			return false
		}
	}
	return true
}

var floatRe = regexp.MustCompile(`^(?:[-+])?(?:[0-9]+)?(?:\.[0-9]*)?(?:[eE][\+\-]?(?:[0-9]+))?$`)

// IsFloat : isFloat() sans locale.
func IsFloat(s string, bounds ...Bound) bool {
	if s == "" || s == "." || s == "," || s == "-" || s == "+" || !floatRe.MatchString(s) {
		return false
	}
	v := jsParseFloat(strings.Replace(s, ",", ".", 1))
	for _, b := range bounds {
		if !b.ok(v) {
			return false
		}
	}
	return true
}

// jsParseFloat : parseFloat() sur une chaîne déjà validée par floatRe.
func jsParseFloat(s string) float64 {
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return v
	}
	// "1." ou "-.e5" : on retire la partie exposant invalide.
	for end := len(s); end > 0; end-- {
		if v, err := strconv.ParseFloat(s[:end], 64); err == nil {
			return v
		}
	}
	return math.NaN()
}

// IsISO8601 : validator.isISO8601 sans options (regex seule, syntaxe JS : le
// moteur regexp2 en mode ECMAScript gère l'anticipation et les références arrière).
func (c *Chain) IsISO8601() *Chain { return c.Standard(IsISO8601) }

var iso8601Re = regexp2.MustCompile(`^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-3])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$`, regexp2.ECMAScript)

func IsISO8601(s string) bool {
	ok, err := iso8601Re.MatchString(s)
	return err == nil && ok
}
