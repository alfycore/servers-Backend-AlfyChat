package platform

import (
	"context"
	"encoding/json"
	"math"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
)

// Compare le validateur Go à express-validator : EV_FIXTURES pointe vers le
// JSON produit par la vraie bibliothèque (mêmes chaînes, mêmes valeurs).
func TestValidateAgainstExpressValidator(t *testing.T) {
	path := os.Getenv("EV_FIXTURES")
	if path == "" {
		t.Skip("EV_FIXTURES non défini")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Chain  string          `json:"chain"`
		Input  json.RawMessage `json:"input"`
		Errors json.RawMessage `json:"errors"`
		Body   json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	chains := map[string]func() *Chain{
		"str_len":     func() *Chain { return BodyField("x").IsString().IsLength(2, 5).WithMessage("len") },
		"opt_str":     func() *Chain { return BodyField("x").Optional().IsString().IsLength(0, 3) },
		"nullable":    func() *Chain { return BodyField("x").OptionalNullable().IsInt(Min(0)) },
		"uuid":        func() *Chain { return BodyField("x").IsUUID() },
		"isin":        func() *Chain { return BodyField("x").IsIn("online", "offline").WithMessage("Statut invalide") },
		"int_range":   func() *Chain { return BodyField("x").IsInt(MinMax(1, 100)) },
		"float_range": func() *Chain { return BodyField("x").IsFloat(MinMax(-90, 90)) },
		"bool":        func() *Chain { return BodyField("x").Optional().IsBoolean() },
		"array":       func() *Chain { return BodyField("x").IsArray(1, 3).WithMessage("arr") },
		"object":      func() *Chain { return BodyField("x").IsObject() },
		"not_empty":   func() *Chain { return BodyField("x").NotEmpty() },
		"trim_len":    func() *Chain { return BodyField("x").Trim().IsLength(1, -1) },
		"trim_opt":    func() *Chain { return BodyField("x").Optional().Trim() },
		"to_int":      func() *Chain { return BodyField("x").ToInt() },
		"email":       func() *Chain { return BodyField("x").IsEmail() },
		"norm_email":  func() *Chain { return BodyField("x").IsEmail().NormalizeEmail() },
		"url_notld":   func() *Chain { return BodyField("x").IsURL(func(o *URLOptions) { o.RequireTLD = false }) },
		"url_https": func() *Chain {
			return BodyField("x").IsURL(func(o *URLOptions) { o.Protocols = []string{"https"}; o.RequireProtocol = true })
		},
		"matches": func() *Chain { return BodyField("x").Matches(regexp.MustCompile(`^[a-z0-9-]{2,60}$`)) },
		"equals":  func() *Chain { return BodyField("x").Equals("authorization_code") },
		"nested":  func() *Chain { return BodyField("a.b").IsString() },
	}

	failures := 0
	for _, c := range cases {
		mk, ok := chains[c.Chain]
		if !ok {
			t.Fatalf("chaîne inconnue %s", c.Chain)
		}
		var input struct {
			Undefined bool            `json:"undefined"`
			Value     json.RawMessage `json:"value"`
		}
		_ = json.Unmarshal(c.Input, &input)

		body := O()
		if !input.Undefined {
			v, _ := ParseJSON(input.Value)
			if c.Chain == "nested" {
				body.Set("a", O("b", v))
			} else {
				body.Set("x", v)
			}
		} else if c.Chain == "nested" {
			body.Set("a", O())
		}
		req := httptest.NewRequest("POST", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxBody, body))

		errs := Validate(req, mk())
		gotErrs, _ := marshalNoEscape(nonFinite(errs))
		gotBody, _ := marshalNoEscape(nonFinite(body))

		if !jsonEqual(gotErrs, c.Errors) || !jsonEqual(gotBody, c.Body) {
			failures++
			if failures <= 40 {
				t.Errorf("%s %s\n  errors JS=%s\n         Go=%s\n  body   JS=%s\n         Go=%s",
					c.Chain, c.Input, c.Errors, gotErrs, c.Body, gotBody)
			}
		}
	}
	t.Logf("%d/%d cas identiques", len(cases)-failures, len(cases))
}

// nonFinite remplace NaN/Infinity par le marqueur utilisé côté JS.
func nonFinite(v any) any {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) {
			return O("nonfinite", "NaN")
		}
		if math.IsInf(x, 0) {
			return O("nonfinite", JSNumber(x))
		}
	case *Object:
		c := x.Clone()
		for _, k := range c.Keys() {
			c.Set(k, nonFinite(c.Get(k)))
		}
		return c
	case []*Object:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = nonFinite(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = nonFinite(e)
		}
		return out
	}
	return v
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return string(ja) == string(jb)
}

// ISO_FIXTURES : verdicts de validator.isISO8601 (version JS) sur des dates variées.
func TestISO8601AgainstValidatorJS(t *testing.T) {
	path := os.Getenv("ISO_FIXTURES")
	if path == "" {
		t.Skip("ISO_FIXTURES non défini")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases [][]any
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if got := IsISO8601(c[0].(string)); got != c[1].(bool) {
			t.Errorf("isISO8601(%q) = %v, JS %v", c[0], got, c[1])
		}
	}
	t.Logf("%d cas comparés", len(cases))
}

// Résultats relevés sur express-validator pour body('participantIds.*').isString().
func TestWildcardPaths(t *testing.T) {
	cases := []struct {
		body string
		want string // chemins en erreur
	}{
		{`{"participantIds":["a",1,null,{}]}`, "participantIds[1] participantIds[2] participantIds[3]"},
		{`{"participantIds":"x"}`, ""},
		{`{}`, ""},
		{`{"participantIds":[]}`, ""},
		{`{"participantIds":{"a":"s","b":2}}`, "participantIds.b"},
	}
	for _, c := range cases {
		parsed, _ := ParseJSON([]byte(c.body))
		req := httptest.NewRequest("POST", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxBody, parsed))
		got := ""
		for _, e := range Validate(req, BodyField("participantIds.*").IsString()) {
			if got != "" {
				got += " "
			}
			got += e.Str("path")
		}
		if got != c.want {
			t.Errorf("%s : %q, attendu %q", c.body, got, c.want)
		}
	}
}
