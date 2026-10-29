package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAccepts(t *testing.T) {
	cases := map[string]string{
		"":                                    "text/html",
		"*/*":                                 "text/html",
		"application/json":                    "application/json",
		"application/json, text/plain, */*":   "application/json",
		"text/html,application/xhtml+xml,*/*": "text/html",
		"text/plain":                          "",
		"application/json;q=0.5, text/html":   "text/html",
	}
	for header, want := range cases {
		if got := Accepts(header, "text/html", "application/json"); got != want {
			t.Errorf("Accepts(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestObjectOrderAndEscape(t *testing.T) {
	o := O("b", 1, "a", "<x>&", "c", nil)
	o.Set("b", 2)
	b, _ := marshalNoEscape(o)
	if string(b) != `{"b":2,"a":"<x>&","c":null}` {
		t.Fatalf("got %s", b)
	}
	parsed, err := ParseJSON([]byte(`{"z":1,"y":{"k":[1,{"q":true}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = marshalNoEscape(parsed)
	if string(b) != `{"z":1,"y":{"k":[1,{"q":true}]}}` {
		t.Fatalf("got %s", b)
	}
}

func TestConvertColumn(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC)
	if v := convertColumn("TIMESTAMP", ts); v != "2026-01-02T03:04:05.006Z" {
		t.Errorf("date: %v", v)
	}
	if v := convertColumn("TINYINT", []byte("1")); v != int64(1) {
		t.Errorf("tinyint: %#v", v)
	}
	if v := convertColumn("DECIMAL", []byte("1.50")); v != "1.50" {
		t.Errorf("decimal: %#v", v)
	}
	if v, ok := convertColumn("JSON", []byte(`{"a":1}`)).(*Object); !ok || v.Int("a") != 1 {
		t.Errorf("json: %#v", v)
	}
	if v := convertColumn("VARCHAR", []byte("x")); v != "x" {
		t.Errorf("varchar: %#v", v)
	}
}

func newTestServer(t *testing.T) (*Server, *Auth) {
	t.Setenv("JWT_SECRET", "jwt-test")
	t.Setenv("INTERNAL_SECRET", "internal-test")
	t.Setenv("ALLOWED_ORIGINS", "https://alfychat.app")
	s := NewServer()
	a := NewAuth()
	s.Handle("GET /items", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, 200, []any{})
	})
	s.Handle("POST /items", a.Require(func(w http.ResponseWriter, r *http.Request) {
		JSON(w, 201, O("user", UserID(r), "body", Body(r)))
	}))
	return s, a
}

func do(s *Server, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestRouting(t *testing.T) {
	s, _ := newTestServer(t)
	js := map[string]string{"Accept": "application/json"}

	if rec := do(s, "GET", "/items/", js, ""); rec.Code != 200 || rec.Body.String() != "[]" {
		t.Errorf("trailing slash: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "DELETE", "/items", js, ""); rec.Code != 404 || rec.Body.String() != `{"error":"Route not found","path":"/items"}` {
		t.Errorf("wrong method: %d %s", rec.Code, rec.Body)
	}
	if rec := do(s, "GET", "/nope", nil, ""); rec.Code != 404 {
		t.Errorf("html 404: %d", rec.Code)
	}
	if rec := do(s, "GET", "/items", js, ""); rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("helmet missing")
	}
}

func TestCORS(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(s, "OPTIONS", "/items", map[string]string{"Origin": "http://localhost:4000", "Access-Control-Request-Headers": "authorization"}, "")
	if rec.Code != 204 || rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:4000" || rec.Header().Get("Access-Control-Allow-Headers") != "authorization" {
		t.Errorf("preflight: %d %v", rec.Code, rec.Header())
	}
	rec = do(s, "GET", "/items", map[string]string{"Origin": "https://evil.example", "Accept": "application/json"}, "")
	if rec.Code != 500 {
		t.Errorf("bad origin: %d", rec.Code)
	}
	rec = do(s, "GET", "/items", map[string]string{"Origin": "https://alfychat.app"}, "")
	if rec.Code != 200 || rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("allowed origin: %d", rec.Code)
	}
}

func TestAuth(t *testing.T) {
	s, _ := newTestServer(t)
	js := map[string]string{"Accept": "application/json", "Content-Type": "application/json"}

	if rec := do(s, "POST", "/items", js, `{}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "Token d'authentification requis") {
		t.Errorf("no token: %d %s", rec.Code, rec.Body)
	}

	internal := map[string]string{"Content-Type": "application/json", "X-Internal-Secret": "internal-test", "X-User-Id": "u1"}
	if rec := do(s, "POST", "/items", internal, `{"b":1,"a":2}`); rec.Code != 201 || rec.Body.String() != `{"user":"u1","body":{"b":1,"a":2}}` {
		t.Errorf("internal: %d %s", rec.Code, rec.Body)
	}

	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"userId": "u2", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("jwt-test"))
	if rec := do(s, "POST", "/items", map[string]string{"Authorization": "Bearer " + tok}, ""); rec.Code != 201 || rec.Body.String() != `{"user":"u2","body":{}}` {
		t.Errorf("jwt: %d %s", rec.Code, rec.Body)
	}

	expired, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"userId": "u2", "exp": time.Now().Add(-time.Hour).Unix()}).SignedString([]byte("jwt-test"))
	if rec := do(s, "POST", "/items", map[string]string{"Authorization": "Bearer " + expired}, ""); !strings.Contains(rec.Body.String(), "Token expiré") {
		t.Errorf("expired: %s", rec.Body)
	}

	if rec := do(s, "POST", "/items", internal, `{bad`); rec.Code != 500 {
		t.Errorf("bad json: %d", rec.Code)
	}
}
