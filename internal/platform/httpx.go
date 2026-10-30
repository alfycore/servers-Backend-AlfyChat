// ==========================================
// ALFYCHAT - COUCHE HTTP
// Reproduit le pipeline Express des services TS : cors → helmet → json →
// métriques → routes → 404/500 négociés (HTML pour un navigateur, JSON sinon).
// ==========================================

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
)

type ctxKey int

const (
	ctxBody ctxKey = iota
	ctxUserID
	ctxQuery
	ctxRaw
)

// Server regroupe le routeur et les réglages du pipeline.
type Server struct {
	routes []route
	mounts []string
	// Middlewares appliqués avant les routes, dans l'ordre (app.use(fn)).
	middlewares []func(http.ResponseWriter, *http.Request) bool
	// BodyLimit : taille max du JSON (express.json() = 100 ko par défaut).
	BodyLimit int64
	// PublicDir : dossier des pages HTML d'erreur.
	PublicDir string
	// AllowedOrigins : origines CORS autorisées en plus de localhost.
	AllowedOrigins []string
	// NoCORS / NoHelmet : désactivent ces middlewares (services internes).
	NoCORS   bool
	NoHelmet bool
	// SkipHelmet : chemins où helmet n'est pas appliqué (webhooks).
	SkipHelmet func(*http.Request) bool
	// SkipJSON : chemins dont le corps JSON n'est pas analysé (express.raw) ;
	// les octets restent accessibles par RawBytes.
	SkipJSON func(*http.Request) bool
	// StrictLocalhost : refuse les origines localhost (NODE_ENV=production).
	StrictLocalhost bool
	// CORSOrigin : origine unique annoncée à tous les appelants (cors({ origin: '…' })),
	// sans rejet ni réflexion de l'origine reçue.
	CORSOrigin string
	// HelmetOverride : en-têtes qui remplacent ceux de helmet.
	HelmetOverride map[string]string
	// AllowNonHTTPOrigins : accepte les origines qui ne sont pas http(s)://
	// (applications natives, file://, « null »).
	AllowNonHTTPOrigins bool
}

func NewServer() *Server {
	origins := strings.Split(Env("ALLOWED_ORIGINS", Env("FRONTEND_URL", "http://localhost:4000")), ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}
	return &Server{
		BodyLimit:      100 * 1024,
		PublicDir:      "public",
		AllowedOrigins: origins,
	}
}

// Use ajoute un middleware global ; il renvoie false s'il a déjà répondu.
func (s *Server) Use(mw func(http.ResponseWriter, *http.Request) bool) {
	s.middlewares = append(s.middlewares, mw)
}

var localhostOrigin = regexp.MustCompile(`^http://localhost(:\d+)?$`)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("panic", "err", rec, "stack", string(debug.Stack()))
			ReportPanic(rec)
			s.ServeError(w, r, http.StatusInternalServerError)
		}
	}()

	if !s.NoCORS {
		if handled, err := s.cors(w, r); err != nil {
			s.ServeError(w, r, http.StatusInternalServerError)
			return
		} else if handled {
			return
		}
	}
	if !s.NoHelmet && (s.SkipHelmet == nil || !s.SkipHelmet(r)) {
		helmet(w.Header())
		for k, v := range s.HelmetOverride {
			w.Header().Set(k, v)
		}
	}

	if r.Body != nil && isJSONRequest(r) {
		body, err := io.ReadAll(io.LimitReader(r.Body, s.BodyLimit+1))
		if err != nil || int64(len(body)) > s.BodyLimit {
			s.ServeError(w, r, http.StatusInternalServerError)
			return
		}
		if len(body) > 0 {
			r = r.WithContext(context.WithValue(r.Context(), ctxRaw, body))
		}
		if s.SkipJSON != nil && s.SkipJSON(r) {
			body = nil
		}
		if len(bytes.TrimSpace(body)) > 0 {
			parsed, err := ParseJSON(body)
			// express.json() en mode strict n'accepte que des objets ou des tableaux.
			_, isObj := parsed.(*Object)
			_, isArr := parsed.([]any)
			if err != nil || (!isObj && !isArr) {
				s.ServeError(w, r, http.StatusInternalServerError)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxBody, parsed))
		}
	}
	// req.body vaut {} quand aucun JSON n'a été lu : on le pose pour que les
	// sanitizers puissent y écrire.
	if r.Context().Value(ctxBody) == nil {
		r = r.WithContext(context.WithValue(r.Context(), ctxBody, O()))
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxQuery, parseQuery(r)))

	TrackRequest(0)
	mw := &meteredWriter{ResponseWriter: w}

	for _, m := range s.middlewares {
		if !m(mw, r) {
			return
		}
	}
	if s.dispatch(mw, r) {
		return
	}
	if r.URL.Path == "/" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && s.prefersHTML(r) {
		s.sendFile(mw, filepath.Join(s.PublicDir, "index.html"), http.StatusOK)
		return
	}
	s.NotFound(mw, r)
}

// meteredWriter compte les octets envoyés pour les métriques de débit.
type meteredWriter struct {
	http.ResponseWriter
	bytes int
}

func (m *meteredWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	m.bytes += n
	TrackBytes(n)
	return n, err
}

func (m *meteredWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (m *meteredWriter) Unwrap() http.ResponseWriter { return m.ResponseWriter }

func isJSONRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// ── CORS (paquet `cors` avec credentials: true) ───────────────────────────

func (s *Server) cors(w http.ResponseWriter, r *http.Request) (bool, error) {
	origin := r.Header.Get("Origin")
	if s.CORSOrigin != "" {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", s.CORSOrigin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
			if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
				h.Set("Access-Control-Allow-Headers", req)
				h.Add("Vary", "Access-Control-Request-Headers")
			}
			h.Set("Content-Length", "0")
			w.WriteHeader(http.StatusNoContent)
			return true, nil
		}
		return false, nil
	}
	local := localhostOrigin.MatchString(origin) && !s.StrictLocalhost
	if s.AllowNonHTTPOrigins && origin != "" && !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
		local = true
	}
	if origin != "" && !local && !contains(s.AllowedOrigins, origin) {
		return false, errors.New("CORS: origine non autorisée — " + origin)
	}
	h := w.Header()
	if origin != "" {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	h.Add("Vary", "Origin")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
		if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
			h.Set("Access-Control-Allow-Headers", req)
			h.Add("Vary", "Access-Control-Request-Headers")
		}
		h.Set("Content-Length", "0")
		w.WriteHeader(http.StatusNoContent)
		return true, nil
	}
	return false, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// helmet pose les en-têtes par défaut de helmet v7.
func helmet(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Origin-Agent-Cluster", "?1")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-DNS-Prefetch-Control", "off")
	h.Set("X-Download-Options", "noopen")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("X-Permitted-Cross-Domain-Policies", "none")
	h.Set("X-XSS-Protection", "0")
}

// ── Réponses ──────────────────────────────────────────────────────────────

// JSON envoie le payload brut, comme res.status(x).json(v). Jamais d'enveloppe
// { success, data } : le client l'ajoute lui-même.
func JSON(w http.ResponseWriter, status int, v any) {
	b, err := marshalNoEscape(v)
	if err != nil {
		slog.Error("json", "err", err)
		status = http.StatusInternalServerError
		b = []byte(`{"error":"Internal server error"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// Error envoie { error: msg }.
func Error(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, O("error", msg))
}

// JSONString sérialise comme JSON.stringify (sans échappement HTML).
func JSONString(v any) string {
	b, err := marshalNoEscape(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsSafe(v)); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsSafe remplace NaN/Infinity par null, comme JSON.stringify.
func jsSafe(v any) any {
	if f, ok := v.(float64); ok && (math.IsNaN(f) || math.IsInf(f, 0)) {
		return nil
	}
	return v
}

// NotFound répond comme le dernier middleware des services TS.
func (s *Server) NotFound(w http.ResponseWriter, r *http.Request) {
	if s.prefersHTML(r) {
		s.sendFile(w, filepath.Join(s.PublicDir, "errors", "404.html"), http.StatusNotFound)
		return
	}
	JSON(w, http.StatusNotFound, O("error", "Route not found", "path", r.URL.EscapedPath()))
}

// ServeError répond comme le gestionnaire d'erreurs Express (500).
func (s *Server) ServeError(w http.ResponseWriter, r *http.Request, status int) {
	if s.prefersHTML(r) {
		s.sendFile(w, filepath.Join(s.PublicDir, "errors", strconv.Itoa(status)+".html"), status)
		return
	}
	JSON(w, status, O("error", "Internal server error"))
}

func (s *Server) sendFile(w http.ResponseWriter, path string, status int) {
	b, err := os.ReadFile(path)
	if err != nil {
		JSON(w, status, O("error", http.StatusText(status)))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// prefersHTML reproduit req.accepts(['html', 'json']) === 'html'.
func (s *Server) prefersHTML(r *http.Request) bool {
	return Accepts(r.Header.Get("Accept"), "text/html", "application/json") == "text/html"
}

// Accepts choisit le type préféré parmi offers selon l'en-tête Accept, avec
// les règles du paquet `negotiator` : qualité, puis spécificité, puis ordre
// dans l'en-tête, puis ordre des offres. Sans en-tête, la première offre gagne.
func Accepts(header string, offers ...string) string {
	if strings.TrimSpace(header) == "" {
		return offers[0]
	}
	type accepted struct {
		typ, sub string
		q        float64
		order    int
	}
	var list []accepted
	for i, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		full := strings.ToLower(strings.TrimSpace(fields[0]))
		typ, sub, ok := strings.Cut(full, "/")
		if !ok {
			continue
		}
		q := 1.0
		for _, p := range fields[1:] {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.TrimSpace(k) == "q" {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = f
				}
			}
		}
		list = append(list, accepted{typ, sub, q, i})
	}

	type scored struct {
		offer       string
		q           float64
		spec, order int
		index       int
	}
	var res []scored
	for i, offer := range offers {
		typ, sub, _ := strings.Cut(offer, "/")
		best := scored{offer: offer, q: -1, index: i}
		for _, a := range list {
			spec := 0
			if a.typ == typ {
				spec |= 4
			} else if a.typ != "*" {
				continue
			}
			if a.sub == sub {
				spec |= 2
			} else if a.sub != "*" {
				continue
			}
			if spec > best.spec || (spec == best.spec && a.q > best.q) || best.q < 0 {
				best.q, best.spec, best.order = a.q, spec, a.order
			}
		}
		if best.q > 0 {
			res = append(res, best)
		}
	}
	if len(res) == 0 {
		return ""
	}
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].q != res[j].q {
			return res[i].q > res[j].q
		}
		if res[i].spec != res[j].spec {
			return res[i].spec > res[j].spec
		}
		if res[i].order != res[j].order {
			return res[i].order < res[j].order
		}
		return res[i].index < res[j].index
	})
	return res[0].offer
}

// ── Corps de requête ──────────────────────────────────────────────────────

// Body renvoie le corps JSON objet, ou un objet vide (req.body vaut {} dans Express).
func Body(r *http.Request) *Object {
	if o, ok := r.Context().Value(ctxBody).(*Object); ok {
		return o
	}
	return O()
}

// RawBytes renvoie les octets exacts d'un corps JSON non vide (req.rawBody).
func RawBytes(r *http.Request) []byte {
	b, _ := r.Context().Value(ctxRaw).([]byte)
	return b
}

// SendEmpty répond comme res.status(n).send(”) : corps vide, text/html.
func SendEmpty(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

// RawBody renvoie le corps JSON tel quel (objet, tableau ou nil).
func RawBody(r *http.Request) any {
	return r.Context().Value(ctxBody)
}

// Truthy applique la vérité JavaScript.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil, undefinedT:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0 && !math.IsNaN(x)
	case int64:
		return x != 0
	case int:
		return x != 0
	default:
		return true
	}
}

// Or renvoie la première valeur vraie au sens JS (a || b || c).
func Or(vals ...any) any {
	for _, v := range vals {
		if Truthy(v) {
			return v
		}
	}
	if len(vals) == 0 {
		return nil
	}
	return vals[len(vals)-1]
}

// AsString renvoie (v, true) si v est une chaîne.
func AsString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// ── Démarrage ─────────────────────────────────────────────────────────────

// Listen démarre le serveur HTTP sur PORT.
func (s *Server) Listen(port string, onReady func()) error {
	srv := &http.Server{Addr: ":" + port, Handler: s}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	if onReady != nil {
		go onReady()
	}
	return srv.Serve(ln)
}
