// ==========================================
// ALFYCHAT - ROUTEUR ORDONNÉ (sémantique Express)
// Les routes sont essayées dans l'ordre de déclaration et la première qui
// correspond gagne : "/bots/servers/{id}" déclarée avant "/bots/{id}/oauth2"
// l'emporte, comme dans Express. Correspondance insensible à la casse, slash
// final optionnel, paramètres décodés (decodeURIComponent).
// ==========================================

package platform

import (
	"net/http"
	"net/url"
	"strings"
)

type route struct {
	method  string
	segs    []string // "{name}" = paramètre, "{name...}" = reste du chemin
	handler http.HandlerFunc
}

// Mount déclare un préfixe de routeur monté (app.use('/friends', router)) :
// Express y tolère un slash supplémentaire ("/friends//blocked").
func (s *Server) Mount(prefix string) {
	s.mounts = append(s.mounts, strings.TrimRight(prefix, "/"))
}

// Handle enregistre une route : "GET /friends/{id}". Méthode "ALL" = toutes.
func (s *Server) Handle(pattern string, h http.HandlerFunc) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		method, path = "ALL", pattern
	}
	s.routes = append(s.routes, route{method: method, segs: splitPath(path), handler: h})
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// dispatch sert la première route correspondante ; false si aucune.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) bool {
	// Express accepte un unique slash final ("/friends/" == "/friends").
	raw := r.URL.EscapedPath()
	for _, m := range s.mounts {
		if len(raw) > len(m)+1 && strings.EqualFold(raw[:len(m)], m) && raw[len(m):len(m)+2] == "//" {
			raw = raw[:len(m)] + raw[len(m)+1:]
			break
		}
	}
	if len(raw) > 1 && strings.HasSuffix(raw, "/") {
		raw = raw[:len(raw)-1]
	}
	parts := splitPath(raw)
	if strings.HasPrefix(raw, "//") || strings.Contains(strings.Trim(raw, "/"), "//") {
		return false
	}

	for _, rt := range s.routes {
		if !methodMatches(rt.method, r.Method) {
			continue
		}
		params, ok := matchSegs(rt.segs, parts)
		if !ok {
			continue
		}
		for name, v := range params {
			r.SetPathValue(name, v)
		}
		rt.handler(w, r)
		return true
	}
	return false
}

func methodMatches(routeMethod, reqMethod string) bool {
	if routeMethod == "ALL" || routeMethod == reqMethod {
		return true
	}
	return routeMethod == http.MethodGet && reqMethod == http.MethodHead
}

func matchSegs(segs, parts []string) (map[string]string, bool) {
	var params map[string]string
	for i, seg := range segs {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "...}") {
			if i >= len(parts) {
				return nil, false
			}
			rest, err := url.PathUnescape(strings.Join(parts[i:], "/"))
			if err != nil {
				return nil, false
			}
			if params == nil {
				params = map[string]string{}
			}
			params[seg[1:len(seg)-4]] = rest
			return params, true
		}
		if i >= len(parts) {
			return nil, false
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			v, err := url.PathUnescape(parts[i])
			if err != nil || parts[i] == "" {
				return nil, false
			}
			if params == nil {
				params = map[string]string{}
			}
			params[seg[1:len(seg)-1]] = v
			continue
		}
		if !strings.EqualFold(seg, parts[i]) {
			return nil, false
		}
	}
	if len(segs) != len(parts) {
		return nil, false
	}
	return params, true
}
