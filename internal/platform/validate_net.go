// ==========================================
// ALFYCHAT - VALIDATION : URL, e-mail, domaine, IP (validator 13.15)
// ==========================================

package platform

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// URLOptions reprend les options de validator.isURL.
type URLOptions struct {
	Protocols                 []string
	RequireTLD                bool
	RequireProtocol           bool
	RequireHost               bool
	RequirePort               bool
	RequireValidProtocol      bool
	AllowUnderscores          bool
	AllowTrailingDot          bool
	AllowProtocolRelativeURLs bool
	AllowFragments            bool
	AllowQueryComponents      bool
	DisallowAuth              bool
	ValidateLength            bool
	MaxAllowedLength          int
}

func DefaultURLOptions() URLOptions {
	return URLOptions{
		Protocols:            []string{"http", "https", "ftp"},
		RequireTLD:           true,
		RequireHost:          true,
		RequireValidProtocol: true,
		AllowFragments:       true,
		AllowQueryComponents: true,
		ValidateLength:       true,
		MaxAllowedLength:     2084,
	}
}

var (
	urlForbiddenRe = regexp.MustCompile(`[\s<>]`)
	protocolRe     = regexp.MustCompile(`(?i)^([a-z][a-z0-9+\-.]*):`)
	validAuthRe    = regexp.MustCompile(`^[a-zA-Z0-9\-_.%:]*$`)
	encodedRe      = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	wrappedIPv6Re  = regexp.MustCompile(`^\[([^\]]+)\](?::([0-9]+))?$`)
	digitsOnlyRe   = regexp.MustCompile(`^[0-9]+$`)
	startsDigitRe  = regexp.MustCompile(`^[0-9]`)
)

// IsURL : port fidèle de validator.isURL.
func IsURL(u string, o URLOptions) bool {
	if u == "" || urlForbiddenRe.MatchString(u) || strings.HasPrefix(u, "mailto:") {
		return false
	}
	if o.ValidateLength && JSLength(u) > o.MaxAllowedLength {
		return false
	}
	if !o.AllowFragments && strings.Contains(u, "#") {
		return false
	}
	if !o.AllowQueryComponents && (strings.Contains(u, "?") || strings.Contains(u, "&")) {
		return false
	}
	u, _, _ = strings.Cut(u, "#")
	u, _, _ = strings.Cut(u, "?")

	hadExplicitProtocol := false
	cleanUp := func(m []string) (string, bool) {
		hadExplicitProtocol = true
		protocol := strings.ToLower(m[1])
		if o.RequireValidProtocol && !contains(o.Protocols, protocol) {
			return "", false
		}
		return u[len(m[0]):], true
	}

	if m := protocolRe.FindStringSubmatch(u); m != nil {
		after := u[len(m[0]):]
		if !strings.HasPrefix(after, "//") {
			beforeSlash := after
			if i := strings.Index(after, "/"); i >= 0 {
				beforeSlash = after[:i]
			}
			if at := strings.Index(beforeSlash, "@"); at >= 0 {
				beforeAt := beforeSlash[:at]
				if validAuthRe.MatchString(beforeAt) && !encodedRe.MatchString(beforeAt) {
					if o.RequireProtocol {
						return false
					}
				} else {
					var ok bool
					if u, ok = cleanUp(m); !ok {
						return false
					}
				}
			} else if startsDigitRe.MatchString(after) {
				if o.RequireProtocol {
					return false
				}
			} else {
				var ok bool
				if u, ok = cleanUp(m); !ok {
					return false
				}
			}
		} else {
			var ok bool
			if u, ok = cleanUp(m); !ok {
				return false
			}
		}
	} else if o.RequireProtocol {
		return false
	}

	if strings.HasPrefix(u, "//") {
		if !hadExplicitProtocol && !o.AllowProtocolRelativeURLs {
			return false
		}
		u = u[2:]
	}
	if u == "" {
		return false
	}
	u, _, _ = strings.Cut(u, "/")
	if u == "" && !o.RequireHost {
		return true
	}

	split := strings.Split(u, "@")
	if len(split) > 1 {
		if o.DisallowAuth || split[0] == "" {
			return false
		}
		auth := split[0]
		split = split[1:]
		if strings.Count(auth, ":") > 1 {
			return false
		}
		user, password, hasColon := strings.Cut(auth, ":")
		if user == "" && hasColon && password == "" {
			return false
		}
	}
	hostname := strings.Join(split, "@")

	var host, ipv6 string
	portStr, hasPort := "", false
	if m := wrappedIPv6Re.FindStringSubmatch(hostname); m != nil {
		ipv6 = m[1]
		if m[2] != "" {
			portStr, hasPort = m[2], true
		}
	} else {
		parts := strings.Split(hostname, ":")
		host = parts[0]
		if len(parts) > 1 {
			portStr, hasPort = strings.Join(parts[1:], ":"), true
		}
	}
	if hasPort && portStr != "" {
		port, _ := strconv.Atoi(portStr)
		if !digitsOnlyRe.MatchString(portStr) || port <= 0 || port > 65535 {
			return false
		}
	} else if o.RequirePort {
		return false
	}
	if host == "" && !o.RequireHost {
		return true
	}
	fqdn := FQDNOptions{RequireTLD: o.RequireTLD, AllowUnderscores: o.AllowUnderscores, AllowTrailingDot: o.AllowTrailingDot}
	if !IsIP(host, 0) && !IsFQDN(host, fqdn) && (ipv6 == "" || !IsIP(ipv6, 6)) {
		return false
	}
	return true
}

// FQDNOptions reprend les options de validator.isFQDN.
type FQDNOptions struct {
	RequireTLD       bool
	AllowUnderscores bool
	AllowTrailingDot bool
	AllowNumericTLD  bool
	IgnoreMaxLength  bool
}

var (
	// Les plages JS portent sur des unités UTF-16 : un caractère hors BMP
	// (paire de substitution) est accepté par ¡-￿ mais pas par la
	// classe du TLD, d'où les deux traductions.
	tldRe        = regexp.MustCompile(`(?i)^([a-z\x{00A1}-\x{00A8}\x{00AA}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}]{2,}|xn[a-z0-9-]{2,})$`)
	spaceRe      = regexp.MustCompile(`[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`)
	numericTLDRe = regexp.MustCompile(`^\d+$`)
	fqdnPartRe   = regexp.MustCompile(`(?i)^[a-z_\x{00a1}-\x{10ffff}0-9-]+$`)
	fullWidthRe  = regexp.MustCompile(`[\x{ff01}-\x{ff5e}]`)
)

// IsFQDN : port de validator.isFQDN.
func IsFQDN(s string, o FQDNOptions) bool {
	if o.AllowTrailingDot && strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	parts := strings.Split(s, ".")
	tld := parts[len(parts)-1]
	if o.RequireTLD {
		if len(parts) < 2 {
			return false
		}
		if !o.AllowNumericTLD && !tldRe.MatchString(tld) {
			return false
		}
		if spaceRe.MatchString(tld) {
			return false
		}
	}
	if !o.AllowNumericTLD && numericTLDRe.MatchString(tld) {
		return false
	}
	for _, part := range parts {
		if JSLength(part) > 63 && !o.IgnoreMaxLength {
			return false
		}
		if !fqdnPartRe.MatchString(part) || fullWidthRe.MatchString(part) {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		if !o.AllowUnderscores && strings.Contains(part, "_") {
			return false
		}
	}
	return true
}

const ipv4Seg = `(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])`
const ipv4Addr = `(` + ipv4Seg + `[.]){3}` + ipv4Seg
const ipv6Seg = `(?:[0-9a-fA-F]{1,4})`

var (
	ipv4Re = regexp.MustCompile(`^` + ipv4Addr + `$`)
	ipv6Re = regexp.MustCompile(`^(` +
		`(?:` + ipv6Seg + `:){7}(?:` + ipv6Seg + `|:)|` +
		`(?:` + ipv6Seg + `:){6}(?:` + ipv4Addr + `|:` + ipv6Seg + `|:)|` +
		`(?:` + ipv6Seg + `:){5}(?::` + ipv4Addr + `|(:` + ipv6Seg + `){1,2}|:)|` +
		`(?:` + ipv6Seg + `:){4}(?:(:` + ipv6Seg + `){0,1}:` + ipv4Addr + `|(:` + ipv6Seg + `){1,3}|:)|` +
		`(?:` + ipv6Seg + `:){3}(?:(:` + ipv6Seg + `){0,2}:` + ipv4Addr + `|(:` + ipv6Seg + `){1,4}|:)|` +
		`(?:` + ipv6Seg + `:){2}(?:(:` + ipv6Seg + `){0,3}:` + ipv4Addr + `|(:` + ipv6Seg + `){1,5}|:)|` +
		`(?:` + ipv6Seg + `:){1}(?:(:` + ipv6Seg + `){0,4}:` + ipv4Addr + `|(:` + ipv6Seg + `){1,6}|:)|` +
		`(?::((?::` + ipv6Seg + `){0,5}:` + ipv4Addr + `|(?::` + ipv6Seg + `){1,7}|:))` +
		`)(%[0-9a-zA-Z.]{1,})?$`)
)

// IsIP : version 0 = 4 ou 6.
func IsIP(s string, version int) bool {
	switch version {
	case 4:
		return ipv4Re.MatchString(s)
	case 6:
		return ipv6Re.MatchString(s)
	}
	return ipv4Re.MatchString(s) || ipv6Re.MatchString(s)
}

var (
	emailUserUtf8Re   = regexp.MustCompile(`(?i)^[a-z\d!#\$%&'\*\+\-\/=\?\^_` + "`" + `{\|}~\x{00A1}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}]+$`)
	quotedEmailUtf8Re = regexp.MustCompile(`(?i)^([\s\x01-\x08\x0b\x0c\x0e-\x1f\x7f\x21\x23-\x5b\x5d-\x7e\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}]|(\\[\x01-\x09\x0b\x0c\x0d-\x7f\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}]))*$`)
)

// byteLength : longueur UTF-8 (isByteLength via encodeURI).
func byteLength(s string) int { return len(s) }

// IsEmail : validator.isEmail avec les options par défaut.
func IsEmail(s string) bool {
	if JSLength(s) > 254 {
		return false
	}
	parts := strings.Split(s, "@")
	domain := parts[len(parts)-1]
	user := strings.Join(parts[:len(parts)-1], "@")
	if byteLength(user) > 64 || byteLength(domain) > 254 {
		return false
	}
	if !IsFQDN(domain, FQDNOptions{RequireTLD: true}) {
		return false
	}
	if strings.HasPrefix(user, `"`) && strings.HasSuffix(user, `"`) && len(user) >= 1 {
		inner := ""
		if len(user) >= 2 {
			inner = user[1 : len(user)-1]
		}
		return quotedEmailUtf8Re.MatchString(inner)
	}
	for _, p := range strings.Split(user, ".") {
		if !emailUserUtf8Re.MatchString(p) {
			return false
		}
	}
	return true
}

var (
	icloudDomains  = []string{"icloud.com", "me.com"}
	outlookDomains = strings.Fields(`hotmail.at hotmail.be hotmail.ca hotmail.cl hotmail.co.il hotmail.co.nz hotmail.co.th hotmail.co.uk hotmail.com hotmail.com.ar hotmail.com.au hotmail.com.br hotmail.com.gr hotmail.com.mx hotmail.com.pe hotmail.com.tr hotmail.com.vn hotmail.cz hotmail.de hotmail.dk hotmail.es hotmail.fr hotmail.hu hotmail.id hotmail.ie hotmail.in hotmail.it hotmail.jp hotmail.kr hotmail.lv hotmail.my hotmail.ph hotmail.pt hotmail.sa hotmail.sg hotmail.sk live.be live.co.uk live.com live.com.ar live.com.mx live.de live.es live.eu live.fr live.it live.nl msn.com outlook.at outlook.be outlook.cl outlook.co.il outlook.co.nz outlook.co.th outlook.com outlook.com.ar outlook.com.au outlook.com.br outlook.com.gr outlook.com.pe outlook.com.tr outlook.com.vn outlook.cz outlook.de outlook.dk outlook.es outlook.fr outlook.hu outlook.id outlook.ie outlook.in outlook.it outlook.jp outlook.kr outlook.lv outlook.my outlook.ph outlook.pt outlook.sa outlook.sg outlook.sk passport.com`)
	yahooDomains   = []string{"rocketmail.com", "yahoo.ca", "yahoo.co.uk", "yahoo.com", "yahoo.de", "yahoo.fr", "yahoo.in", "yahoo.it", "ymail.com"}
	yandexDomains  = []string{"yandex.ru", "yandex.ua", "yandex.kz", "yandex.com", "yandex.by", "ya.ru"}
	dotsRe         = regexp.MustCompile(`\.+`)
)

// NormalizeEmail : validator.normalizeEmail avec les options par défaut.
// Renvoie false (ok=false) comme la version JS quand la partie locale disparaît.
func NormalizeEmail(email string) (string, bool) {
	raw := strings.Split(email, "@")
	domain := strings.ToLower(raw[len(raw)-1])
	user := strings.Join(raw[:len(raw)-1], "@")
	switch {
	case domain == "gmail.com" || domain == "googlemail.com":
		user, _, _ = strings.Cut(user, "+")
		user = dotsRe.ReplaceAllStringFunc(user, func(m string) string {
			if len(m) > 1 {
				return m
			}
			return ""
		})
		if user == "" {
			return "", false
		}
		user = strings.ToLower(user)
		domain = "gmail.com"
	case contains(icloudDomains, domain), contains(outlookDomains, domain):
		user, _, _ = strings.Cut(user, "+")
		if user == "" {
			return "", false
		}
		user = strings.ToLower(user)
	case contains(yahooDomains, domain):
		comps := strings.Split(user, "-")
		if len(comps) > 1 {
			user = strings.Join(comps[:len(comps)-1], "-")
		}
		if user == "" {
			return "", false
		}
		user = strings.ToLower(user)
	case contains(yandexDomains, domain):
		user = strings.ToLower(user)
		domain = "yandex.ru"
	default:
		user = strings.ToLower(user)
	}
	return user + "@" + domain, true
}

// ParseURL : équivalent de new URL(s) pour les cas courants (schéma + hôte).
func ParseURL(s string) (*url.URL, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return nil, false
	}
	return u, true
}
