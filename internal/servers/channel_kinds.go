// ==========================================
// ALFYCHAT - TYPES DE SALON
// Les 16 types d'origine, plus 30 types « à usage » construits sur une vue
// existante (texte, forum, vocal, scène). Leurs règles d'écriture (lecture
// seule, médias seuls, liens seuls…) sont appliquées par le gateway ; ici on
// ne fait que les accepter et poser leur mode lent par défaut.
// Liste à garder identique dans gateway/src/channel_kinds.rs et dans l'app
// (components/alfy/guild/channel-kinds.ts).
// ==========================================

package servers

// extraChannelTypes : nouveaux types, ajoutés en fin d'ENUM (la migration MODIFY reste compatible).
var extraChannelTypes = []string{
	// Texte
	"rules", "welcome", "changelog", "logs", "resources", "links", "memes", "art", "screenshots", "music",
	"clips", "questions", "oneword", "emoji", "code", "selfpromo", "focus", "commands", "introductions", "lfg",
	// Forum
	"support", "bugs", "feedback", "jobs", "wiki", "showcase",
	// Vocal et scène
	"listening", "gaming", "afk", "podcast",
}

// defaultSlowMode : secondes de mode lent posées à la création si rien n'est précisé.
var defaultSlowMode = map[string]float64{
	"selfpromo":     3600,
	"focus":         60,
	"introductions": 21600,
	"lfg":           300,
}
