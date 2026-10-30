// ==========================================
// ALFYCHAT - CONFIGURATION
// Lecture du .env et des variables d'environnement.
// ==========================================

package platform

import (
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

var startedAt = time.Now()

// LoadEnv charge le .env du dossier courant s'il existe (comme dotenv.config()).
// Les variables déjà présentes dans l'environnement ne sont jamais écrasées.
func LoadEnv() {
	_ = godotenv.Load()
}

// LoadEnvOverride charge le .env en écrasant les variables déjà présentes
// (dotenv.config({ override: true })).
func LoadEnvOverride() {
	_ = godotenv.Overload()
}

// Env renvoie la variable ou la valeur par défaut si elle est vide.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvInt renvoie la variable convertie en entier, ou la valeur par défaut.
func EnvInt(key string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return n
	}
	return def
}

// MustEnv arrête le service si la variable est absente : on refuse de
// démarrer sans secret plutôt que de tourner en mode dégradé.
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error(key + " environment variable is required — refusing to start without it")
		os.Exit(1)
	}
	return v
}

// Uptime en secondes, équivalent de process.uptime().
func Uptime() float64 {
	return time.Since(startedAt).Seconds()
}

// Now renvoie l'heure tronquée à la milliseconde, comme new Date() : les
// DATETIME arrondis par MySQL restent identiques à ceux écrits par mysql2.
func Now() time.Time {
	return time.Now().Truncate(time.Millisecond)
}
