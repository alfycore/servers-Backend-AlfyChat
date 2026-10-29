// ==========================================
// ALFYCHAT - SERVICE SERVEURS
// Modèle P2P style TeamSpeak - Les utilisateurs hébergent leurs serveurs
// Le système central gère uniquement l'annuaire et les métadonnées
// ==========================================

package main

import (
	"context"
	"log/slog"

	"github.com/alfychat/servers/internal/platform"
	"github.com/alfychat/servers/internal/servers"
)

func main() {
	platform.LoadEnv()
	platform.InitLogger()

	srv := platform.NewServer()
	auth := platform.NewAuth()
	auth.AccessOnly = true
	auth.NoExpired = true
	auth.MissingMessage = "Authentification requise"
	auth.AllowNoUser = true
	auth.InternalDefaultUser = "internal"

	db, err := platform.OpenDatabase()
	if err != nil {
		platform.Fatal("Erreur au démarrage", err)
	}
	rdb, err := platform.NewRedis()
	if err != nil {
		platform.Fatal("Erreur au démarrage", err)
	}
	if err := servers.Migrate(context.Background(), db); err != nil {
		platform.Fatal("Erreur au démarrage", err)
	}

	servers.Register(srv, db, rdb, auth)
	servers.StartCleanups(db, rdb)

	port := platform.Env("PORT", "3005")
	err = srv.Listen(port, func() {
		slog.Info("🚀 Service Servers démarré sur le port " + port)
		platform.StartServiceRegistration("servers")
	})
	if err != nil {
		platform.Fatal("Erreur au démarrage", err)
	}
}
