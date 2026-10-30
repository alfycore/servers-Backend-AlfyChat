// ==========================================
// ALFYCHAT - REMONTÉE D'ERREURS AU GATEWAY
// ==========================================

package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

var (
	reportMu   sync.Mutex
	lastReport time.Time
)

// ReportErrorToGateway envoie une erreur au gateway, au plus une par minute.
func ReportErrorToGateway(errorType, message, stack, severity string) {
	secret := Env("INTERNAL_SECRET", "")
	if secret == "" {
		return
	}
	reportMu.Lock()
	if time.Since(lastReport) < time.Minute {
		reportMu.Unlock()
		return
	}
	lastReport = time.Now()
	reportMu.Unlock()

	body := O("serviceId", Env("SERVICE_ID", "unknown"), "errorType", errorType, "message", message, "severity", severity)
	if stack != "" {
		body.Set("stack", stack)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, Env("GATEWAY_URL", "http://localhost:3000")+"/api/internal/service-error", bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", secret)
	// Silencieux : ne pas créer de boucle d'erreurs.
	if res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req); err == nil {
		res.Body.Close()
	}
}

// ReportPanic remonte une panique récupérée dans un handler.
func ReportPanic(rec any) {
	go ReportErrorToGateway("unhandledRejection", fmt.Sprint(rec), string(debug.Stack()), "warning")
}

// InitLogger configure slog et la remontée des paniques fatales.
func InitLogger() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

// Fatal journalise, remonte l'erreur comme critique puis arrête le service.
func Fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	ReportErrorToGateway("uncaughtException", fmt.Sprintf("%s: %v", msg, err), "", "critical")
	os.Exit(1)
}

// Go lance une goroutine dont la panique est journalisée et remontée au lieu
// de tuer le process.
func Go(fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "err", rec, "stack", string(debug.Stack()))
				ReportPanic(rec)
			}
		}()
		fn()
	}()
}
