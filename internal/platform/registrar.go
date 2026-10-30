// ==========================================
// ALFYCHAT - CLIENT D'ENREGISTREMENT SERVICE
// Chaque microservice se déclare au gateway (/api/lb/register) puis envoie
// ses métriques toutes les 30 s. Sur 404 (gateway redémarré) il se
// ré-enregistre, sur 403 il arrête les heartbeats.
// ==========================================

package platform

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

const metricsWindow = 20 * time.Minute

var (
	metricsMu sync.Mutex
	requestTs []time.Time
	bytesOut  []bytesEntry
)

type bytesEntry struct {
	ts    time.Time
	bytes int
}

// TrackRequest compte une requête (et ses octets) dans la fenêtre de 20 min.
func TrackRequest(bytes int) {
	now := time.Now()
	metricsMu.Lock()
	requestTs = append(requestTs, now)
	if bytes > 0 {
		bytesOut = append(bytesOut, bytesEntry{now, bytes})
	}
	metricsMu.Unlock()
}

// TrackBytes compte des octets envoyés sans compter de requête.
func TrackBytes(n int) {
	if n <= 0 {
		return
	}
	metricsMu.Lock()
	bytesOut = append(bytesOut, bytesEntry{time.Now(), n})
	metricsMu.Unlock()
}

// CollectServiceMetrics renvoie les mêmes champs que collectServiceMetrics().
func CollectServiceMetrics() *Object {
	cutoff := time.Now().Add(-metricsWindow)

	metricsMu.Lock()
	i := 0
	for i < len(requestTs) && requestTs[i].Before(cutoff) {
		i++
	}
	requestTs = requestTs[i:]
	j := 0
	for j < len(bytesOut) && bytesOut[j].ts.Before(cutoff) {
		j++
	}
	bytesOut = bytesOut[j:]
	count := len(requestTs)
	total := 0
	for _, e := range bytesOut {
		total += e.bytes
	}
	metricsMu.Unlock()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	return O(
		"ramUsage", int64(ms.HeapAlloc),
		"ramMax", ramMax(),
		"cpuUsage", cpuUsage(),
		"cpuMax", 100,
		"bandwidthUsage", int64(float64(total)/metricsWindow.Seconds()+0.5),
		"requestCount20min", count,
	)
}

// ramMax : limite mémoire du runtime si elle est posée, sinon RAM totale.
func ramMax() int64 {
	if limit := debug.SetMemoryLimit(-1); limit > 0 && limit < 1<<62 {
		return limit
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		return int64(vm.Total)
	}
	return 0
}

// cpuUsage : charge cumulée depuis le démarrage de la machine, comme os.cpus().
func cpuUsage() int {
	times, err := cpu.Times(false)
	if err != nil || len(times) == 0 {
		return 0
	}
	t := times[0]
	total := t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
	if total <= 0 {
		return 0
	}
	return int((1-t.Idle/total)*100 + 0.5)
}

// StartServiceRegistration démarre l'enregistrement auprès du gateway.
// SERVICE_KEY (sk_...) est préféré ; à défaut INTERNAL_SECRET + SERVICE_ID.
func StartServiceRegistration(serviceType string) {
	gatewayURL := Env("GATEWAY_URL", "http://localhost:3000")
	serviceKey := Env("SERVICE_KEY", "")
	serviceID := Env("SERVICE_ID", "")
	internalSecret := Env("INTERNAL_SECRET", "")
	endpoint := Env("SERVICE_ENDPOINT", "")

	var (
		mu           sync.Mutex
		registeredID string
		ticker       *time.Ticker
		stop         chan struct{}
	)
	headers := func() http.Header {
		h := http.Header{"Content-Type": {"application/json"}}
		if serviceKey != "" {
			h.Set("X-Service-Key", serviceKey)
		} else {
			h.Set("X-Internal-Secret", internalSecret)
		}
		return h
	}

	post := func(path string, body any, timeout time.Duration) (*http.Response, error) {
		b, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, gatewayURL+path, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header = headers()
		return (&http.Client{Timeout: timeout}).Do(req)
	}

	stopHeartbeat := func() {
		if ticker != nil {
			ticker.Stop()
			close(stop)
			ticker = nil
		}
	}

	var register func()
	heartbeat := func() {
		mu.Lock()
		id := registeredID
		mu.Unlock()
		if id == "" || (serviceKey == "" && internalSecret == "") {
			return
		}
		body := map[string]any{"metrics": CollectServiceMetrics()}
		if serviceKey == "" {
			body["serviceId"] = id
		}
		res, err := post("/api/lb/heartbeat", body, 5*time.Second)
		if err != nil {
			return
		}
		res.Body.Close()
		switch res.StatusCode {
		case http.StatusForbidden:
			mu.Lock()
			stopHeartbeat()
			mu.Unlock()
		case http.StatusNotFound:
			slog.Warn("[ServiceClient] Service inconnu du gateway — ré-enregistrement...")
			mu.Lock()
			registeredID = ""
			stopHeartbeat()
			mu.Unlock()
			time.AfterFunc(3*time.Second, register)
		}
	}

	startHeartbeat := func() {
		mu.Lock()
		defer mu.Unlock()
		stopHeartbeat()
		ticker = time.NewTicker(30 * time.Second)
		stop = make(chan struct{})
		t, s := ticker, stop
		go func() {
			for {
				select {
				case <-t.C:
					heartbeat()
				case <-s:
					return
				}
			}
		}()
	}

	register = func() {
		if serviceKey == "" && internalSecret == "" {
			slog.Warn(`[ServiceClient] SERVICE_KEY et INTERNAL_SECRET absents — service "` + serviceType + `" non enregistré`)
			return
		}
		if endpoint == "" {
			slog.Warn("[ServiceClient] SERVICE_ENDPOINT absent — impossible de s'enregistrer")
			return
		}
		body := map[string]string{"endpoint": endpoint}
		if serviceKey == "" && serviceID != "" {
			body["serviceId"] = serviceID
		}
		res, err := post("/api/lb/register", body, 8*time.Second)
		if err != nil {
			slog.Error("[ServiceClient] Erreur réseau lors de l'enregistrement", "err", err)
			time.AfterFunc(15*time.Second, register)
			return
		}
		defer res.Body.Close()
		var data struct {
			ServiceID string `json:"serviceId"`
			GatewayID string `json:"gatewayId"`
			Error     string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&data)
		if res.StatusCode < 300 && data.ServiceID != "" {
			mu.Lock()
			registeredID = data.ServiceID
			mu.Unlock()
			slog.Info("[ServiceClient] Connecté — serviceId: " + data.ServiceID + " via " + data.GatewayID)
			startHeartbeat()
			return
		}
		slog.Error("[ServiceClient] Enregistrement refusé: " + data.Error)
		slog.Warn("[ServiceClient] → Vérifiez SERVICE_KEY dans votre .env et que le service est créé dans l'admin panel")
	}

	// Démarrage différé pour laisser le serveur s'initialiser, puis un ré-essai à 15 s.
	time.AfterFunc(2*time.Second, register)
	time.AfterFunc(15*time.Second, func() {
		mu.Lock()
		id := registeredID
		mu.Unlock()
		if id == "" {
			register()
		}
	})
}
