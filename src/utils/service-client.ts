// ==========================================
// ALFYCHAT - CLIENT D'ENREGISTREMENT SERVICE
// Chaque microservice l'importe pour se déclarer au gateway
// et envoyer ses métriques périodiquement.
//
// Usage (dans le index.ts d'un service) :
//   import { startServiceRegistration } from './utils/service-client';
//   startServiceRegistration('messages');
// ==========================================

import os from 'os';
import v8 from 'v8';

type ServiceType = 'users' | 'messages' | 'friends' | 'calls' | 'servers' | 'bots' | 'media';

// Compteur de requêtes fenêtre 20min
const WINDOW_MS = 20 * 60 * 1000;
const _requestTs: number[] = [];
let _bytesOut: { ts: number; bytes: number }[] = [];

/** Middleware Express à appeler dans chaque service pour compter les requêtes */
export function trackRequest(bytes = 0) {
  const now = Date.now();
  _requestTs.push(now);
  if (bytes > 0) _bytesOut.push({ ts: now, bytes });
}

/** Collecte les métriques du process Node */
export function collectServiceMetrics() {
  const now = Date.now();
  const cutoff = now - WINDOW_MS;

  // Purge
  while (_requestTs.length && _requestTs[0] < cutoff) _requestTs.shift();
  _bytesOut = _bytesOut.filter((e) => e.ts >= cutoff);

  const mem = process.memoryUsage();
  const heapLimit = v8.getHeapStatistics().heap_size_limit;
  const cpus = os.cpus();
  let idle = 0, total = 0;
  for (const c of cpus) {
    for (const val of Object.values(c.times)) total += val;
    idle += c.times.idle;
  }
  const cpuUsage = total > 0 ? Math.round((1 - idle / total) * 100) : 0;
  const totalBytes = _bytesOut.reduce((s, e) => s + e.bytes, 0);

  return {
    ramUsage: mem.heapUsed,
    ramMax: heapLimit,
    cpuUsage,
    cpuMax: 100,
    bandwidthUsage: Math.round(totalBytes / (WINDOW_MS / 1000)),
    requestCount20min: _requestTs.length,
  };
}

/**
 * Démarre la boucle d'enregistrement + heartbeat auprès du gateway.
 * À appeler une fois dans le callback de `app.listen()`.
 */
export function startServiceRegistration(serviceType: ServiceType): void {
  const GATEWAY_URL     = process.env.GATEWAY_URL     || 'http://localhost:3000';
  const INTERNAL_SECRET = process.env.INTERNAL_SECRET || 'alfychat-internal-secret-dev';
  const SERVICE_ID      = process.env.SERVICE_ID      || `${serviceType}-default`;
  const SERVICE_LOCATION = (process.env.SERVICE_LOCATION || 'EU').toUpperCase();
  const PORT            = process.env.PORT            || '3000';
  const SERVICE_ENDPOINT = process.env.SERVICE_ENDPOINT || `http://localhost:${PORT}`;
  const SERVICE_DOMAIN  = process.env.SERVICE_DOMAIN  || `localhost:${PORT}`;

  async function register() {
    try {
      const res = await fetch(`${GATEWAY_URL}/api/internal/service/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: INTERNAL_SECRET,
          id: SERVICE_ID,
          serviceType,
          endpoint: SERVICE_ENDPOINT,
          domain: SERVICE_DOMAIN,
          location: SERVICE_LOCATION,
          metrics: collectServiceMetrics(),
        }),
      });
      if (res.ok) {
        console.log(`[ServiceClient] Enregistré au gateway (${SERVICE_ID})`);
      } else {
        console.warn(`[ServiceClient] Échec enregistrement: ${res.status}`);
      }
    } catch {
      console.warn('[ServiceClient] Gateway non disponible, nouvelle tentative…');
    }
  }

  async function heartbeat() {
    try {
      const res = await fetch(`${GATEWAY_URL}/api/internal/service/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: INTERNAL_SECRET,
          id: SERVICE_ID,
          metrics: collectServiceMetrics(),
        }),
      });
      if (res.status === 404) {
        // Gateway redémarré → ré-enregistrement
        await register();
      }
    } catch { /* non bloquant */ }
  }

  // Premier enregistrement avec retries
  let attempt = 0;
  const tryRegister = async () => {
    await register();
    attempt++;
    if (attempt < 5) setTimeout(tryRegister, attempt * 10_000);
  };
  setTimeout(tryRegister, 3_000);

  // Heartbeat toutes les 30s
  setInterval(heartbeat, 30_000);
}

/**
 * Middleware Express léger pour compter les requêtes et le débit.
 * À placer en début de pipeline : app.use(serviceMetricsMiddleware)
 */
export function serviceMetricsMiddleware(
  req: any,
  res: any,
  next: () => void,
): void {
  const origJson = res.json?.bind(res);
  const origSend = res.send?.bind(res);

  const track = (body: any) => {
    try {
      const bytes = typeof body === 'string' ? Buffer.byteLength(body) :
        Buffer.isBuffer(body) ? body.length :
        Buffer.byteLength(JSON.stringify(body));
      trackRequest(bytes);
    } catch {
      trackRequest(0);
    }
  };

  if (origJson) res.json = (b: any) => { track(b); return origJson(b); };
  if (origSend) res.send = (b: any) => { track(b); return origSend(b); };

  trackRequest(0);
  next();
}
