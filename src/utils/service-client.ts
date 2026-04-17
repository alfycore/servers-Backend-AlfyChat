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
  const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
  const SERVICE_KEY = process.env.SERVICE_KEY || process.env.INTERNAL_SECRET || '';
  const SERVICE_ID  = process.env.SERVICE_ID  || `${serviceType}-default`;

  async function heartbeat() {
    try {
      const res = await fetch(`${GATEWAY_URL}/api/internal/service/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: SERVICE_KEY,
          id: SERVICE_ID,
          metrics: collectServiceMetrics(),
        }),
      });
      if (res.status === 404) {
        console.warn(`[ServiceClient] Instance "${SERVICE_ID}" inconnue du gateway — un administrateur doit l'ajouter via /api/admin/services`);
      } else if (res.status === 401 || res.status === 403) {
        console.warn(`[ServiceClient] Heartbeat refusé (${res.status}) — clé invalide ou instance bannie`);
      }
    } catch { /* non bloquant */ }
  }

  // Heartbeat immédiat puis toutes les 30s (pas d'auto-enregistrement : admin-only)
  setTimeout(heartbeat, 3_000);
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
