// ==========================================
// ALFYCHAT — Service Registrar
// Enregistre le microservice auprès du gateway
// et envoie des heartbeats périodiques.
// ==========================================

import dotenv from 'dotenv';
dotenv.config();
import os from 'os';

const GATEWAY_URL        = process.env.GATEWAY_URL     || 'http://localhost:3000';
const SERVICE_KEY        = process.env.SERVICE_KEY     || '';
const SERVICE_ENDPOINT   = process.env.SERVICE_ENDPOINT|| '';
const HEARTBEAT_INTERVAL = 30_000;

let _serviceId: string | null = null;
let _heartbeatTimer: NodeJS.Timeout | null = null;
let _requestCount = 0;

export function incrementRequestCount(): void { _requestCount++; }

async function doRegister(): Promise<void> {
  if (!SERVICE_KEY) {
    console.warn('[Registrar] SERVICE_KEY absent — service non enregistré auprès du gateway');
    return;
  }
  if (!SERVICE_ENDPOINT) {
    console.warn('[Registrar] SERVICE_ENDPOINT absent — impossible de s\'enregistrer');
    return;
  }
  try {
    const res = await fetch(`${GATEWAY_URL}/api/lb/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-Service-Key': SERVICE_KEY },
      body:    JSON.stringify({ endpoint: SERVICE_ENDPOINT }),
      signal:  AbortSignal.timeout(8000),
    });
    const data = await res.json() as any;
    if (res.ok && data.serviceId) {
      _serviceId = data.serviceId;
      console.info(`[Registrar] Connecté au gateway "${data.gatewayId}" — serviceId: ${_serviceId}`);
      startHeartbeat();
    } else {
      console.error('[Registrar] Échec enregistrement:', data.error ?? JSON.stringify(data));
    }
  } catch (err) {
    console.error('[Registrar] Erreur réseau lors de l\'enregistrement:', err);
  }
}

function collectMetrics() {
  const mem = process.memoryUsage();
  const cpus = os.cpus();
  const cpuUsage = cpus.reduce((sum, c) => {
    const t = Object.values(c.times).reduce((a, b) => a + b, 0);
    return sum + ((t - c.times.idle) / t) * 100;
  }, 0) / (cpus.length || 1);

  const metrics = {
    cpuUsage:          Math.round(cpuUsage),
    cpuMax:            100,
    ramUsage:          mem.rss,
    ramMax:            os.totalmem(),
    bandwidthUsage:    0,
    requestCount20min: _requestCount,
  };
  _requestCount = 0;
  return metrics;
}

async function sendHeartbeat(): Promise<void> {
  if (!SERVICE_KEY || !_serviceId) return;
  try {
    const res = await fetch(`${GATEWAY_URL}/api/lb/heartbeat`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-Service-Key': SERVICE_KEY },
      body:    JSON.stringify({ metrics: collectMetrics() }),
      signal:  AbortSignal.timeout(5000),
    });
    if (res.status === 404) {
      // Gateway ne connaît plus ce service (redémarrage) → se ré-enregistrer
      console.warn('[Registrar] Service inconnu du gateway — ré-enregistrement...');
      _serviceId = null;
      clearInterval(_heartbeatTimer!);
      _heartbeatTimer = null;
      setTimeout(doRegister, 3000);
    }
  } catch {
    // Silencieux — le gateway est peut-être temporairement indisponible
  }
}

function startHeartbeat(): void {
  if (_heartbeatTimer) clearInterval(_heartbeatTimer);
  _heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL);
  if (_heartbeatTimer.unref) _heartbeatTimer.unref();
}

async function doDeregister(): Promise<void> {
  if (!SERVICE_KEY) return;
  try {
    await fetch(`${GATEWAY_URL}/api/lb/deregister`, {
      method:  'POST',
      headers: { 'X-Service-Key': SERVICE_KEY },
      signal:  AbortSignal.timeout(3000),
    });
  } catch { /* silencieux */ }
}

export async function startServiceRegistrar(): Promise<void> {
  await doRegister();

  // Retry si le gateway n'est pas encore prêt
  if (!_serviceId) {
    setTimeout(async () => {
      if (!_serviceId) await doRegister();
    }, 10_000);
  }

  process.on('SIGTERM', async () => { await doDeregister(); });
  process.on('SIGINT',  async () => { await doDeregister(); });
}
