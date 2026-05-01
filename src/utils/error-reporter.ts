import dotenv from 'dotenv';
dotenv.config();

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || '';
const SERVICE_ID = process.env.SERVICE_ID || 'unknown';

let _lastReport = 0;
const THROTTLE_MS = 60_000;

export async function reportErrorToGateway(opts: {
  errorType: string;
  message: string;
  stack?: string;
  severity?: 'info' | 'warning' | 'critical';
}): Promise<void> {
  if (!INTERNAL_SECRET) return;
  const now = Date.now();
  if (now - _lastReport < THROTTLE_MS) return;
  _lastReport = now;
  try {
    await fetch(`${GATEWAY_URL}/api/internal/service-error`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': INTERNAL_SECRET,
      },
      body: JSON.stringify({ serviceId: SERVICE_ID, ...opts }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    // Silencieux : ne pas créer de boucle d'erreurs
  }
}

export function registerGlobalErrorHandlers(): void {
  process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
    reportErrorToGateway({
      errorType: 'uncaughtException',
      message: err.message,
      stack: err.stack,
      severity: 'critical',
    }).catch(() => {});
  });

  process.on('unhandledRejection', (reason) => {
    const msg = reason instanceof Error ? reason.message : String(reason);
    const stack = reason instanceof Error ? reason.stack : undefined;
    console.error('[unhandledRejection]', reason);
    reportErrorToGateway({
      errorType: 'unhandledRejection',
      message: msg,
      stack,
      severity: 'warning',
    }).catch(() => {});
  });
}
