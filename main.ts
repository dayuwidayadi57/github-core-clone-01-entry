// Forge entrypoint: bind a port, register it with the env, wait for the env to finish.
// The scoring suite talks to the server that app.ts builds; this file owns only the
// lifecycle between the process and the env that runs the suite:
//   1. find the env at MAKEFUN_ENV_URL (give it a short while to appear, then fail loud)
//   2. listen on an ephemeral port the kernel picks (never 8080 — the env owns it)
//   3. tell the env the port with POST /register {"port": N}
//   4. poll GET /done until the env answers {"done": true}, then close and exit 0
// A 409 from register means another entry registered first: this process just waits
// like any other. 400/405 are contract errors and end the program at once.

import { buildServer } from './app.ts';

const ENV_WAIT_MS = 30_000;
const REQUEST_TIMEOUT_MS = 30_000;
const FIRST_RETRY_MS = 250;
const LAST_RETRY_MS = 2_000;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoff(attempt: number): number {
  const growth = FIRST_RETRY_MS * 2 ** (attempt > 8 ? 8 : attempt);
  return growth > LAST_RETRY_MS ? LAST_RETRY_MS : growth;
}

async function envOrigin(): Promise<string> {
  const deadline = Date.now() + ENV_WAIT_MS;
  for (;;) {
    const raw = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
    if (raw !== '') return raw;
    if (Date.now() >= deadline) {
      throw new Error('MAKEFUN_ENV_URL never appeared: no env to register with');
    }
    await delay(1000);
  }
}

async function announce(envUrl: string, port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.status === 200 || response.status === 409) return;
      if (response.status === 400 || response.status === 405) {
        throw new Error(`register refused with HTTP ${response.status}: ${await response.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register refused with HTTP ')) throw err;
    }
    await delay(backoff(attempt));
  }
}

async function waitUntilDone(envUrl: string): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${envUrl}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (response.ok) {
        const payload = (await response.json()) as { done?: unknown };
        if (payload.done === true) return;
      }
    } catch {
      // The env is silent or the poll timed out: not done yet, so poll again.
    }
    await delay(backoff(attempt));
  }
}

async function run(): Promise<void> {
  const envUrl = await envOrigin();
  const server = buildServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const bound = server.address();
  if (bound === null || typeof bound === 'string') {
    throw new Error('server did not bind a TCP port');
  }
  process.stdout.write(`[forge] up on ${bound.port}, env at ${envUrl}\n`);
  await announce(envUrl, bound.port);
  process.stdout.write('[forge] registered; waiting for done\n');
  await waitUntilDone(envUrl);
  server.close();
  process.stdout.write('[forge] done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[forge] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
