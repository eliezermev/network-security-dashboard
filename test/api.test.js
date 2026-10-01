/**
 * Prueba de extremo a extremo: levanta el servidor real y ejecuta un escaneo
 * de verdad contra el loopback.
 *
 * Solo usa direcciones de loopback para no tocar ninguna otra red.
 * Requiere nmap disponible: en Windows a través de WSL, en Linux directamente.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');

const PORT = process.env.TEST_PORT || '3999';
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT = path.join(__dirname, '..');

let server = null;

function getJson(url, timeoutMs = 180000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(url, { signal: controller.signal })
        .then(async (res) => {
            const body = await res.json();
            return { status: res.status, body };
        })
        .finally(() => clearTimeout(timer));
}

function postJson(url, payload, timeoutMs = 180000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
    })
        .then(async (res) => ({ status: res.status, body: await res.json() }))
        .finally(() => clearTimeout(timer));
}

before(async () => {
    server = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: { ...process.env, PORT, HOST: '127.0.0.1' },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    server.stderr.on('data', (d) => {
        const text = String(d);
        if (!text.includes('ExperimentalWarning')) process.stderr.write(`[server] ${text}`);
    });

    // Espera a que responda el health check
    const deadline = Date.now() + 20000;
    for (;;) {
        try {
            const res = await getJson(`${BASE}/api/health`, 2000);
            if (res.status === 200) return;
        } catch { /* aún no está listo */ }
        if (Date.now() > deadline) throw new Error('El servidor no arrancó en 20s');
        await new Promise((r) => setTimeout(r, 300));
    }
});

after(() => {
    if (server) server.kill();
});

test('GET /api/health responde con la configuración activa', async () => {
    const { status, body } = await getJson(`${BASE}/api/health`, 10000);
    assert.strictEqual(status, 200);
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.status, 'ok');
    assert.ok(body.node.startsWith('v'));
    assert.ok(['WSL', 'system'].some((m) => body.nmap.mode.startsWith(m)));
});

test('GET /api/network/cidr devuelve al menos una red', async () => {
    const { status, body } = await getJson(`${BASE}/api/network/cidr`);
    assert.strictEqual(status, 200);
    assert.strictEqual(body.success, true);
    assert.ok(Array.isArray(body.networks));
    assert.ok(body.networks.length > 0, 'debe detectar al menos una red local');
    assert.match(body.networks[0].cidr, /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/);
});

test('GET /api/scan/discovery encuentra el loopback', async () => {
    const { status, body } = await getJson(`${BASE}/api/scan/discovery?network=127.0.0.0/24`);
    assert.strictEqual(status, 200);
    assert.strictEqual(body.success, true);
    assert.match(body.output, /Nmap scan report for 127\.0\.0\.1/);
});

test('GET /api/scan/ports responde con la salida de nmap', async () => {
    const { status, body } = await getJson(`${BASE}/api/scan/ports?target=127.0.0.1&os=false`);
    assert.strictEqual(status, 200);
    assert.strictEqual(body.success, true);
    assert.ok(body.output.length > 0);
    assert.match(body.output, /PORT\s+STATE\s+SERVICE/);
});

test('los scripts NSE se ejecutan sin errores', async () => {
    const { status, body } = await getJson(
        `${BASE}/api/scan/vulns?target=127.0.0.1&ports=1`, 180000);
    assert.strictEqual(status, 200);
    assert.strictEqual(body.success, true);
    assert.ok(body.output.length > 0, 'debe devolver salida aunque no haya hallazgos');
});

test('rechaza targets mal formados', async () => {
    for (const target of [';whoami', '../../etc/passwd', '1.2.3.4.5', '']) {
        const { status } = await getJson(`${BASE}/api/scan/ports?target=${encodeURIComponent(target)}`, 20000);
        assert.strictEqual(status, 400, `debe rechazar: "${target}"`);
    }
});

test('rechaza inyección de comandos en /api/scan/custom', async () => {
    const payloads = [
        { target: '127.0.0.1', args: '-oN /tmp/x' },
        { target: '127.0.0.1', args: '-sV && whoami' },
        { target: '127.0.0.1; rm -rf /', args: '-sV' },
        { target: '127.0.0.1', args: '--script-args evil' },
        { target: '127.0.0.1', args: '-p 99999' }
    ];
    for (const payload of payloads) {
        const { status } = await postJson(`${BASE}/api/scan/custom`, payload, 20000);
        assert.strictEqual(status, 400, `debe rechazar: ${JSON.stringify(payload)}`);
    }
});

test('rechaza rangos de red demasiado grandes', async () => {
    for (const network of ['192.0.0.0/8', '10.0.0.0/12', '8.8.8.8/4']) {
        const { status } = await getJson(`${BASE}/api/scan/discovery?network=${network}`, 20000);
        assert.strictEqual(status, 400, `debe rechazar: ${network}`);
    }
});

test('no sirve archivos internos del proyecto', async () => {
    for (const file of ['/server.js', '/package.json', '/doctor.js', '/lib/platform.js', '/.env']) {
        const res = await fetch(BASE + file);
        assert.strictEqual(res.status, 404, `debe ocultar: ${file}`);
    }
});

test('sirve el frontend', async () => {
    for (const [file, needle] of [['/index.html', '<title>'], ['/app.js', 'startScan'], ['/styles.css', 'container']]) {
        const res = await fetch(BASE + file);
        assert.strictEqual(res.status, 200, `debe servir: ${file}`);
        const text = await res.text();
        assert.ok(text.includes(needle), `${file} debería contener "${needle}"`);
    }
});