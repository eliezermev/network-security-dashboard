const express = require('express');
const cors = require('cors');
const path = require('path');

const {
    IS_WINDOWS,
    USE_WSL,
    WSL_DISTRO,
    NMAP_TIMEOUT,
    VULN_SCRIPTS,
    PORT_HOST_TIMEOUT,
    VULN_HOST_TIMEOUT,
    NO_OS_HOST_TIMEOUT,
    runNmap,
    detectLocalCidr,
    isValidCidr
} = require('./lib/platform');

const app = express();

// Escucha solo en loopback por defecto: sin autenticación, exponer el puerto
// a la LAN permitiría que cualquiera escanee la red. Usa HOST=0.0.0.0 si
// realmente necesitas acceder desde otro dispositivo.
const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3000', 10);

const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

app.disable('x-powered-by');
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: '64kb' }));

// Solo se sirven estos archivos (no todo el directorio)
const STATIC_FILES = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/app.js': 'app.js',
    '/styles.css': 'styles.css'
};
for (const [route, file] of Object.entries(STATIC_FILES)) {
    app.get(route, (req, res) => res.sendFile(path.join(__dirname, file)));
}

/* ---------------------------------------------------------------------------
 * Validación (evita inyección de comandos: nunca se concatena entrada de
 * usuario en la cadena de shell, se pasa como argumento de execFile)
 * ------------------------------------------------------------------------ */

const IP_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isValidIp(str) {
    const m = IP_RE.exec(str);
    if (!m) return false;
    return m.slice(1).every((o) => Number(o) <= 255);
}

// Objetivo aceptado: IP, IP/prefijo, hostname o rango con guion (a-b)
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i;

function isValidTarget(str) {
    if (typeof str !== 'string' || str.length === 0 || str.length > 255) return false;
    const value = str.trim();
    if (isValidIp(value) || isValidCidr(value)) return true;
    // Rango 192.0.2.1-192.0.2.50
    if (/^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
        const [from, to] = value.split('-');
        return isValidIp(from) && isValidIp(to);
    }
    if (!HOSTNAME_RE.test(value)) return false;
    // La última etiqueta de un hostname no puede ser solo numérica: "1.2.3.4.5"
    // no es un nombre válido y nmap solo devolvería un error de resolución.
    const labels = value.split('.');
    return !/^\d+$/.test(labels[labels.length - 1]);
}

function isValidPorts(str) {
    if (typeof str !== 'string' || str.length === 0 || str.length > 200) return false;
    const pattern = /^(\d{1,5}(-\d{1,5})?)(,(?:\d{1,5}(-\d{1,5})?)?)*$/;
    if (!pattern.test(str)) return false;
    return str.split(',').every((chunk) => {
        const [a, b] = chunk.split('-').map(Number);
        if (a < 1 || a > 65535) return false;
        if (b === undefined) return true;
        return b >= a && b <= 65535;
    });
}

// Lista blanca de flags para el endpoint custom (previene -oN, ;, &&, etc.)
const ALLOWED_ARGS = new Set([
    '-sV', '-sC', '-O', '-sn', '-Pn', '-A',
    '-p', '--top-ports', '--script', '--script-timeout', '-T4', '-T5',
    '--min-rate', '--max-retries', '--host-timeout', '-n'
]);

const FLAGS_WITH_VALUE = new Set([
    '-p', '--script', '--top-ports', '--script-timeout', '--min-rate',
    '--max-retries', '--host-timeout'
]);

function sanitizeArgs(input) {
    if (typeof input !== 'string') return null;
    // Sin comillas, redirecciones ni metacarácteres de shell
    if (/["'`<>;&|$\\\n\r*?!]/.test(input)) return null;
    const tokens = input.trim().split(/\s+/);
    if (tokens.length === 0 || tokens.length > 20) return null;
    for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        if (!ALLOWED_ARGS.has(token)) return null;
        if (FLAGS_WITH_VALUE.has(token)) {
            const value = tokens[++i];
            if (!value) return null;
            if (token === '-p' && !isValidPorts(value)) return null;
            if (token === '--script' && !/^[a-z0-9,._\s-]+$/i.test(value)) return null;
            if (['--top-ports', '--min-rate', '--max-retries'].includes(token) &&
                !/^\d+$/.test(value)) return null;
            if (['--script-timeout', '--host-timeout'].includes(token) &&
                !/^\d+[smh]?$/.test(value)) return null;
        }
    }
    return tokens;
}

/* ---------------------------------------------------------------------------
 * Endpoints
 * ------------------------------------------------------------------------ */

// API: estado del servicio, útil para verificar la instalación
app.get('/api/health', async (req, res) => {
    res.json({
        success: true,
        status: 'ok',
        node: process.version,
        platform: process.platform,
        nmap: {
            mode: USE_WSL ? `WSL (${WSL_DISTRO})` : 'system',
            timeoutMs: NMAP_TIMEOUT,
            vulnScripts: VULN_SCRIPTS
        },
        server: { host: HOST, port: PORT }
    });
});

// API: redes locales detectadas
app.get('/api/network/cidr', async (req, res) => {
    try {
        const networks = await detectLocalCidr();
        res.json({ success: true, networks });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: descubrimiento de hosts
app.get('/api/scan/discovery', async (req, res) => {
    try {
        const network = String(req.query.network || '').trim();
        if (network && !isValidCidr(network)) {
            return res.status(400).json({ success: false, error: 'Red no válida (use IP/prefijo, ej. 192.0.2.0/24)' });
        }
        const args = ['-sn', '-n'];
        if (network) {
            args.push(network);
        } else {
            // Sin red indicada se usa la primera detectada
            const networks = await detectLocalCidr();
            if (networks.length > 0) args.push(networks[0].cidr);
        }
        const output = await runNmap(args);
        res.json({ success: true, output, network: network || null });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: escaneo de puertos, servicios y sistema operativo
app.get('/api/scan/ports', async (req, res) => {
    try {
        const target = String(req.query.target || '').trim();
        if (!isValidTarget(target)) {
            return res.status(400).json({ success: false, error: 'Target inválido' });
        }
        // La detección de SO (-O) es lenta: puede duplicar el tiempo de escaneo.
        // Se puede desactivar con ?os=false si el dispositivo responde lento.
        const wantOs = req.query.os !== 'false';
        const args = ['-sV', '-sC', '--host-timeout',
            wantOs ? PORT_HOST_TIMEOUT : NO_OS_HOST_TIMEOUT, target];
        if (wantOs) args.splice(2, 0, '-O');
        if (isValidCidr(target)) args.splice(1, 0, '-Pn');
        const output = await runNmap(args);
        res.json({ success: true, output });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: detección de vulnerabilidades en puertos concretos
app.get('/api/scan/vulns', async (req, res) => {
    try {
        const target = String(req.query.target || '').trim();
        const ports = String(req.query.ports || '').trim();
        if (!isValidTarget(target)) {
            return res.status(400).json({ success: false, error: 'Target inválido' });
        }
        if (!isValidPorts(ports)) {
            return res.status(400).json({ success: false, error: 'Lista de puertos inválida' });
        }
        // "not dos" evita payloads de denegación de servicio contra tus propios
        // dispositivos y reduce los errores de socket en WSL.
        const output = await runNmap([
            '--script', VULN_SCRIPTS,
            '--script-timeout', '20s',
            '--host-timeout', VULN_HOST_TIMEOUT,
            '-p', ports,
            target
        ]);
        res.json({ success: true, output });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: escaneo completo (todos los puertos). Lento: puede tardar varios minutos.
app.get('/api/scan/full', async (req, res) => {
    try {
        const target = String(req.query.target || '').trim();
        if (!isValidTarget(target)) {
            return res.status(400).json({ success: false, error: 'Target inválido' });
        }
        const output = await runNmap([
            '-sV', '-p-', '--script', `${VULN_SCRIPTS},banner,http-enum`,
            '--script-timeout', '20s', '--host-timeout', '600s',
            target
        ], 660000);
        res.json({ success: true, output });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: escaneo personalizado (flags restringidos a una lista blanca)
app.post('/api/scan/custom', async (req, res) => {
    try {
        const target = String(req.body.target || '').trim();
        const rawArgs = req.body.args;
        if (!isValidTarget(target)) {
            return res.status(400).json({ success: false, error: 'Target inválido' });
        }
        const args = sanitizeArgs(rawArgs);
        if (!args) {
            return res.status(400).json({ success: false, error: 'Argumentos no permitidos' });
        }
        const output = await runNmap([...args, target]);
        res.json({ success: true, output });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.listen(PORT, HOST, () => {
    console.log('');
    console.log('  API-NMAP · Network Security Dashboard');
    console.log(`  Servidor:  http://localhost:${PORT}`);
    console.log(`  Escuchando en: ${HOST}:${PORT}`);
    console.log(`  nmap:      ${USE_WSL ? `WSL (${WSL_DISTRO})` : 'instalado en el sistema'}`);
    console.log(`  Timeout:   ${NMAP_TIMEOUT} ms`);
    if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
        console.log('');
        console.log(`  AVISO: el servidor está accesible desde la red y no tiene`);
        console.log(`  autenticación. Cualquiera en la red puede escanear tus equipos.`);
    }
    console.log('');
});