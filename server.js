const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const WSL_DISTRO = process.env.WSL_DISTRO || 'kali-linux';
const NMAP_TIMEOUT = parseInt(process.env.NMAP_TIMEOUT || '300000', 10);

app.use(cors());
app.use(express.json());

// Solo se sirven estos archivos (no todo el directorio)
app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/index.html', (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/app.js', (req, res) => res.sendFile(__dirname + '/app.js'));
app.get('/styles.css', (req, res) => res.sendFile(__dirname + '/styles.css'));

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

function isValidCidr(str) {
    const parts = str.split('/');
    if (parts.length !== 2) return false;
    if (!isValidIp(parts[0])) return false;
    const prefix = Number(parts[1]);
    return Number.isInteger(prefix) && prefix >= 16 && prefix <= 32;
}

// Objetivo aceptado: IP, IP/prefix, hostname o rango con guion (a-b)
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i;

function isValidTarget(str) {
    if (typeof str !== 'string' || str.length === 0 || str.length > 255) return false;
    const value = str.trim();
    if (isValidIp(value) || isValidCidr(value)) return true;
    // Rango 192.168.0.1-192.168.0.50
    if (/^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
        const [from, to] = value.split('-');
        return isValidIp(from) && isValidIp(to);
    }
    return HOSTNAME_RE.test(value);
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

function sanitizeArgs(input) {
    if (typeof input !== 'string') return null;
    // Sin comillas, redirecciones ni metacarácteres de shell
    if (/["'`<>;&|$\\\n\r*?!]/.test(input)) return null;
    const tokens = input.trim().split(/\s+/);
    for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        if (!ALLOWED_ARGS.has(token)) return null;
        // Un flag con valor: el valor va en el siguiente token
        if (token === '-p' || token === '--script' || token === '--top-ports' ||
            token === '--script-timeout' || token === '--min-rate' ||
            token === '--max-retries' || token === '--host-timeout') {
            const value = tokens[++i];
            if (!value) return null;
            if (token === '-p' && !isValidPorts(value)) return null;
            if (token === '--script' && !/^[a-z0-9,._-]+$/i.test(value)) return null;
            if (['--top-ports', '--min-rate', '--max-retries'].includes(token) &&
                !/^\d+$/.test(value)) return null;
            if (token === '--script-timeout' && !/^\d+[smh]?$/.test(value)) return null;
            if (token === '--host-timeout' && !/^\d+[smh]?$/.test(value)) return null;
        }
    }
    return tokens;
}

/* ---------------------------------------------------------------------------
 * Ejecución de nmap
 * ------------------------------------------------------------------------ */

function runNmap(args, timeout = NMAP_TIMEOUT) {
    return new Promise((resolve, reject) => {
        // execFile con array de argumentos: no hay shell, no hay inyección
        const child = execFile(
            'wsl.exe',
            ['-d', WSL_DISTRO, '--', 'nmap', ...args, '-oN', '-'],
            { timeout, maxBuffer: 16 * 1024 * 1024 },
            (error, stdout, stderr) => {
                if (error && !stdout) {
                    reject(new Error(stderr || error.message));
                    return;
                }
                resolve(stdout || '');
            }
        );
        child.on('error', reject);
    });
}

// Detecta la red local desde Windows (WSL está detrás de NAT, su IP no sirve)
function detectLocalCidr() {
    return new Promise((resolve) => {
        const ps = 'Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | ' +
            'ForEach-Object { "$($_.InterfaceAlias)|$($_.IPv4Address.IPAddress)/$($_.IPv4Address.PrefixLength)" }';
        execFile('powershell.exe', ['-NoProfile', '-Command', ps], { timeout: 20000 }, (err, stdout) => {
            const lines = (stdout || '').split(/\r?\n/).filter((l) => l.trim());
            const found = [];
            for (const line of lines) {
                const [iface, cidr] = line.split('|');
                if (!cidr || !isValidCidr(cidr.trim())) continue;
                const [ip, prefix] = cidr.trim().split('/');
                const octets = ip.split('.').map(Number);
                const mask = prefix === 0 ? 0 : (0xffffffff << (32 - Number(prefix))) >>> 0;
                const network = octets
                    .map((o, i) => o & ((mask >>> (24 - i * 8)) & 255))
                    .join('.');
                found.push({ interface: iface.trim(), cidr: `${network}/${prefix}` });
            }
            if (found.length > 0) {
                resolve(found);
                return;
            }
            // Fallback: subred /24 de la IP local de Windows
            const addrs = [];
            const ifaces = os.networkInterfaces();
            for (const name of Object.keys(ifaces)) {
                for (const net of ifaces[name] || []) {
                    if (net.family === 'IPv4' && !net.internal) addrs.push(net.address);
                }
            }
            if (addrs.length > 0) {
                resolve([{ interface: 'local', cidr: `${addrs[0].split('.').slice(0, 3).join('.')}.0/24` }]);
                return;
            }
            resolve([]);
        });
    });
}

/* ---------------------------------------------------------------------------
 * Endpoints
 * ------------------------------------------------------------------------ */

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
            return res.status(400).json({ success: false, error: 'Red no válida (use IP/prefijo, ej. 192.168.0.0/24)' });
        }
        const args = network ? ['-sn', '-n', network] : ['-sn', '-n'];
        if (!network) {
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
        const hostTimeout = wantOs ? '240s' : '150s';
        const args = ['-sV', '-sC', '--host-timeout', hostTimeout, target];
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
const VULN_SCRIPTS = process.env.VULN_SCRIPTS || 'vuln and not dos';

const output = await runNmap([
            '--script', VULN_SCRIPTS,
            '--script-timeout', '20s',
            '--host-timeout', '300s',
            '-p', ports,
            target
        ]);
        res.json({ success: true, output });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: escaneo completo
app.get('/api/scan/full', async (req, res) => {
    try {
        const target = String(req.query.target || '').trim();
        if (!isValidTarget(target)) {
            return res.status(400).json({ success: false, error: 'Target inválido' });
        }
        const output = await runNmap([
            '-sV', '-p-', '--script', 'vuln and not dos,banner,http-enum',
            '--script-timeout', '20s', '--host-timeout', '600s',
            target
        ], 660000);
        res.json({ success: true, output });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API: escaneo personalizado (flags restrictedos a una lista blanca)
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

app.listen(PORT, () => {
    console.log(`API-NMAP Server corriendo en http://localhost:${PORT}`);
    console.log(`WSL distro: ${WSL_DISTRO}`);
});