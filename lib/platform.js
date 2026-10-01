/**
 * platform.js - Detección de plataforma y ejecución de nmap.
 *
 * En Windows, nmap corre dentro de una distro de WSL (normalmente Kali).
 * En Linux y macOS, y dentro de Docker, se usa el nmap del sistema.
 */

const { execFile } = require('child_process');
const os = require('os');

const IS_WINDOWS = process.platform === 'win32';
const WSL_DISTRO = process.env.WSL_DISTRO || 'kali-linux';

// Timeout del proceso. Debe ser MAYOR que el --host-timeout que se le pasa a
// nmap, o el proceso se mata antes de que nmap termine solo.
const NMAP_TIMEOUT = parseInt(process.env.NMAP_TIMEOUT || '360000', 10);

const VULN_SCRIPTS = process.env.VULN_SCRIPTS || 'vuln and not dos';
const PORT_HOST_TIMEOUT = process.env.PORT_HOST_TIMEOUT || '240s';
const VULN_HOST_TIMEOUT = process.env.VULN_HOST_TIMEOUT || '240s';
const NO_OS_HOST_TIMEOUT = process.env.NO_OS_HOST_TIMEOUT || '150s';

// ¿Usar WSL? En Windows sí por defecto; se puede desactivar con USE_WSL=0
// si el usuario instaló nmap de forma nativa en Windows.
const USE_WSL = IS_WINDOWS && process.env.USE_WSL !== '0';
const NMAP_BIN = process.env.NMAP_BIN || 'nmap';

/* ---------------------------------------------------------------------------
 * Ejecución de nmap
 * ------------------------------------------------------------------------ */

/** Construye el comando sin pasar por un shell. */
function nmapCommand(args) {
    if (USE_WSL) {
        return { file: 'wsl.exe', args: ['-d', WSL_DISTRO, '--', NMAP_BIN, ...args] };
    }
    return { file: NMAP_BIN, args };
}

/** Convierte errores poco descriptivos en mensajes accionables. */
function friendlyError(error, stderr) {
    const text = String(stderr || '');
    if (error.code === 'ENOENT') {
        return USE_WSL
            ? 'No se encontró wsl.exe. Instala WSL: https://learn.microsoft.com/windows/wsl/install'
            : `No se encontró "${NMAP_BIN}". Instálalo o define NMAP_BIN con la ruta completa.`;
    }
    if (USE_WSL && /not a recognized|distribution.*not found|no distributions/i.test(text)) {
        return `La distro de WSL "${WSL_DISTRO}" no existe o no está inicializada. ` +
            `Ejecuta "wsl -l -v" para ver las instaladas, o define WSL_DISTRO.`;
    }
    if (/command not found|nmap: not found|No such file or directory/i.test(text) && /nmap/.test(text)) {
        return 'nmap no está instalado en ' + (USE_WSL ? WSL_DISTRO : 'este sistema') +
            '. En WSL/Kali: sudo apt update && sudo apt install nmap';
    }
    if (error.killed && error.signal) {
        return `El escaneo se canceló al superar NMAP_TIMEOUT (${NMAP_TIMEOUT} ms). ` +
            'Súbelo con la variable de entorno NMAP_TIMEOUT.';
    }
    return text.trim() || error.message;
}

/**
 * Ejecuta nmap y devuelve su salida estándar.
 * Nunca usa shell: los argumentos van en un array, sin concatenación de
 * entrada del usuario en una línea de comandos.
 */
function runNmap(args, timeout = NMAP_TIMEOUT) {
    return new Promise((resolve, reject) => {
        const { file, args: argv } = nmapCommand([...args, '-oN', '-']);
        execFile(
            file,
            argv,
            { timeout, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
            (error, stdout, stderr) => {
                const out = stdout || '';
                if (error && !out) {
                    reject(new Error(friendlyError(error, stderr)));
                    return;
                }
                resolve(out);
            }
        );
    });
}

/** Devuelve la versión de nmap, o null si no está disponible. */
function nmapVersion(timeout = 20000) {
    return new Promise((resolve) => {
        const { file, args } = nmapCommand(['--version']);
        execFile(file, args, { timeout, windowsHide: true }, (error, stdout) => {
            const first = String(stdout || '').split(/\r?\n/).find((l) => /version/i.test(l));
            resolve(error ? null : (first ? first.trim() : null));
        });
    });
}

/* ---------------------------------------------------------------------------
 * Detección de la red local
 * ------------------------------------------------------------------------ */

function isValidIp(str) {
    return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(str) &&
        str.split('.').every((o) => Number(o) <= 255);
}

function isValidCidr(str) {
    if (typeof str !== 'string') return false;
    const parts = str.split('/');
    if (parts.length !== 2 || !isValidIp(parts[0])) return false;
    const prefix = Number(parts[1]);
    // Mínimo /16: un /8 son 16 millones de hosts y el escaneo no terminaría.
    return Number.isInteger(prefix) && prefix >= 16 && prefix <= 32;
}

/** Convierte "255.255.255.0" en 24. */
function maskToPrefix(mask) {
    if (typeof mask !== 'string') return null;
    const parts = mask.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return null;
    let bits = 0;
    for (const byte of parts) {
        for (let i = 7; i >= 0; i--) {
            if (byte & (1 << i)) bits++;
        }
    }
    return bits;
}

/** Calcula la dirección de red de una IP con un prefijo dado. */
function networkAddress(ip, prefix) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ip.split('.').map((o, i) => Number(o) & ((mask >>> (24 - i * 8)) & 255)).join('.');
}

function exec(cmd, args, timeout = 20000) {
    return new Promise((resolve) => {
        execFile(cmd, args, { timeout, windowsHide: true }, (error, stdout) => {
            resolve(error ? '' : String(stdout || ''));
        });
    });
}

/** Windows: la IP de la interfaz con gateway por defecto. */
async function detectWindows() {
    const ps = 'Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | ' +
        'ForEach-Object { "$($_.InterfaceAlias)|$($_.IPv4Address.IPAddress)/$($_.IPv4Address.PrefixLength)" }';
    const stdout = await exec('powershell.exe', ['-NoProfile', '-Command', ps]);
    const found = [];
    for (const line of stdout.split(/\r?\n/).filter((l) => l.trim())) {
        const [iface, cidr] = line.split('|');
        if (!cidr || !isValidCidr(cidr.trim())) continue;
        const [ip, prefix] = cidr.trim().split('/');
        found.push({ interface: iface.trim(), cidr: `${networkAddress(ip, Number(prefix))}/${prefix}` });
    }
    return found;
}

/** Linux: direcciones IPv4 globales con su prefijo. */
async function detectLinux() {
    const stdout = await exec('ip', ['-4', '-o', 'addr', 'show', 'scope', 'global']);
    const found = [];
    for (const line of stdout.split(/\r?\n/)) {
        const match = /\s(\S+)\s+inet\s+([\d.]+)\/(\d+)/.exec(line);
        if (!match) continue;
        const [, iface, ip, prefix] = match;
        found.push({ interface: iface, cidr: `${networkAddress(ip, Number(prefix))}/${prefix}` });
    }
    return found;
}

/** macOS: ifconfig no expone el prefijo, se deriva de la máscara. */
async function detectMac() {
    const stdout = await exec('ifconfig', []);
    const found = [];
    let iface = null;
    for (const line of stdout.split(/\r?\n/)) {
        const header = /^([a-z0-9]+):\s/.exec(line);
        if (header) iface = header[1];
        const match = /inet\s+([\d.]+)\s+netmask\s+([\d.]+)/.exec(line);
        if (!match || !iface || iface.startsWith('lo')) continue;
        const prefix = maskToPrefix(match[2]);
        if (prefix === null) continue;
        found.push({ interface: iface, cidr: `${networkAddress(match[1], prefix)}/${prefix}` });
    }
    return found;
}

/** Último recurso: usa la info de Node, que sí trae la máscara. */
function detectFromNode() {
    const found = [];
    for (const [name, nets] of Object.entries(os.networkInterfaces())) {
        for (const net of nets || []) {
            if (net.family !== 'IPv4' || net.internal) continue;
            const prefix = maskToPrefix(net.netmask) ?? 24;
            found.push({ interface: name, cidr: `${networkAddress(net.address, prefix)}/${prefix}` });
        }
    }
    return found;
}

/**
 * Devuelve las redes locales candidatas a escanear.
 * El orden va de la más específica a la más general.
 */
async function detectLocalCidr() {
    let networks = [];
    if (IS_WINDOWS) networks = await detectWindows();
    else if (process.platform === 'darwin') networks = await detectMac();
    else networks = await detectLinux();

    if (networks.length === 0) networks = detectFromNode();

    // Descarta duplicados conservando el orden
    const seen = new Set();
    return networks.filter((n) => {
        if (!n.cidr || seen.has(n.cidr)) return false;
        seen.add(n.cidr);
        return true;
    });
}

module.exports = {
    IS_WINDOWS,
    USE_WSL,
    WSL_DISTRO,
    NMAP_TIMEOUT,
    NMAP_BIN,
    VULN_SCRIPTS,
    PORT_HOST_TIMEOUT,
    VULN_HOST_TIMEOUT,
    NO_OS_HOST_TIMEOUT,
    runNmap,
    nmapVersion,
    nmapCommand,
    detectLocalCidr,
    isValidCidr,
    networkAddress
};