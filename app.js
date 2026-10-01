// Network Security Dashboard - JavaScript
// Todos los datos provienen de escaneos reales de nmap vía la API local.

/* ---------------------------------------------------------------------------
 * Estado
 * ------------------------------------------------------------------------ */

const state = {
    network: null,   // CIDR detectado
    devices: [],     // dispositivos encontrados
    isScanning: false,
    startedAt: null
};

const els = {};

/* ---------------------------------------------------------------------------
 * Utilidades
 * ------------------------------------------------------------------------ */

function esc(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
}

function el(id) {
    if (!els[id]) els[id] = document.getElementById(id);
    return els[id];
}

function logToTerminal(text, cls) {
    const term = el('terminalOutput');
    const line = document.createElement('div');
    line.className = cls || 'result';
    line.textContent = text;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

function setProgress(percent) {
    el('progressFill').style.width = percent + '%';
    el('progressPercent').textContent = Math.round(percent) + '%';
}

async function api(path, requireOutput = false) {
    const res = await fetch(path);
    const data = await res.json().catch(() => ({ success: false, error: 'Respuesta inválida' }));
    if (!data || !data.success) throw new Error((data && data.error) || 'Error desconocido');
    if (requireOutput && typeof data.output !== 'string') {
        throw new Error('El servidor no devolvió la salida de nmap');
    }
    return data;
}

/* ---------------------------------------------------------------------------
 * Parseo de la salida de nmap
 * ------------------------------------------------------------------------ */

// -sn -> lista de hosts
function parseDiscovery(output) {
    const hosts = [];
    output = typeof output === 'string' ? output : '';
    const lines = output.split(/\r?\n/);
    let current = null;

    for (const raw of lines) {
        const line = raw.trim();
        const report = /^Nmap scan report for (.+)$/.exec(line);
        if (report) {
            let value = report[1];
            let ip = null;
            const inParens = /\(([\d.]+)\)\s*$/.exec(value);
            if (inParens) {
                ip = inParens[1];
                value = value.slice(0, inParens.index).trim();
            } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
                ip = value;
                value = '';
            }
            current = {
                ip,
                hostname: value || ip,
                mac: null,
                vendor: null
            };
            if (ip) hosts.push(current);
            continue;
        }
        if (!current) continue;
        const mac = /^MAC Address:\s*([0-9A-Fa-f:]+)\s*\((.*)\)\s*$/.exec(line);
        if (mac) {
            current.mac = mac[1];
            current.vendor = mac[2];
            if (!current.hostname) current.hostname = mac[2];
        }
    }
    return hosts.filter((h) => h.ip);
}

// -sV -sC -O -> puertos + sistema operativo
function parseHostScan(output) {
    const result = { ports: [], os: [], osDetails: null, hostnames: [], hostname: null };
    output = typeof output === 'string' ? output : '';
    const lines = output.split(/\r?\n/);
    let current = null;
    let inPortTable = false;

    for (const raw of lines) {
        const line = raw.trimEnd();

        const report = /^Nmap scan report for (.+)$/.exec(line.trim());
        if (report) {
            const value = report[1];
            const inParens = /\(([\d.]+)\)\s*$/.exec(value);
            if (inParens) result.hostname = value.slice(0, inParens.index).trim() || inParens[1];
            inPortTable = false;
            continue;
        }

        if (/^PORT\s+STATE\s+SERVICE/.test(line.trim())) {
            inPortTable = true;
            continue;
        }

        // Fuera de la tabla de puertos: se termina el registro
        if (inPortTable && line.trim() === '') {
            if (current) current = null;
            continue;
        }

        if (/^OS details:/.test(line.trim())) {
            result.osDetails = line.trim().replace(/^OS details:\s*/, '');
            inPortTable = false;
            continue;
        }

        // "Service Info: OS: Linux; Device: broadband router; CPE: cpe:/o:linux..."
        const serviceInfo = /^Service Info:\s*(.*)$/.exec(line.trim());
        if (serviceInfo) {
            inPortTable = false;
            for (const part of serviceInfo[1].split(';')) {
                const value = part.trim();
                if (!value) continue;
                const kv = /^([^:]+):\s*(.*)$/.exec(value);
                if (kv && /^(OS|CPE|Device|Host|Server)$/i.test(kv[1].trim())) {
                    result.os.push(`${kv[1].trim()}: ${kv[2].trim()}`);
                } else {
                    result.os.push(value);
                }
            }
            continue;
        }

        if (/^No exact OS matches/i.test(line.trim())) {
            result.osDetails = 'No identificado con certeza (Linux probable)';
            inPortTable = false;
            continue;
        }

        // Fingerprint de -O: ruido, se descarta
        if (/^(OS:|TCP\/IP fingerprint:|Uptime:|Network Distance:)/i.test(line.trim())) {
            inPortTable = false;
            continue;
        }

        // Hostnames reportados por -O
        const osMatch = /^\|?\s*(?:OS|CPE)\s*:\s*(.+)$/.exec(line.trim());
        if (osMatch && !inPortTable) {
            result.os.push(osMatch[1].trim());
            continue;
        }

        const rdns = /^RDNS record:?\s*(.*)$/.exec(line.trim());
        if (rdns && !inPortTable) {
            const name = (rdns[1] || '').trim();
            if (name) result.hostnames.push(name);
            continue;
        }

        if (inPortTable) {
            const port = /^(\d+)\/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)\s*(.*)$/.exec(line.trim());
            if (port) {
                current = {
                    port: Number(port[1]),
                    proto: port[2],
                    state: port[3],
                    service: port[4],
                    version: port[5].trim() || null,
                    vulns: []
                };
                result.ports.push(current);
                continue;
            }
            // Líneas de script ("| ...") y notas siguen dentro del puerto actual
            if (current) {
                const note = line.trim().replace(/^[|_]\s*/, '').trim();
                if (!note) continue;
                if (/^(Note|Warning):/i.test(note)) continue;
                // Ruido del fingerprint de nmap, no es información del servicio
                if (/^(SF|NSEC?|Nmap)\b/.test(note)) continue;
                if (/despite returning data|submit the following fingerprint|cgi-bin\/submit/i.test(note)) continue;
                if (/VULNERABILITY RESULT|VULNERABLE|^\s*VULN RESULTS/.test(note) || /^CVE-/.test(note)) {
                    current.vulns.push({ raw: note });
                } else if (!/ERROR:|Script execution failed/i.test(note)) {
                    current.scriptNotes = current.scriptNotes || [];
                    current.scriptNotes.push(note);
                }
            }
            continue;
        }
    }
    return result;
}

// --script vuln -> vulnerabilidades por puerto
// Cubre los tres formatos que emite nmap:
//   1) "|   VULNERABILITY RESULT:" + líneas "|     ..." del bloque vulnresults
//   2) "| http-vuln-cve2014-3704: VULNERABLE: ..." (resultado por script)
//   3) "|     CVE-XXXX-YYYY:" + "|       VULNERABLE:"
function parseVulns(output) {
    const byPort = {};
    output = typeof output === 'string' ? output : '';
    const lines = output.split(/\r?\n/);
    const CVE_RE = /\b(CVE-\d{4}-\d{4,})\b/i;
    const META_RE = /^(Reference|VULN RESULTS|CISA|Confidence|Exploit|Link|Service Info|Hint|Note|Warning)\b/i;
    let currentPort = null;
    let pending = null;
    let pendingCve = null; // CVE announced en una línea y confirmada en la siguiente
    let pendingDetail = null; // entrada a la que anexar la línea descriptiva

    function add(port, entry) {
        byPort[port] = byPort[port] || [];
        const key = `${entry.cve || ''}|${entry.text}`;
        // Evita duplicados cuando el mismo CVE aparece en varias líneas
        if (byPort[port].some((v) => v.key === key)) return null;
        entry.key = key;
        byPort[port].push(entry);
        return entry;
    }

    function flush() {
        if (!pending || currentPort === null) {
            pending = null;
            return;
        }
        const cve = (CVE_RE.exec(pending.block.join(' ')) || [])[1];
        const text = pending.desc;
        if (text || cve) {
            add(currentPort, {
                kind: cve ? 'cve' : 'result',
                cve: cve ? cve.toUpperCase() : null,
                script: 'vulnresults',
                text: text || `VULNERABILITY RESULT (${cve})`
            });
        }
        pending = null;
    }

    for (const raw of lines) {
        const line = raw.trim();

        const port = /^(\d+)\/(tcp|udp)\s+(open|filtered)\s+(\S+)/.exec(line);
        if (port) {
            flush();
            pendingCve = null;
            pendingDetail = null;
            currentPort = Number(port[1]);
            byPort[currentPort] = byPort[currentPort] || [];
            continue;
        }
        if (currentPort === null) continue;

        if (/VULNERABILITY RESULT/i.test(line)) {
            flush();
            pending = { block: [], desc: null };
            continue;
        }

        // Contenido del bloque "vulnresults:" (todas empiezan con "|")
        if (pending && /^(\||\|_)/.test(raw.trim())) {
            const content = line.replace(/^[|_\s]+/, '');
            pending.block.push(content);
            // La descripción es la primera línea que no sea metadato
            if (!pending.desc && content && !META_RE.test(content)) {
                pending.desc = content;
            }
            continue;
        }
        flush();

        const cleaned = line.replace(/^[|_\s]+/, '');

        // Línea descriptiva que sigue a un CVE confirmado
        if (pendingDetail) {
            if (cleaned && !/^[|_\s]*$/.test(line) && !META_RE.test(cleaned)) {
                pendingDetail.text = `${pendingDetail.text} — ${cleaned}`;
                pendingDetail.key = `${pendingDetail.cve || ''}|${pendingDetail.text}`;
            }
            pendingDetail = null;
            continue;
        }

        // Formato en dos líneas: "|     CVE-2013-7091:" + "|       VULNERABLE:"
        if (pendingCve) {
            if (/\bVULNERABLE\b/i.test(cleaned)) {
                const entry = add(currentPort, {
                    kind: 'cve',
                    cve: pendingCve,
                    script: null,
                    text: `${pendingCve}: VULNERABLE`
                });
                // La línea siguiente suele contener la descripción
                pendingDetail = entry || null;
            }
            pendingCve = null;
            continue;
        }
        const announced = /^([A-Z0-9][A-Z0-9_.\-]*):\s*$/.exec(cleaned);
        if (announced && CVE_RE.test(announced[1])) {
            pendingCve = announced[1].toUpperCase();
            continue;
        }

        // Formato por script: "http-vuln-cve2014-3704: VULNERABLE: ..."
        const scriptHit = /^([a-z0-9][a-z0-9_\-]*):\s*(.*)$/i.exec(cleaned);
        if (scriptHit && /\bVULNERABLE\b/i.test(scriptHit[2])) {
            const cve = (CVE_RE.exec(cleaned) || [])[1];
            add(currentPort, {
                kind: cve ? 'cve' : 'script',
                cve: cve ? cve.toUpperCase() : null,
                script: scriptHit[1],
                text: cleaned
            });
            continue;
        }

        // Formato "CVE-XXXX-YYYY: VULNERABLE"
        if (/\bVULNERABLE\b/i.test(cleaned) && CVE_RE.test(cleaned)) {
            add(currentPort, {
                kind: 'cve',
                cve: (CVE_RE.exec(cleaned)[1]).toUpperCase(),
                script: null,
                text: cleaned
            });
        }
    }
    flush();
    return byPort;
}

/* ---------------------------------------------------------------------------
 * Clasificación de riesgo
 * ------------------------------------------------------------------------ */

function scorePort(port) {
    let score = 0;
    const reasons = [];
    const svc = port.service.toLowerCase();

    if (port.version && /\d+\.\d+/.test(port.version)) {
        const ver = parseFloat((/\d+\.\d+/.exec(port.version) || [0, 9])[0]);
        if (ver < 3) { score += 15; reasons.push(`versión antigua (${port.version})`); }
    }
    if (svc === 'telnet' || svc === 'ftp' || svc === 'rsh' || svc === 'rlogin' || svc === 'tftp') {
        score += 35;
        reasons.push(`${svc} transmite credenciales en texto plano`);
    }
    if (['sunrpc', 'rsync', 'rsh', 'vnc', 'redis', 'mongodb', 'elasticsearch', 'influxdb'].includes(svc)) {
        score += 20;
        reasons.push(`${svc} expuesto`);
    }
    if (port.port === 3389) { score += 10; reasons.push('RDP expuesto'); }
    if (port.port === 23 || port.port === 2323) { score += 30; reasons.push('telnet exposed'); }
    if ((port.port === 80 || port.port === 8080) && !/https/i.test(svc)) {
        score += 5;
        reasons.push('administración sin cifrar');
    }
    if (port.vulns && port.vulns.length) {
        score += Math.min(40, port.vulns.length * 12);
        reasons.push(`${port.vulns.length} indicio(s) de vulnerabilidad`);
    }
    if (port.state === 'open|filtered' || port.state === 'filtered') score += 5;
    return { score, reasons };
}

function computeRisk(device) {
    if (!device.scanned) {
        return { risk: 'PENDIENTE', riskClass: 'risk-medium', score: 0, reasons: [] };
    }
    let score = 0;
    const reasons = [];
    for (const port of device.ports) {
        const r = scorePort(port);
        score += r.score;
        r.reasons.forEach((x) => reasons.push(`Puerto ${port.port}/${port.proto} (${port.service}): ${x}`));
    }
    const totalVulns = Object.values(device.vulns || {}).flat().length;
    if (totalVulns > 0) reasons.push(`${totalVulns} hallazgo(s) de --script vuln`);
    score = Math.min(100, score);

    let risk, riskClass;
    if (score >= 60) { risk = 'ALTO'; riskClass = 'risk-high'; }
    else if (score >= 25) { risk = 'MEDIO'; riskClass = 'risk-medium'; }
    else { risk = 'BAJO'; riskClass = 'risk-low'; }
    return { risk, riskClass, score, reasons, totalVulns };
}

/* ---------------------------------------------------------------------------
 * Iconos
 * ------------------------------------------------------------------------ */

function guessType(device) {
    const text = `${device.hostname || ''} ${(device.ports || []).map((p) => p.service).join(' ')}`.toLowerCase();
    if (/router|gateway|zte|tp-?link|huawei|arris|technicolor|modem|openwrt|dd-wrt/.test(text)) return 'router';
    if (/phone|android|iphone|mobile|galaxy|pixel/.test(text)) return 'phone';
    if (/printer|scanner/.test(text)) return 'printer';
    if (/tv|chromecast|roku|firetv|appletv/.test(text)) return 'tv';
    if (/camera|dvr|nvr|ipcam/.test(text)) return 'camera';
    if (/nas|disk|storage|synology|server/.test(text)) return 'server';
    return 'pc';
}

function getDeviceIcon(type) {
    const icons = {
        router: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="18" x2="6.01" y2="18"/><line x1="10" y1="18" x2="10.01" y2="18"/><line x1="14" y1="18" x2="14.01" y2="18"/></svg>',
        phone: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
        printer: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>',
        tv: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/></svg>',
        camera: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>',
        server: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
        pc: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>'
    };
    return icons[type] || icons.pc;
}

function setStatus(text, cls) {
    const s = el('scanStatus');
    s.textContent = text;
    s.className = 'scan-status' + (cls ? ' ' + cls : '');
}

/* ---------------------------------------------------------------------------
 * Paso 1: descubrimiento de red
 * ------------------------------------------------------------------------ */

async function startScan() {
    if (state.isScanning) return;
    state.isScanning = true;
    state.startedAt = new Date();

    const btnStart = el('btnStartScan');
    btnStart.disabled = true;
    btnStart.classList.add('scanning');
    btnStart.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Escaneando...';

    el('btnFinishScan').disabled = true;
    el('scanProgress').classList.add('active');
    el('devicesSection').classList.remove('active');
    el('detailsPanel').classList.remove('active');
    el('reportPanel').classList.remove('active');
    el('terminalOutput').innerHTML = '';
    el('devicesGrid').innerHTML = '';
    state.devices = [];
    state.network = null;
    setProgress(0);
    setStatus('Escaneando', 'scanning');
    el('scanDate').textContent = 'Escaneo en curso...';

    try {
        // 1) Detectar red local
        logToTerminal('· Detectando red local...', 'cmd');
        const cidrData = await api('/api/network/cidr');
        if (!cidrData.networks || cidrData.networks.length === 0) {
            throw new Error('No se pudo detectar la red local');
        }
        const network = cidrData.networks[0];
        state.network = network.cidr;
        logToTerminal(`✓ Red local: ${network.cidr} (${network.interface})`, 'result');
        setProgress(10);

        // 2) Descubrimiento de hosts
        const cmd = `nmap -sn -n ${network.cidr}`;
        logToTerminal(`$ ${cmd}`, 'cmd');
        logToTerminal('→ Buscando dispositivos activos...', 'result');

        const disc = await api(`/api/scan/discovery?network=${encodeURIComponent(network.cidr)}`, true);
        const hosts = parseDiscovery(disc.output);
        logToTerminal(`✓ ${hosts.length} dispositivo(s) encontrado(s)`, 'result');

        if (hosts.length === 0) {
            logToTerminal('! No se encontraron dispositivos en la red', 'warning');
        }

        state.devices = hosts.map((h, i) => ({
            id: `dev-${i}`,
            ip: h.ip,
            hostname: h.hostname || h.ip,
            mac: h.mac,
            vendor: h.vendor,
            ports: [],
            os: [],
            osDetails: null,
            hostnames: [],
            vulns: {},
            scanned: false,
            scanning: false,
            error: null,
            rawPorts: null,
            rawVulns: null
        }));
        setProgress(100);

        renderDevices();
        setStatus('Completado', 'completed');
        el('scanDate').textContent = 'Último escaneo: ' + new Date().toLocaleString();
        el('btnFinishScan').disabled = false;

        btnStart.classList.remove('scanning');
        btnStart.innerHTML = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Reiniciar Análisis';
    } catch (error) {
        logToTerminal(`✗ Error: ${error.message}`, 'error');
        setStatus('Error', '');
        el('btnStartScan').disabled = false;
    } finally {
        state.isScanning = false;
    }
}

/* ---------------------------------------------------------------------------
 * Render de dispositivos
 * ------------------------------------------------------------------------ */

function renderDevices() {
    const grid = el('devicesGrid');
    grid.innerHTML = '';

    if (state.devices.length === 0) {
        grid.innerHTML = '<p style="color: var(--color-text-muted)">No se encontraron dispositivos.</p>';
        el('devicesSection').classList.add('active');
        return;
    }

    state.devices.forEach((device) => {
        const risk = computeRisk(device);
        const card = document.createElement('div');
        card.className = 'device-card';
        card.id = `card-${device.id}`;

        const portTags = device.ports.length > 0
            ? device.ports.slice(0, 8).map((p) => {
                const r = scorePort(p);
                const cls = r.score >= 30 ? 'critical' : '';
                return `<span class="port-tag ${cls}">${p.port}/${p.proto} ${esc(p.service)}</span>`;
            }).join('') + (device.ports.length > 8 ? `<span class="port-tag">+${device.ports.length - 8}</span>` : '')
            : (device.scanned ? '<span class="port-tag closed">Sin puertos abiertos</span>' : '<span class="port-tag">Sin analizar</span>');

        card.innerHTML = `
            <div class="device-header">
                <div class="device-icon">${getDeviceIcon(guessType(device))}</div>
                <div class="device-info">
                    <h3 class="device-name">${esc(device.hostname)}</h3>
                    <span class="device-ip">${esc(device.ip)}</span>
                </div>
                <span class="risk-badge ${risk.riskClass}">${risk.risk}</span>
            </div>
            <div class="device-ports">${portTags}</div>
            <div class="device-actions">
                <button class="btn btn-primary" id="btn-${device.id}" onclick="analyzeDevice('${device.id}')" ${device.scanning ? 'disabled' : ''}>
                    ${device.scanning ? 'Analizando...' : (device.scanned ? 'Reanalizar' : 'Analizar')}
                </button>
            </div>
        `;
        grid.appendChild(card);
    });

    el('devicesSection').classList.add('active');
}

/* ---------------------------------------------------------------------------
 * Paso 2: análisis por dispositivo (puertos + vulnerabilidades)
 * ------------------------------------------------------------------------ */

async function analyzeDevice(deviceId) {
    const device = state.devices.find((d) => d.id === deviceId);
    if (!device || device.scanning) return;
    device.scanning = true;
    renderDevices();

    const panel = el('detailsPanel');
    const title = el('detailsTitle');
    const content = el('detailsContent');
    title.textContent = `Analizando: ${device.hostname} (${device.ip})`;
    content.innerHTML = `
        <div class="detail-section">
            <h4>Ejecutando nmap -sV -sC -O ${esc(device.ip)}</h4>
            <p style="color: var(--color-text-muted)">Detección de puertos, servicios y sistema operativo. Puede tardar un minuto...</p>
        </div>`;
    panel.classList.add('active');
    panel.scrollIntoView({ behavior: 'smooth' });

    try {
        // 3a) Puertos + servicios + OS
        const portsData = await api(`/api/scan/ports?target=${encodeURIComponent(device.ip)}`, true);
        const parsed = parseHostScan(portsData.output);
        device.rawPorts = portsData.output;
        device.ports = parsed.ports;
        device.os = parsed.os;
        device.osDetails = parsed.osDetails;
        device.hostnames = parsed.hostnames;
        device.scanned = true;
        device.scanning = false;

        logToTerminal(`✓ ${device.ip}: ${device.ports.length} puerto(s) abierto(s)`, 'result');

        // 3b) Vulnerabilidades sobre los puertos abiertos
        const openPorts = device.ports.filter((p) => p.state === 'open').map((p) => p.port);
        if (openPorts.length > 0) {
            const list = openPorts.slice(0, 30).join(',');
            logToTerminal(`→ nmap --script vuln -p ${list} ${device.ip}`, 'cmd');
            content.innerHTML += '<div class="detail-section"><h4>Analizando vulnerabilidades... (puede tardar varios minutos)</h4></div>';
            const vulnData = await api(`/api/scan/vulns?target=${encodeURIComponent(device.ip)}&ports=${encodeURIComponent(list)}`, true);
            device.rawVulns = vulnData.output;
            device.vulns = parseVulns(vulnData.output);
            const count = Object.values(device.vulns).flat().length;
            logToTerminal(`✓ ${device.ip}: ${count} hallazgo(s) de seguridad`, count > 0 ? 'warning' : 'result');
        } else {
            logToTerminal(`→ ${device.ip}: sin puertos abiertos, se omite --script vuln`, 'warning');
        }

        renderDevices();
        showDetails(deviceId);
    } catch (error) {
        device.scanning = false;
        device.error = error.message;
        logToTerminal(`✗ ${device.ip}: ${error.message}`, 'error');
        renderDevices();
        content.innerHTML = `<div class="detail-section"><h4 style="color: var(--color-danger)">Error</h4>
            <p style="color: var(--color-text-muted)">${esc(error.message)}</p></div>`;
    }
}

/* ---------------------------------------------------------------------------
 * Panel de detalles
 * ------------------------------------------------------------------------ */

function showDetails(deviceId) {
    const device = state.devices.find((d) => d.id === deviceId);
    if (!device) return;
    const panel = el('detailsPanel');
    const title = el('detailsTitle');
    const content = el('detailsContent');
    const risk = computeRisk(device);

    title.textContent = `Análisis: ${device.hostname} (${device.ip})`;

    let html = '';

    html += `
        <div class="detail-section">
            <h4>Información General</h4>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-label">Dirección IP</div>
                    <div class="detail-value">${esc(device.ip)}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Hostname</div>
                    <div class="detail-value">${esc(device.hostname)}</div>
                </div>
                ${device.mac ? `<div class="detail-item">
                    <div class="detail-label">MAC / Fabricante</div>
                    <div class="detail-value">${esc(device.mac)} ${esc(device.vendor || '')}</div>
                </div>` : ''}
                <div class="detail-item">
                    <div class="detail-label">Sistema Operativo</div>
                    <div class="detail-value">${esc(device.osDetails || device.os.join(', ') || 'No determinado')}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Nivel de Riesgo</div>
                    <div class="detail-value">${risk.risk} (${risk.score}/100)</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Puertos Abiertos</div>
                    <div class="detail-value">${device.ports.filter((p) => p.state === 'open').length}</div>
                </div>
            </div>
        </div>
    `;

    if (device.ports.length > 0) {
        html += `
            <div class="detail-section">
                <h4>Puertos y Servicios</h4>
                <div class="detail-grid">
                    ${device.ports.map((p) => {
                        const r = scorePort(p);
                        return `
                        <div class="detail-item">
                            <div class="detail-label">${p.port}/${p.proto} · ${esc(p.state)}</div>
                            <div class="detail-value">${esc(p.service)}</div>
                            <div style="color: var(--color-text-muted); font-size: 0.8125rem; margin-top: 4px;">${esc(p.version || 'versión no reportada')}</div>
                            ${r.reasons.length ? `<div style="color: var(--color-warning); font-size: 0.8125rem; margin-top: 4px;">⚠ ${esc(r.reasons.join('; '))}</div>` : ''}
                        </div>`;
                    }).join('')}
                </div>
            </div>
        `;
    }

    const vulnEntries = Object.entries(device.vulns || {}).filter(([, list]) => list.length > 0);
    if (vulnEntries.length > 0) {
        html += '<div class="detail-section"><h4>Hallazgos de Seguridad (--script vuln)</h4>';
        for (const [port, list] of vulnEntries) {
            const p = device.ports.find((x) => x.port === Number(port));
            html += `<h4 style="color: var(--color-warning); margin-top: 12px;">Puerto ${esc(port)} — ${esc(p ? p.service : '')}</h4>`;
            html += '<div class="vuln-list">';
            for (const v of list) {
                const cve = v.cve || (/\b(CVE-\d{4}-\d{4,})\b/i.exec(v.text) || [])[1] || null;
                html += `
                    <div class="vuln-item ${/vulnerable/i.test(v.text) ? 'high' : 'medium'}">
                        <span class="vuln-cve">${esc(cve || v.script || 'SCRIPT')}</span>
                        <span class="vuln-desc">${esc(v.text)}</span>
                    </div>`;
            }
            html += '</div>';
        }
        html += '</div>';
    } else if (device.scanned) {
        html += `<div class="detail-section"><h4>Hallazgos de Seguridad</h4>
            <p style="color: var(--color-text-muted)">No se detectaron vulnerabilidades conocidas en los puertos abiertos.</p></div>`;
    }

    const recommendations = buildRecommendations(device, risk);
    if (recommendations.length > 0) {
        html += `
            <div class="detail-section">
                <h4>Recomendaciones</h4>
                <ul style="padding-left: 20px; color: var(--color-text-muted);">
                    ${recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    html += `
        <div class="detail-section">
            <h4>Salida de nmap (referencia)</h4>
            <details>
                <summary style="cursor: pointer; color: var(--color-text-muted)">Ver salida completa</summary>
                <pre style="background: #000; color: #22c55e; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.8125rem; margin-top: 12px;">${esc(device.rawPorts || '')}${device.rawVulns ? '\n\n' + esc(device.rawVulns) : ''}</pre>
            </details>
        </div>
    `;

    content.innerHTML = html;
    panel.classList.add('active');
    panel.scrollIntoView({ behavior: 'smooth' });
}

function buildRecommendations(device, risk) {
    const recs = [];
    const open = device.ports.filter((p) => p.state === 'open');
    const services = open.map((p) => p.service.toLowerCase());

    if (services.some((s) => ['telnet', 'ftp', 'rsh', 'rlogin', 'tftp'].includes(s))) {
        recs.push('Desactivar servicios en texto plano (telnet/ftp) y usar SSH/SFTP');
    }
    if (services.includes('ssh')) recs.push('Restringir SSH por IP y usar autenticación por clave en vez de contraseña');
    if (services.some((s) => s.includes('http') || s === 'http-proxy')) recs.push('Activar HTTPS y evitar exponer el panel de administración a toda la red');
    if (services.includes('smb') || services.includes('microsoft-ds') || services.includes('netbios-ssn')) {
        recs.push('Desactivar SMBv1 y NetBIOS si no se usan, y filtrar los puertos en el firewall');
    }
    if (services.some((s) => ['upnp', 'ssdp'].includes(s))) recs.push('Desactivar UPnP: permite abrir puertos automáticamente sin autorización');
    if (open.some((p) => [23, 2323, 445, 3389, 5900, 23].includes(p.port))) {
        recs.push('Cerrar con el firewall los puertos de administración expuestos a la LAN');
    }
    if (Object.values(device.vulns || {}).flat().length > 0) {
        recs.push('Revisar los hallazgos de --script vuln y actualizar el firmware/software del dispositivo');
    }
    if (risk.score >= 60) recs.push('Riesgo alto: seguir un plan de remediación inmediato');
    return recs;
}

function closeDetails() {
    el('detailsPanel').classList.remove('active');
}

/* ---------------------------------------------------------------------------
 * Paso 3: informe final
 * ------------------------------------------------------------------------ */

function finishScan() {
    const analyzed = state.devices.filter((d) => d.scanned);
    if (analyzed.length === 0) {
        alert('Analiza al menos un dispositivo antes de generar el informe.');
        return;
    }

    const panel = el('reportPanel');
    const content = el('reportContent');

    const totalDevices = state.devices.length;
    const analyzedCount = analyzed.length;
    const withRisk = analyzed.map((d) => ({ d, r: computeRisk(d) }));
    const highRisk = withRisk.filter((x) => x.r.risk === 'ALTO');
    const mediumRisk = withRisk.filter((x) => x.r.risk === 'MEDIO');
    const lowRisk = withRisk.filter((x) => x.r.risk === 'BAJO');
    const totalPorts = analyzed.reduce((acc, d) => acc + d.ports.filter((p) => p.state === 'open').length, 0);
    const totalVulns = analyzed.reduce((acc, d) => acc + Object.values(d.vulns).flat().length, 0);
    const duration = state.startedAt
        ? Math.max(1, Math.round((Date.now() - state.startedAt.getTime()) / 1000))
        : 0;

    let html = `
        <div class="report-summary">
            <div class="report-stat info">
                <div class="report-stat-value">${totalDevices}</div>
                <div class="report-stat-label">Dispositivos</div>
            </div>
            <div class="report-stat danger">
                <div class="report-stat-value">${highRisk.length}</div>
                <div class="report-stat-label">Riesgo Alto</div>
            </div>
            <div class="report-stat warning">
                <div class="report-stat-value">${mediumRisk.length}</div>
                <div class="report-stat-label">Riesgo Medio</div>
            </div>
            <div class="report-stat success">
                <div class="report-stat-value">${lowRisk.length}</div>
                <div class="report-stat-label">Riesgo Bajo</div>
            </div>
            <div class="report-stat info">
                <div class="report-stat-value">${totalPorts}</div>
                <div class="report-stat-label">Puertos Abiertos</div>
            </div>
            <div class="report-stat danger">
                <div class="report-stat-value">${totalVulns}</div>
                <div class="report-stat-label">Hallazgos</div>
            </div>
        </div>
        <div class="report-section">
            <p style="color: var(--color-text-muted); font-size: 0.875rem;">
                Red: ${esc(state.network || 'n/d')} · Analizados: ${analyzedCount}/${totalDevices} ·
                Duración: ${duration}s · Informe generado: ${new Date().toLocaleString()}
            </p>
        </div>
    `;

    // Hallazgos críticos (derivados de datos reales)
    const criticals = [];
    for (const { d, r } of withRisk) {
        for (const reason of r.reasons) {
            const sev = /texto plano|VULNERABLE|vulnerab/i.test(reason) ? 'critical' : 'high';
            criticals.push({ device: d, reason, sev });
        }
    }
    criticals.sort((a, b) => (a.sev === 'critical' ? -1 : 1));

    html += '<div class="report-section"><h3>Hallazgos</h3><div class="report-list">';
    if (criticals.length === 0) {
        html += `<div class="report-item low"><div>
            <div class="report-item-title">Sin hallazgos relevantes</div>
            <div class="report-item-desc">Ningún puerto abierto presenta señales de riesgo en los dispositivos analizados.</div>
        </div></div>`;
    } else {
        for (const c of criticals.slice(0, 40)) {
            html += `<div class="report-item ${c.sev}"><div>
                <div class="report-item-title">${esc(c.device.hostname)} (${esc(c.device.ip)})</div>
                <div class="report-item-desc">${esc(c.reason)}</div>
            </div></div>`;
        }
        if (criticals.length > 40) {
            html += `<div class="report-item medium"><div>
                <div class="report-item-title">+${criticals.length - 40} hallazgos adicionales</div>
            </div></div>`;
        }
    }
    html += '</div></div>';

    // Acciones recomendadas priorizadas
    const actions = new Map();
    for (const { d, r } of withRisk) {
        for (const rec of buildRecommendations(d, r)) {
            if (!actions.has(rec)) actions.set(rec, []);
            actions.get(rec).push(`${d.hostname} (${d.ip})`);
        }
    }
    const priorityOf = (text) => /urgente|inmediato|Riesgo alto|texto plano|vulnerab|UPnP/i.test(text) ? 'critical' : 'high';

    if (actions.size > 0) {
        html += '<div class="report-section"><h3>Acciones Recomendadas</h3><div class="report-list">';
        for (const [rec, targets] of actions) {
            html += `<div class="report-item ${priorityOf(rec)}"><div>
                <div class="report-item-title">${esc(rec)}</div>
                <div class="report-item-desc">Aplica a: ${esc(targets.join(', '))}</div>
            </div></div>`;
        }
        html += '</div></div>';
    }

    // Dispositivos analizados
    html += '<div class="report-section"><h3>Dispositivos Analizados</h3><div class="report-list">';
    for (const { d, r } of withRisk) {
        const openPorts = d.ports.filter((p) => p.state === 'open').map((p) => `${p.port}/${p.proto}`).join(', ') || 'ninguno';
        const sev = r.risk === 'ALTO' ? 'critical' : (r.risk === 'MEDIO' ? 'medium' : 'low');
        html += `<div class="report-item ${sev}"><div>
            <div class="report-item-title">${esc(d.hostname)} (${esc(d.ip)})</div>
            <div class="report-item-desc">
                Riesgo: ${r.risk} (${r.score}/100) · SO: ${esc(d.osDetails || d.os.join(', ') || 'n/d')} · Puertos: ${esc(openPorts)}
            </div>
        </div></div>`;
    }
    html += '</div></div>';

    const pending = state.devices.filter((d) => !d.scanned);
    if (pending.length > 0) {
        html += `<div class="report-section"><h3>No Analizados</h3><div class="report-list">
            <div class="report-item medium"><div>
                <div class="report-item-title">${pending.length} dispositivo(s) pendientes</div>
                <div class="report-item-desc">${esc(pending.map((d) => d.ip).join(', '))}</div>
            </div></div>
        </div></div>`;
    }

    content.innerHTML = html;
    panel.classList.add('active');
    panel.scrollIntoView({ behavior: 'smooth' });
}

function closeReport() {
    el('reportPanel').classList.remove('active');
}