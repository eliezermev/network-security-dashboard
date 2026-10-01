/**
 * Pruebas de los parsers de salida de nmap.
 *
 * Estos parsers son la parte más frágil: dependen de formatos de texto que
 * cambian entre versiones de nmap. Cada formato real que se ha encontrado
 * está cubierto aquí para que una regresión se detecte antes de publicar.
 */

const { test } = require('node:test');
const assert = require('node:assert');

const { parseDiscovery, parseHostScan, parseVulns, scorePort, computeRisk, esc } = require('../app.js');

/* -------------------------------------------------------------------------
 * parseDiscovery  (nmap -sn)
 * ---------------------------------------------------------------------- */

test('parseDiscovery: encuentra hosts por IP', () => {
    const output = `Nmap scan report for 192.0.2.1
Host is up (0.0044s latency).
Nmap scan report for 192.0.2.20
Host is up (0.080s latency).
Nmap scan report for 192.0.2.168
Host is up (0.00039s latency).
# Nmap done at Thu Oct  1 11:35:41 2026 -- 256 IP addresses (3 hosts up) scanned in 3.93 seconds`;

    const hosts = parseDiscovery(output);
    assert.strictEqual(hosts.length, 3);
    assert.deepStrictEqual(hosts.map((h) => h.ip), ['192.0.2.1', '192.0.2.20', '192.0.2.168']);
});

test('parseDiscovery: extrae hostname y MAC', () => {
    const output = `Nmap scan report for router.lan (192.0.2.1)
Host is up (0.01s latency).
MAC Address: 50:C7:BF:00:11:22 (TP-LINK Technologies)`;

    const hosts = parseDiscovery(output);
    assert.strictEqual(hosts.length, 1);
    assert.strictEqual(hosts[0].ip, '192.0.2.1');
    assert.strictEqual(hosts[0].hostname, 'router.lan');
    assert.strictEqual(hosts[0].mac, '50:C7:BF:00:11:22');
    assert.strictEqual(hosts[0].vendor, 'TP-LINK Technologies');
});

test('parseDiscovery: devuelve lista vacía sin hosts', () => {
    const output = `Nmap scan report for 192.0.2.0/24
# Nmap done -- 256 IP addresses (0 hosts up) scanned in 0.5 seconds`;
    assert.deepStrictEqual(parseDiscovery(output), []);
});

test('parseDiscovery: no falla con entrada vacía o inválida', () => {
    assert.deepStrictEqual(parseDiscovery(''), []);
    assert.deepStrictEqual(parseDiscovery(undefined), []);
});

/* -------------------------------------------------------------------------
 * parseHostScan  (nmap -sV -sC -O)
 * ---------------------------------------------------------------------- */

test('parseHostScan: extrae puertos, versiones y SO', () => {
    const output = `Nmap scan report for 192.0.2.1
Host is up (0.0017s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
53/tcp   open  tcpwrapped
80/tcp   open  http       BusyBox http 1.19.4
|_http-title: Site doesn't have a title (text/html).
443/tcp  open  ssl/http   BusyBox http 1.19.4
1900/tcp open  upnp       MiniUPnP 2.2.2 (TP-LINK router; UPnP 1.1)
No exact OS matches for host (see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.99%E=4%D=10/1%OT=80%CT=1%CU=42713%PV=Y%G=Y)SEQ(SP=104%GCD=1)
Network Distance: 2 hops
Service Info: OS: Linux; Device: broadband router; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed.`;

    const result = parseHostScan(output);
    assert.strictEqual(result.ports.length, 4);

    const http = result.ports.find((p) => p.port === 80);
    assert.strictEqual(http.state, 'open');
    assert.strictEqual(http.proto, 'tcp');
    assert.strictEqual(http.service, 'http');
    assert.strictEqual(http.version, 'BusyBox http 1.19.4');

    const upnp = result.ports.find((p) => p.port === 1900);
    assert.match(upnp.version, /MiniUPnP/);

    // El SO se lee de "Service Info", no del fingerprint
    assert.ok(result.os.some((o) => o.includes('Linux')));
    assert.ok(result.os.some((o) => o.includes('broadband router')));
    assert.ok(!result.os.some((o) => o.includes('SCAN(V=')), 'el fingerprint no debe colarse como SO');
});

test('parseHostScan: lee "OS details"', () => {
    const output = `Nmap scan report for 192.0.2.5
PORT   STATE SERVICE
22/tcp open  ssh
OS details: Linux 5.15.0-generic`;
    const result = parseHostScan(output);
    assert.strictEqual(result.osDetails, 'Linux 5.15.0-generic');
});

test('parseHostScan: descarta el bloque SF del fingerprint', () => {
    const output = `Nmap scan report for 192.0.2.20
PORT   STATE SERVICE
9080/tcp open glrpc
| fingerprint-strings:
|_    status=ok
1 service unrecognized despite returning data.
SF-Port9080-TCP:V=7.99%I=7%D=10/1%r(Ge
SF:tRequest,99,"HTTP/1\\.0");
Network Distance: 2 hops`;

    const result = parseHostScan(output);
    const port = result.ports.find((p) => p.port === 9080);
    const notes = port.scriptNotes || [];
    assert.ok(!notes.some((n) => n.startsWith('SF')), 'las líneas SF no deben guardarse');
    assert.ok(!notes.some((n) => /despite returning data/.test(n)));
});

test('parseHostScan: no falla con entrada vacía', () => {
    const result = parseHostScan('');
    assert.deepStrictEqual(result.ports, []);
    assert.strictEqual(result.osDetails, null);
});

/* -------------------------------------------------------------------------
 * parseVulns  (nmap --script vuln)
 * ---------------------------------------------------------------------- */

test('parseVulns: recoge los cuatro formatos de salida', () => {
    const output = `PORT     STATE    SERVICE
22/tcp   open     ssh
| vulnresults:
|   VULNERABILITY RESULT:
|     OpenSSH <6.9: Vulnerability in the way authentication requests are processed
|     Reference: https://vuxml.org/cpe/cpe-53:cpe:openssh:openssh
|     VULN RESULTS: * VULNERABLE *
80/tcp   open     http
|_http-vuln-cve2014-3704: VULNERABLE: WordPress Pingback API: XML Injection
|     CVE-2013-7091:
|       VULNERABLE:
|       OpenSSH: Server side drop (CVE-2013-7091)
21/tcp   open     ftp
| ftp-anon: VULNERABLE: Anonymous FTP login allowed
443/tcp  open     ssl/https`;

    const result = parseVulns(output);

    // Formato 1: bloque vulnresults (la descripción viene en la línea siguiente)
    assert.strictEqual(result['22'].length, 1);
    assert.match(result['22'][0].text, /OpenSSH <6\.9/);
    assert.ok(!/VULN RESULTS/.test(result['22'][0].text), 'los metadatos no deben ser la descripción');

    // Formato 2: resultado por script
    assert.strictEqual(result['80'].length, 2);
    assert.ok(result['80'].some((v) => v.script === 'http-vuln-cve2014-3704'));

    // Formato 3: CVE en dos líneas, con la descripción anexada
    const cve = result['80'].find((v) => v.cve === 'CVE-2013-7091');
    assert.ok(cve, 'debe detectar el CVE en formato de dos líneas');
    assert.match(cve.text, /Server side drop/);

    // Formato 4: script sin CVE
    assert.strictEqual(result['21'].length, 1);
    assert.strictEqual(result['21'][0].script, 'ftp-anon');

    // Un puerto sin hallazgos
    assert.deepStrictEqual(result['443'], []);
});

test('parseVulns: no reporta falsos positivos', () => {
    // Salida real de un router sin vulnerabilidades
    const output = `PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
443/tcp  open  https
|_ssl-ccs-injection: No reply from server (TIMEOUT)
1900/tcp open  upnp`;

    const result = parseVulns(output);
    for (const port of Object.keys(result)) {
        assert.deepStrictEqual(result[port], [], `el puerto ${port} no debe reportar hallazgos`);
    }
});

test('parseVulns: elimina duplicados del mismo CVE', () => {
    const output = `PORT   STATE SERVICE
22/tcp open  ssh
|     CVE-2014-2130:
|       VULNERABLE:
|       OpenSSH: cipher with available key length of 128 bits
|     CVE-2014-2130:
|       VULNERABLE:
|       OpenSSH: cipher with available key length of 128 bits`;
    const result = parseVulns(output);
    assert.strictEqual(result['22'].length, 1);
});

test('parseVulns: no falla con entrada vacía', () => {
    assert.deepStrictEqual(parseVulns(''), {});
    assert.deepStrictEqual(parseVulns(undefined), {});
});

/* -------------------------------------------------------------------------
 * Clasificación de riesgo
 * ---------------------------------------------------------------------- */

test('scorePort: penaliza telnet más que https', () => {
    const telnet = scorePort({ port: 23, proto: 'tcp', state: 'open', service: 'telnet', version: null });
    const https = scorePort({ port: 443, proto: 'tcp', state: 'open', service: 'https', version: 'nginx 1.24' });
    assert.ok(telnet.score > https.score, 'telnet debe puntuar más alto');
    assert.ok(telnet.reasons.length > 0);
});

test('scorePort: detecta versión antigua', () => {
    const old = scorePort({ port: 80, proto: 'tcp', state: 'open', service: 'http', version: 'BusyBox http 1.19.4' });
    assert.ok(old.reasons.some((r) => /antigua/.test(r)));
});

test('computeRisk: dispositivo sin analizar queda pendiente', () => {
    const risk = computeRisk({ ports: [], vulns: {}, scanned: false });
    assert.strictEqual(risk.risk, 'PENDIENTE');
    assert.strictEqual(risk.score, 0);
});

test('computeRisk: escalona el riesgo según los puertos', () => {
    const low = computeRisk({
        scanned: true,
        vulns: {},
        ports: [{ port: 443, proto: 'tcp', state: 'open', service: 'https', version: 'nginx 1.24' }]
    });
    const high = computeRisk({
        scanned: true,
        vulns: { 23: [{ kind: 'script', text: 'telnet: VULNERABLE' }] },
        ports: [
            { port: 23, proto: 'tcp', state: 'open', service: 'telnet', version: 'BusyBox 1.19' },
            { port: 21, proto: 'tcp', state: 'open', service: 'ftp', version: null }
        ]
    });
    assert.ok(high.score > low.score);
    assert.strictEqual(low.riskClass, 'risk-low');
    assert.ok(['risk-high', 'risk-medium'].includes(high.riskClass));
});

/* -------------------------------------------------------------------------
 * Escape de HTML
 * ---------------------------------------------------------------------- */

test('esc: neutraliza HTML para evitar inyección desde datos de nmap', () => {
    assert.strictEqual(esc('<script>alert(1)</script>'),
        '&lt;script&gt;alert(1)&lt;/script&gt;');
    assert.strictEqual(esc('a"b\'c&d'), 'a&quot;b&#39;c&amp;d');
    assert.strictEqual(esc(null), '');
    assert.strictEqual(esc(undefined), '');
});