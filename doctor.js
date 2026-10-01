#!/usr/bin/env node
/**
 * doctor.js - Comprueba que todo lo necesario esté listo.
 *
 *   npm run doctor
 *
 * No modifica nada: solo informa qué funciona y qué falta.
 */

const {
    IS_WINDOWS,
    USE_WSL,
    WSL_DISTRO,
    NMAP_TIMEOUT,
    runNmap,
    nmapVersion,
    detectLocalCidr
} = require('./lib/platform');

const results = [];

function report(ok, title, detail) {
    results.push({ ok, title, detail });
    const icon = ok === null ? '?' : (ok ? 'OK  ' : 'FALLA');
    const color = ok === null ? '\x1b[33m' : (ok ? '\x1b[32m' : '\x1b[31m');
    console.log(`  ${color}${icon}\x1b[0m  ${title}`);
    if (detail) {
        console.log(`        \x1b[90m${detail}\x1b[0m`);
    }
}

function line() {
    console.log('');
}

async function main() {
    console.log('');
    console.log('\x1b[1m  Diagnóstico de API-NMAP\x1b[0m');
    console.log('  ' + '-'.repeat(50));

    // 1. Node
    const major = parseInt(process.versions.node.split('.')[0], 10);
    report(major >= 18, `Node.js ${process.version}`, major >= 18
        ? 'Versión correcta'
        : 'Se requiere Node 18 o superior: https://nodejs.org');

    // 2. Plataforma
    report(null, `Plataforma: ${process.platform}`,
        IS_WINDOWS ? 'Windows: nmap se ejecuta dentro de WSL' : 'Linux/macOS: se usa el nmap del sistema');

    // 3. nmap
    line();
    const version = await nmapVersion();
    if (version) {
        report(true, `nmap disponible (${USE_WSL ? WSL_DISTRO : 'sistema'})`, version);
    } else if (USE_WSL) {
        report(false, 'nmap no disponible', [
            `Comprueba la distro de WSL:  wsl -l -v`,
            `Instala nmap en Kali:        wsl -d ${WSL_DISTRO} -- sudo apt install nmap`,
            `O define otra distro:        $env:WSL_DISTRO = "Ubuntu"`
        ].join('\n        '));
    } else {
        report(false, 'nmap no disponible',
            'Instálalo con "sudo apt install nmap" o define NMAP_BIN con la ruta completa');
    }

    // 4. Privilegios (Linux: -O y los SYN scan necesitan root)
    if (!IS_WINDOWS) {
        const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
        if (isRoot) {
            report(true, 'Privilegios', 'Ejecutando como root: escaneos SYN y detección de SO completos');
        } else {
            report(null, 'Privilegios', 'Sin root: el escaneo SYN y la detección de SO pueden fallar. ' +
                'Usa sudo o añade el usuario al grupo de nmap si tienes sudo.');
        }
    }

    // 5. Detección de red
    line();
    const networks = await detectLocalCidr();
    if (networks.length > 0) {
        report(true, 'Red local detectada', networks.map((n) => `${n.cidr}  (${n.interface})`).join('\n        '));
    } else {
        report(false, 'No se pudo detectar la red local',
            'Indica la red manualmente con /api/scan/discovery?network=192.0.2.0/24');
    }

    // 6. Prueba real de escaneo
    line();
    try {
        const output = await runNmap(['-sn', '-n', '127.0.0.1'], 30000);
        if (output.includes('127.0.0.1')) {
            report(true, 'Prueba de escaneo con nmap', 'Detectó el host loopback correctamente');
        } else {
            report(null, 'Prueba de escaneo con nmap', 'nmap respondió pero sin resultado inesperado');
        }
    } catch (error) {
        report(false, 'Prueba de escaneo con nmap', error.message);
    }

    // 7. Escaneo de loopback con Scripts NSE
    try {
        const output = await runNmap(['-sV', '-p', '1', '--script', 'banner', '127.0.0.1'], 60000);
        report(output.length > 0, 'Scripts NSE funcionando',
            'Necesarios para --script vuln');
    } catch (error) {
        report(null, 'Scripts NSE', `No se pudieron ejecutar: ${error.message}`);
    }

    // Resumen
    line();
    console.log('  ' + '-'.repeat(50));
    const failed = results.filter((r) => r.ok === false);
    const warnings = results.filter((r) => r.ok === null);
    const ok = results.filter((r) => r.ok === true);

    console.log(`  ${ok.length} correctos · ${warnings.length} con aviso · ${failed.length} con error`);
    console.log(`  Timeout de escaneo: ${NMAP_TIMEOUT} ms`);
    console.log('');

    if (failed.length > 0) {
        console.log('  \x1b[31mHay componentes pendientes. Corrígelos antes de usar el panel.\x1b[0m');
        console.log('');
        process.exitCode = 1;
        return;
    }

    console.log('  \x1b[32mTodo listo. Ejecuta "npm start" y abre http://localhost:3000\x1b[0m');
    console.log('');
}

main().catch((error) => {
    console.error('');
    console.error('  Error inesperado en el diagnóstico:', error.message);
    console.error('');
    process.exitCode = 1;
});