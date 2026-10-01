# API-NMAP · Network Security Dashboard

[![CI](https://github.com/eliezermev/network-security-dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/eliezermev/network-security-dashboard/actions/workflows/ci.yml)

Dashboard web que analiza tu red local con **nmap real**: descubre dispositivos,
identifica puertos y servicios abiertos, busca vulnerabilidades conocidas y genera
un informe de riesgo.

> ⚠️ **Uso autorizado únicamente.** Esta herramienta solo debe usarse en redes de
> las que seas propietario o sobre las que tengas autorización por escrito.
> Escanear redes ajenas sin permiso es ilegal en la mayoría de países.

---

## Índice

- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Verificar la instalación](#verificar-la-instalación)
- [Pruebas](#pruebas)
- [Cómo usarlo](#cómo-usarlo)
- [API](#api)
- [Variables de entorno](#variables-de-entorno)
- [Docker](#docker)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Notas técnicas](#notas-técnicas)
- [Seguridad](#seguridad)
- [Solución de problemas](#solución-de-problemas)
- [Contribuir](#contribuir)

---

## Requisitos

| Software | Versión | Para qué |
|----------|---------|----------|
| **Node.js** | 18 o superior | Ejecutar el servidor |
| **nmap** | 7.x | Los escaneos |
| **Git** | Cualquiera | Solo para clonar el repo |

### Windows

nmap se ejecuta dentro de una distro de WSL. Instálalas en este orden:

1. **WSL 2** → <https://learn.microsoft.com/es-es/windows/wsl/install>
   En PowerShell (como Administrador): `wsl --install`
2. **Kali Linux** → <https://www.kali.org/get-kali/>
   En PowerShell: `wsl --install -d kali-linux`
3. **nmap** (ya viene en Kali):
   ```powershell
   wsl -d kali-linux -- sudo apt update
   wsl -d kali-linux -- sudo apt install nmap
   ```

> ¿Ya tienes nmap instalado de forma nativa en Windows? Entonces no necesitas
> WSL. Arranca con `USE_WSL=0` (ver [variables](#variables-de-entorno)).

### Linux

```bash
sudo apt update && sudo apt install -y nmap iproute2
```

Para escaneos SYN completos y detección de sistema operativo conviene ejecutar
el servidor con `sudo` o añadir tu usuario al grupo `nmap`:

```bash
sudo usermod -aG nmap $USER   # cierra y vuelve a iniciar sesión
```

### macOS

```bash
brew install nmap
brew install iputils     # aporta 'ip', usado para detectar la red
```

Los escaneos que requieren privilegios (`-O`, SYN scan) piden contraseña de
administrador en macOS.

### Estado de verificación

| Plataforma | Estado |
|------------|--------|
| Windows + WSL + Kali | Probado de punta a punta |
| Linux (nmap nativo) | Probado con y sin permisos root |
| macOS | **Sin probar.** Es el camino menos verificado |

En Linux se validó la detección de red con `ip`, el uso de nmap sin WSL y el
comportamiento sin privilegios. En macOS el código es equivalente, pero depende
de `ifconfig` para obtener la máscara de red.

---

## Instalación

```bash
git clone https://github.com/eliezermev/network-security-dashboard.git
cd network-security-dashboard
npm install
npm start
```

Abre <http://localhost:3000>.

Si ya tienes los archivos, basta con `npm install` y `npm start`.

---

## Verificar la instalación

Antes de la primera ejecución, comprueba que todas las piezas están en su sitio:

```bash
npm run doctor
```

```
  Diagnóstico de API-NMAP
  --------------------------------------------------
  OK    Node.js v24.21.0
  ?    Plataforma: win32
        Windows: nmap se ejecuta dentro de WSL
  OK    nmap disponible (kali-linux)
        Nmap version 7.99 ( https://nmap.org )
  OK    Red local detectada
        192.0.2.0/24  (Wi-Fi)
  OK    Prueba de escaneo con nmap
  OK    Scripts NSE funcionando

  5 correctos · 1 con aviso · 0 con error
  Todo listo. Ejecuta "npm start" y abre http://localhost:3000
```

No modifica nada: solo te dice qué funciona y qué falta, con el comando exacto
para arreglarlo.

---

## Pruebas

El proyecto trae pruebas que puedes ejecutar tú mismo:

```bash
npm test
```

```
ℹ tests 27
ℹ pass 27
ℹ fail 0
ℹ duration_ms 9043
```

Hay dos tipos:

- **Unitarias** (`test/parsers.test.js`): verifican el parseo de la salida de
  nmap. Incluyen los cuatro formatos que emite `--script vuln` y una salida real
  de un router sin vulnerabilidades, para asegurar que no se reporten falsos
  positivos.
- **De integración** (`test/api.test.js`): levantan el servidor real y ejecutan
  un escaneo de verdad contra `127.0.0.1`. También comprueban que se rechacen
  los intentos de inyección de comandos y que no se sirvan archivos internos.

Requieren nmap disponible. Tardan unos 10 segundos.

Están verificadas en Windows (con WSL + Kali) y en Linux, tanto con permisos
root como sin ellos.

### Integración continua

Cada push a `main` activa [GitHub Actions](.github/workflows/ci.yml), que
ejecuta las pruebas en Ubuntu con Node 20, 22 y 24, construye la imagen de
Docker y comprueba que el contenedor arranca y responde. La insignia arriba del
README refleja el resultado del último push.

---

## Cómo usarlo

### 1. Iniciar Análisis de Red

Detecta tu red y descubre qué equipos responden:

```
GET /api/network/cidr    → {"cidr":"192.0.2.0/24"}
GET /api/scan/discovery  → nmap -sn -n 192.0.2.0/24
```

Aparece una tarjeta por dispositivo, con su IP y un botón **Analizar**.

### 2. Analizar dispositivo

Botón **Analizar** en cada tarjeta. Encadena dos escaneos:

```
GET /api/scan/ports?target=192.0.2.10   → nmap -sV -sC -O
GET /api/scan/vulns?target=192.0.2.10&ports=53,80,443,1900   → nmap --script "vuln and not dos"
```

El panel muestra puertos, versiones, sistema operativo, hallazgos y
recomendaciones, todo derivado de los datos reales del escaneo.

### 3. Finalizar Análisis y Generar Informe

Resume todos los dispositivos analizados: estadísticas, hallazgos priorizados,
acciones recomendadas y equipos pendientes.

> Un dispositivo puede tardar entre **30 segundos y 3 minutos** según los puertos
> abiertos: es nmap working de verdad, no una simulación.

---

## API

Respuesta estándar: `{ "success": boolean, "output": string }`, donde `output` es
la salida cruda de nmap.

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/api/health` | Estado del servicio y configuración activa |
| `GET` | `/api/network/cidr` | Detecta las redes locales |
| `GET` | `/api/scan/discovery?network=CIDR` | Descubre hosts activos (`-sn`) |
| `GET` | `/api/scan/ports?target=IP` | Puertos, servicios y SO (`-sV -sC -O`) |
| `GET` | `/api/scan/vulns?target=IP&ports=LISTA` | Vulnerabilidades (`--script vuln`) |
| `GET` | `/api/scan/full?target=IP` | Todos los puertos. Muy lento |
| `POST` | `/api/scan/custom` | Escaneo con flags de una lista blanca |

```bash
curl "http://localhost:3000/api/scan/ports?target=192.0.2.10"
```

En `/api/scan/ports` se puede añadir `&os=false` para saltarse la detección de
sistema operativo cuando el equipo responde lento.

---

## Variables de entorno

Copia [`.env.example`](.env.example) como referencia. En Windows PowerShell:

```powershell
$env:PORT=8080; npm start
```

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `PORT` | `3000` | Puerto del servidor |
| `HOST` | `127.0.0.1` | Interfaz de escucha |
| `NMAP_TIMEOUT` | `360000` | Timeout en ms de cada escaneo |
| `PORT_HOST_TIMEOUT` | `240s` | `--host-timeout` del escaneo de puertos |
| `VULN_HOST_TIMEOUT` | `240s` | `--host-timeout` del escaneo de vulnerabilidades |
| `VULN_SCRIPTS` | `vuln and not dos` | Scripts NSE de vulnerabilidad |
| `WSL_DISTRO` | `kali-linux` | Solo Windows: distro donde está nmap |
| `USE_WSL` | `1` en Windows | `0` para usar nmap nativo de Windows |
| `NMAP_BIN` | `nmap` | Ruta al ejecutable si no está en el PATH |
| `CORS_ORIGIN` | `*` | Origen permitido por CORS |

> `NMAP_TIMEOUT` debe ser **mayor** que los `--host-timeout`, o el proceso se
> corta antes de que nmap termine solo.

---

## Docker

```bash
docker build -t api-nmap .
docker run --rm -p 3000:3000 api-nmap
```

La imagen instala nmap y arranca con `HOST=0.0.0.0`, así que el panel queda
accesible en <http://localhost:3000>.

**Limitación importante:** en un servidor Linux nativo el contenedor sí ve tu LAN.
En **Docker Desktop (Windows y macOS) el contenedor corre dentro de una máquina
virtual y no alcanza tu red local**, por lo que los escaneos no encontrarán
dispositivos. Para escanear desde Windows o macOS usa la instalación directa.

---

## Estructura del proyecto

```
network-security-dashboard/
├── app.js           # Frontend: llamadas a la API, parseo de nmap, UI
├── server.js        # Backend Express: endpoints y rutas
├── doctor.js        # Diagnóstico de la instalación (npm run doctor)
├── lib/
│   └── platform.js  # Detección de SO/red y ejecución de nmap
├── test/
│   ├── parsers.test.js  # Pruebas del parseo de nmap
│   └── api.test.js      # Pruebas del servidor con escaneo real
├── .github/
│   └── workflows/
│       └── ci.yml       # Integración continua
├── index.html
├── styles.css
├── Dockerfile
├── .env.example
├── package.json
└── package-lock.json
```

---

## Notas técnicas

**Windows usa WSL.** nmap y los scripts NSE son nativos de Linux. En Windows el
servidor delega en `wsl.exe`; en Linux, macOS y Docker usa el nmap del sistema.

**Detección de red.** WSL está detrás de NAT (típicamente `172.2x.x.x`), así que
su IP no sirve para escanear tu LAN. El servidor lee la IP real del sistema
anfitrión (`Get-NetIPConfiguration` en Windows, `ip addr` en Linux, `ifconfig` en
macOS) y calcula el CIDR antes de invocar nmap.

**Tiempo de ejecución.** Se usa `execFile` con argumentos en array, no un shell,
así que el proceso lanza nmap directamente.

**Scripts de vulnerabilidad.** Se usa `vuln and not dos` en lugar de `vuln` a
propósito: la categoría completa produce decenas de errores de socket en WSL y
además enviaría payloads de denegación de servicio contra tus propios equipos.

**Tiempo de espera.** `NMAP_TIMEOUT` (360 s) es mayor que el `--host-timeout`
interno de nmap (240 s) para que el proceso no se mate antes de tiempo.

---

## Seguridad

- **Acceso restringido por defecto.** El servidor escucha en `127.0.0.1`.
- **`execFile` con array de argumentos**: no hay shell, la entrada del usuario
  nunca se concatena en una línea de comandos.
- **Validación estricta** de IP, CIDR, hostname, puertos y flags.
- **Lista blanca de flags** en `/api/scan/custom`; cualquier otra cosa se rechaza.
- **Archivos estáticos limitados**: solo `index.html`, `app.js` y `styles.css`.
  `server.js` y `package.json` devuelven 404.
- **Escape de HTML** en todo dato proveniente de nmap.

> El servidor **no tiene autenticación**. Si lo expones con `HOST=0.0.0.0`,
> cualquiera en tu red podrá usarlo para escanear tus equipos. Es una
> herramienta para redes propias, no para exponer a internet.

---

## Solución de problemas

**Ejecuta `npm run doctor` primero.** Detecta la mayoría de los problemas y dice
qué hacer.

**"nmap no disponible"**
En Windows: `wsl -l -v` para ver las distros. Si no aparece `kali-linux`,
instálala con `wsl --install -d kali-linux`. Luego
`wsl -d kali-linux -- sudo apt install nmap`.
En Linux: `sudo apt install nmap`.

**"La distro de WSL no existe"**
Define otra: `$env:WSL_DISTRO = "Ubuntu"`.

**No se detectan dispositivos**
Comprueba la red con `curl http://localhost:3000/api/network/cidr`. Si está
vacía, indica el rango manual:
`/api/scan/discovery?network=192.0.2.0/24`.

**El escaneo se corta con "Skipping host due to host timeout"**
El equipo tarda demasiado en responder. Sube `NMAP_TIMEOUT` y usa `&os=false`
para saltar la detección de SO.

**"Operation not permitted" en Linux**
Faltan privilegios para SYN scan y `-O`. Ejecuta con `sudo` o usa `-sT`.

**La tarjeta sale sin puertos**
El host puede estar apagado. Usa el botón **Reanalizar**.

---

## Contribuir

```bash
git clone https://github.com/eliezermev/network-security-dashboard.git
cd network-security-dashboard
npm install
npm run doctor     # comprueba que todo funciona
npm test           # ejecuta las pruebas
npm start
```

Para enviar cambios:

```bash
git add .
git commit -m "Describe el cambio"
git push
```

Si cambias algo del servidor o de los parsers, ejecuta `npm test` antes de
subirlo. GitHub Actions lo repetirá en Ubuntu con tres versiones de Node y en
Docker.

---

## Licencia

MIT. Ver [LICENSE](LICENSE).