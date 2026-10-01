# API-NMAP · Network Security Dashboard

Dashboard web que analiza tu red local con **nmap real**: descubre dispositivos,
identifica puertos y servicios abiertos, busca vulnerabilidades conocidas y genera
un informe de riesgo.

> ⚠️ **Uso autorizado únicamente.** Esta herramienta solo debe usarse en redes de
> las que seas propietario o sobre las que tengas autorización por escrito.
> Escanear redes ajenas sin permiso es ilegal en la mayoría de países.

---

## Requisitos previos

### Obligatorios

| Software | Versión mínima | Link |
|----------|----------------|------|
| **Windows** | 10 (build 19041) u 11 | — |
| **Node.js** | 18 o superior (probado en 24.x) | <https://nodejs.org/es/download> |
| **npm** | 9 o superior (viene con Node) | <https://docs.npmjs.com/downloading-and-installing-node-js-and-npm> |
| **WSL 2** | Versión actual | <https://learn.microsoft.com/es-es/windows/wsl/install> |
| **Kali Linux** (distro WSL) | Cualquier versión reciente | <https://www.kali.org/get-kali/> |
| **nmap** | 7.x (viene incluido en Kali) | <https://nmap.org/download.html> |

### Opcionales

| Software | Para qué | Link |
|----------|----------|------|
| **Docker Desktop** | Ver la sección *Limitaciones de Docker* | <https://www.docker.com/products/docker-desktop/> |
| **Git** | Solo si quieres clonar el repo | <https://git-scm.com/download/win> |

### Verificar que todo está instalado

```powershell
node -v          # debe mostrar v18 o superior
npm -v
wsl -l -v        # debe listar kali-linux
wsl -d kali-linux -- nmap --version
```

Si `wsl -l -v` no muestra `kali-linux`, instálalo siguiendo la guía oficial de WSL
(<https://learn.microsoft.com/es-es/windows/wsl/install>) y luego la de Kali.

---

## Instalación

```powershell
git clone https://github.com/eliezermev/network-security-dashboard.git
cd network-security-dashboard
npm install
npm start
```

Sin clonar (si ya tienes los archivos):

```powershell
cd api-nmap
npm install
npm start
```

Abre <http://localhost:3000> en el navegador.

---

## Cómo usarlo

La interfaz tiene tres pasos, en este orden.

### 1. Iniciar Análisis de Red

Detecta automáticamente tu red local y descubre qué dispositivos responden:

```
GET /api/network/cidr      → {"cidr":"192.0.2.0/24"}
GET /api/scan/discovery    → nmap -sn -n 192.0.2.0/24
```

Aparece una tarjeta por dispositivo con su IP y un botón **Analizar**.

### 2. Analizar dispositivo (botón de cada tarjeta)

Ejecuta dos escaneos encadenados:

```
GET /api/scan/ports?target=192.0.2.10   → nmap -sV -sC -O
GET /api/scan/vulns?target=192.0.2.10&ports=53,80,443,1900   → nmap --script "vuln and not dos"
```

El panel de detalle muestra puertos, versiones detectadas, sistema operativo,
hallazgos de seguridad y recomendaciones calculadas a partir de los datos reales.

### 3. Finalizar Análisis y Generar Informe

Agrega los datos de todos los dispositivos analizados: resumen estadístico,
hallazgos priorizados, acciones recomendadas y equipos pendientes.

> El análisis de un dispositivo puede tardar entre **30 segundos y 3 minutos**
> según la cantidad de puertos abiertos: es nmap ejecutándose de verdad.

---

## Estructura del proyecto

```
network-security-dashboard/
├── app.js           # Frontend: llamadas a la API, parseo de nmap, UI
├── server.js        # Backend Express: endpoints + ejecución de nmap vía WSL
├── index.html       # Estructura de la interfaz
├── styles.css       # Estilos (tema oscuro)
├── Dockerfile       # Imagen de contenedor (ver limitaciones)
├── package.json     # Dependencias y script de arranque
├── package-lock.json
└── .gitignore
```

---

## API

Todos los endpoints son `GET` salvo `POST /api/scan/custom`.
El cuerpo de respuesta es `{ "success": boolean, "output": string }`, donde
`output` es la salida cruda de nmap.

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/api/network/cidr` | Detecta la red local desde Windows |
| `GET` | `/api/scan/discovery?network=CIDR` | Descubre hosts activos (`-sn`) |
| `GET` | `/api/scan/ports?target=IP` | Puertos, servicios y SO (`-sV -sC -O`) |
| `GET` | `/api/scan/vulns?target=IP&ports=LISTA` | Vulnerabilidades (`--script vuln`) |
| `GET` | `/api/scan/full?target=IP` | Escaneo completo de todos los puertos |
| `POST` | `/api/scan/custom` | Escaneo con flags de una lista blanca |

Ejemplo:

```powershell
curl "http://localhost:3000/api/scan/ports?target=192.0.2.10"
```

### Variables de entorno

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `PORT` | `3000` | Puerto del servidor |
| `WSL_DISTRO` | `kali-linux` | Distro de WSL donde está nmap |
| `NMAP_TIMEOUT` | `300000` | Timeout en ms por escaneo |
| `VULN_SCRIPTS` | `vuln and not dos` | Scripts NSE usados |

```powershell
$env:PORT=8080; npm start
```

---

## Notas técnicas

**¿Por qué WSL?** El servidor corre en Windows pero ejecuta nmap dentro de
Kali en WSL, porque nmap y los scripts NSE son nativos de Linux.

**Detección de red.** WSL está detrás de NAT (típicamente `172.2x.x.x`), así que
su IP no sirve para escanear tu LAN. El servidor detecta la IP de Windows con
`Get-NetIPConfiguration` y calcula el CIDR real antes de delegar en nmap.

**`-O` es lento.** La detección de sistema operativo puede duplicar el tiempo de
escaneo. Puedes desactivarla con `/api/scan/ports?target=IP&os=false`.

**Scripts de vulnerabilidad.** Se usa `vuln and not dos` en lugar de `vuln` a
propósito: la categoría completa produce decenas de errores de socket en WSL y
además envía payloads de denegación de servicio contra tus propios equipos.

---

## Seguridad

- **`execFile` con array de argumentos**: no se usa `shell`, por lo que la entrada
  del usuario nunca se concatena en una línea de comandos.
- **Validación estricta** de IP, CIDR, hostname y lista de puertos.
- **Lista blanca de flags** en `/api/scan/custom`; todo lo demás se rechaza.
- **Archivos estáticos limitados**: solo se sirven `index.html`, `app.js` y
  `styles.css`. `server.js` y `package.json` devuelven 404.
- **Escape de HTML** en todo dato proveniente de nmap antes de inyectarlo.

Considera además no exponer el puerto 3000 a la red: el servidor queda en
`0.0.0.0` y no tiene autenticación.

---

## Limitaciones de Docker

El `Dockerfile` existe para validar el frontend, pero el proyecto **no funciona
completo dentro de un contenedor**: `server.js` invoca `wsl.exe`, que solo existe
en Windows. Para escanear de verdad necesitas ejecutarlo directamente en Windows
con WSL + Kali.

---

## Solución de problemas

**`wsl -d kali-linux -- bash -c "nmap --version"` falla**
Kali no está instalada o no está inicializada. Abre WSL y ejecuta `nmap` una vez
para que se configure sola.

**"No se encontró el comando nmap"**
Dentro de Kali: `sudo apt update && sudo apt install nmap`.

**El escaneo se corta con *"Skipping host due to host timeout"***
El dispositivo tarda demasiado en responder. Sube `NMAP_TIMEOUT` y usa
`&os=false` para saltar la detección de SO.

**La tarjeta aparece sin puertos**
Puede ser que el host ya no esté en línea, o que el escaneo haya sido interrumpido
por el timeout. Usa el botón **Reanalizar**.

**No se detectan dispositivos**
Comprueba que estás en la red correcta:
`curl "http://localhost:3000/api/network/cidr"`.

---

## Publicar este proyecto en GitHub

### 1. Instalar y configurar Git

Descarga Git si no lo tienes: <https://git-scm.com/download/win>

```powershell
git config --global user.name "eliezermev"
git config --global user.email "eliezermev@gmail.com"
```

El correo puede ser el privado: GitHub no lo muestra públicamente, solo lo usa
para vincular los commits a tu cuenta. Si prefieres no asociar ningún correo
real, usa `eliezermev@users.noreply.github.com`.

### 2. Crear el repositorio en GitHub

Ve a <https://github.com/new>. Elige nombre, decide **público o privado**, y
**no marques** ninguna opción de README, `.gitignore` ni licencia (ya los tiene
el proyecto). Luego pulsa *Create repository*.

### 3. Publicar desde la terminal

```powershell
cd api-nmap
git init
git add .
git status          # revisa qué se va a subir
git commit -m "Dashboard de análisis de red con nmap"
git branch -M main
git remote add origin https://github.com/eliezermev/network-security-dashboard.git
git push -u origin main
```

### 4. Autenticación

GitHub **no acepta tu contraseña normal** para hacer push por HTTPS. Se usa el
gestor de credenciales que ya viene con Git para Windows, que abre el navegador
para iniciar sesión:

```powershell
git credential-manager configure
git push -u origin main
```

Se abrirá una ventana del navegador: inicia sesión y autoriza. Git guarda el
acceso en el Administrador de credenciales de Windows y no lo volverá a pedir.

Si prefieres hacerlo manualmente, crea un **personal access token** en
<https://github.com/settings/tokens> con el permiso `repo` y úsalo como
contraseña cuando git la solicite.

### Alternativa sin terminal

Si prefieres evitar la línea de comandos, usa **GitHub Desktop**
(<https://desktop.github.com/>): *File → Add local repository*, y luego
*Publish repository*.

---

## Licencia

MIT. Ver [LICENSE](LICENSE).