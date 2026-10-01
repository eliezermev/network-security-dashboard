# La imagen incluye nmap, así que dentro del contenedor se usa directamente
# (no WSL, que es específico de Windows host).
FROM node:24-slim

# nmap + las herramientas que usa para la detección de red
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        iproute2 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Escanear SYN y detectar SO requiere privileges de red.
# El contenedor corre como root por defecto, que es lo necesario aquí.
ENV HOST=0.0.0.0
ENV PORT=3000
ENV NMAP_TIMEOUT=360000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]