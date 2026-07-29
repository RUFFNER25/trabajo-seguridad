# SecureBank Lab

Banca **demo** educativa con dos apps gemelas:

| App | Puerto | Carpeta |
|-----|--------|---------|
| Vulnerable | http://localhost:3001 | `vulnerable/` |
| Segura | http://localhost:3002 | `segura/` |

Mismas pantallas y flujos. Dinero ficticio. **Solo localhost / lab.** No desplegar la versión vulnerable en Internet.

> **Guion completo de ataques para la clase:** [GUIA-PRUEBAS.md](GUIA-PRUEBAS.md) (pasos exactos, impacto, contraste seguro y herramientas de los 12 ataques).

## Arranque

```bash
# Vulnerable
cd vulnerable
npm install
npm run reset
npm start

# Segura (otra terminal)
cd segura
npm install
npm run reset
npm start
```

### Usuarios demo (ambas)

| Usuario | Contraseña | Saldo inicial |
|---------|------------|---------------|
| alice | password123 | 1500 |
| bob | password123 | 800 |
| admin | admin123 | 10000 |

Resetear datos: `npm run reset` en cada carpeta.

### Clase en LAN

Si los alumnos atacan desde otras PCs de la misma red:

```bash
# Las apps ya escuchan en 0.0.0.0
# Sustituye por tu IP local, p. ej.:
# http://192.168.1.20:3001
```

## Ética

- Solo contra estas apps en localhost o LAN del curso.
- No atacar sistemas ajenos.
- La app vulnerable existe para aprender, no para publicar.

## Mapa OWASP → feature → demo

| Riesgo | Dónde | Demo rápida (vulnerable :3001) | En segura (:3002) |
|--------|-------|--------------------------------|-------------------|
| A03 SQLi | Login | Usuario: `admin' --` y cualquier pass | Login rechazado |
| A03 SQLi | `/search?q=` | `x' OR '1'='1` | Sin dump / error controlado |
| XSS stored | Soporte | Mensaje: `<script>alert(1)</script>` | Texto escapado |
| XSS reflected | Buscar | `q=<script>alert(1)</script>` | Escapado |
| A01 IDOR | `/account?id=2` | Logueada alice, ver cuenta de bob | 403 / denegado |
| A07 Auth | Cookie / DB | Cookie sin HttpOnly; password en claro en SQLite | bcrypt + HttpOnly |
| CSRF | Transferencia | Abrir `labs/csrf-demo.html` con sesión alice | Token CSRF rechaza |
| A05 Misconfig | Headers | `curl -I http://localhost:3001` | `curl -I :3002` con Helmet |
| Upload | Perfil | Subir con nombre arbitrario | Solo imágenes, nombre random |
| A10 SSRF | Verificar URL | `http://127.0.0.1:3001/` | Solo allowlist (example.com, httpbin.org) |
| A09 Logging | Login | Sin log de fallos | Tabla `auth_events` |
| A04 Design | Login | Sin rate limit | Rate limit en `/login` |

## Guion de clase (por fallo)

1. Nombrar el riesgo OWASP (1 min).
2. Mismos pasos en vulnerable → impacto (saldo ajeno, XSS, transferencia).
3. Mismos pasos en segura → bloqueo.
4. Diff de código entre `vulnerable/server.js` y `segura/server.js`.
5. Tool: DevTools, Burp/ZAP o `curl`.

## Herramientas

- Navegador + DevTools (cookies, red)
- Burp Suite Community o OWASP ZAP
- `curl` (headers)
- DB Browser for SQLite (ver passwords en claro vs hash)
- sqlmap solo contra `:3001` local (opcional, con ética)

## Estructura

```
vulnerable/   → Express + SQLite + EJS (fallos intencionales)
segura/       → mismos flujos + controles
labs/         → csrf-demo.html
README.md     → esta guía
```
# trabajo-seguridad
