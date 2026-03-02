# 🔐 SecureAuth Demo

Demo de login seguro con Node.js + Express + MongoDB Atlas.

## Medidas de seguridad implementadas

| Capa | Librería / técnica | Detalle |
|---|---|---|
| Contraseñas | `bcryptjs` (salt 12) | Nunca se almacenan en texto plano |
| Sesión | `jsonwebtoken` (JWT) | Token firmado, expira en 1 hora |
| Cookie | `httpOnly + sameSite: strict + secure` | No accesible desde JS, protegida contra CSRF |
| Inyección NoSQL | `express-mongo-sanitize` | Sanitiza caracteres peligrosos (`$`, `.`) |
| Headers HTTP | `helmet` | Content-Security-Policy, X-Frame-Options, etc. |
| Fuerza bruta (global) | `express-rate-limit` | Máx 100 req / 15 min |
| Fuerza bruta (auth) | `express-rate-limit` (estricto) | Máx 20 intentos / 15 min |
| Bloqueo de cuenta | Lógica en modelo | Bloqueo 15 min tras 5 intentos fallidos |
| Payload | `express.json({ limit: '10kb' })` | Evita ataques de payload gigante |
| Variables secretas | `.env` (nunca en git) | JWT_SECRET, MongoDB URI |
| Validación email | `validator.isEmail()` | Formato estricto en cliente y servidor |
| Validación contraseña | Regex | Mínimo 8 chars, 1 número, 1 especial |

---

## Despliegue en Render (gratis)

### 1. Crear base de datos en MongoDB Atlas

1. Ve a [https://cloud.mongodb.com](https://cloud.mongodb.com) → crea cuenta gratis
2. Crea un cluster **M0 Free**
3. En **Database Access** → agrega un usuario con contraseña
4. En **Network Access** → agrega `0.0.0.0/0` (permitir desde cualquier IP)
5. En **Connect** → copia la URI de conexión:
   ```
   mongodb+srv://usuario:password@cluster0.xxxxx.mongodb.net/secure_login_demo
   ```

### 2. Subir el código a GitHub

```bash
git init
git add .
git commit -m "initial commit"
# Crea un repo en github.com y luego:
git remote add origin https://github.com/TU_USUARIO/secure-login-demo.git
git push -u origin main
```

### 3. Desplegar en Render

1. Ve a [https://render.com](https://render.com) → crea cuenta gratis con GitHub
2. **New +** → **Web Service** → conecta tu repositorio
3. Configura:
   - **Environment:** `Node`
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
4. En **Environment Variables** agrega:
   ```
   MONGODB_URI   = mongodb+srv://usuario:password@...
   JWT_SECRET    = una_cadena_muy_larga_y_aleatoria_aqui
   JWT_EXPIRES_IN = 1h
   NODE_ENV      = production
   PORT          = 3000
   ```
5. Click en **Create Web Service**
6. En ~2 minutos tendrás tu URL pública: `https://tu-app.onrender.com`

---

## Ejecución local

```bash
# 1. Instalar dependencias
npm install

# 2. Configurar variables de entorno
cp .env.example .env
# Edita .env con tus datos reales

# 3. Correr el servidor
npm run dev
# Abre http://localhost:3000
```
