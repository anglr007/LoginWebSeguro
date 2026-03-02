require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const authRoutes = require('./routes/auth');

const app = express();

// ── Seguridad: Headers HTTP seguros ──────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    }
  }
}));

// ── Seguridad: Rate Limiting global ──────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutos
  max: 100,
  message: { success: false, message: 'Demasiadas solicitudes. Intenta más tarde.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(globalLimiter);

// ── Seguridad: Rate Limiting estricto para auth ───────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Demasiados intentos de autenticación. Espera 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/auth', authLimiter);

// ── Middlewares ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));          // Limitar tamaño de payload
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ── Seguridad: Sanitizar datos (anti NoSQL injection) ────────────────────────
app.use(mongoSanitize());

// ── Archivos estáticos ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Rutas de la API ───────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);

// ── Servir el frontend para cualquier otra ruta ───────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Conexión a MongoDB y arranque del servidor ────────────────────────────────
const PORT = process.env.PORT || 3000;

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ Conectado a MongoDB Atlas');
    app.listen(PORT, () => console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('❌ Error al conectar a MongoDB:', err.message);
    process.exit(1);
  });
