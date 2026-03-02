const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const validator = require('validator');
const User = require('../models/User');
const { protect } = require('../middleware/auth');

// Validación de contraseña segura
const validatePassword = (password) => {
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  const hasMinLength = password.length >= 8;
  
  const errors = [];
  if (!hasMinLength) errors.push('al menos 8 caracteres');
  if (!hasNumber) errors.push('al menos un número');
  if (!hasSpecial) errors.push('al menos un carácter especial (!@#$%^&* etc.)');
  
  return errors;
};

// Crear cookie JWT segura
const sendTokenCookie = (res, userId, email) => {
  const token = jwt.sign(
    { id: userId, email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );

  res.cookie('token', token, {
    httpOnly: true,       // No accesible desde JS del cliente
    secure: process.env.NODE_ENV === 'production', // Solo HTTPS en prod
    sameSite: 'strict',  // Protección CSRF
    maxAge: 60 * 60 * 1000 // 1 hora
  });

  return token;
};

// ────────────────────────────────────────────
// POST /api/auth/register
// ────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validaciones básicas de entrada
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Correo y contraseña son requeridos.' });
    }

    // Validar formato de email
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'El correo no tiene un formato válido (ejemplo@dominio.com).' });
    }

    // Validar contraseña
    const passwordErrors = validatePassword(password);
    if (passwordErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: `La contraseña debe tener: ${passwordErrors.join(', ')}.`
      });
    }

    // Verificar si el correo ya existe
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(409).json({ success: false, message: 'Este correo ya está registrado.' });
    }

    // Crear usuario (el hash se hace en el modelo)
    const user = await User.create({ email, password });

    sendTokenCookie(res, user._id, user.email);

    return res.status(201).json({
      success: true,
      message: '¡Cuenta creada exitosamente! Has iniciado sesión.',
      user: { email: user.email }
    });

  } catch (err) {
    console.error('Error en registro:', err.message);
    return res.status(500).json({ success: false, message: 'Error interno del servidor.' });
  }
});

// ────────────────────────────────────────────
// POST /api/auth/login
// ────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Correo y contraseña son requeridos.' });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Formato de correo inválido.' });
    }

    // Buscar usuario incluyendo el password (select: false por defecto)
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password +loginAttempts +lockUntil');

    // Verificar bloqueo de cuenta (máx 5 intentos)
    if (user && user.isLocked()) {
      const remainingMs = user.lockUntil - Date.now();
      const remainingMin = Math.ceil(remainingMs / 60000);
      return res.status(429).json({
        success: false,
        message: `Cuenta bloqueada por demasiados intentos fallidos. Intenta de nuevo en ${remainingMin} minuto(s).`
      });
    }

    // Verificar credenciales — mensaje genérico para no revelar si el usuario existe
    if (!user || !(await user.comparePassword(password))) {
      // Incrementar intentos fallidos si el usuario existe
      if (user) {
        user.loginAttempts += 1;
        if (user.loginAttempts >= 5) {
          user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // bloquear 15 min
          user.loginAttempts = 0;
        }
        await user.save();
      }
      return res.status(401).json({ success: false, message: 'Correo o contraseña incorrectos.' });
    }

    // Login exitoso: resetear intentos
    if (user.loginAttempts > 0 || user.lockUntil) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
      await user.save();
    }

    sendTokenCookie(res, user._id, user.email);

    return res.json({
      success: true,
      message: '¡Sesión iniciada correctamente!',
      user: { email: user.email }
    });

  } catch (err) {
    console.error('Error en login:', err.message);
    return res.status(500).json({ success: false, message: 'Error interno del servidor.' });
  }
});

// ────────────────────────────────────────────
// POST /api/auth/logout
// ────────────────────────────────────────────
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ success: true, message: 'Sesión cerrada correctamente.' });
});

// ────────────────────────────────────────────
// GET /api/auth/me (ruta protegida)
// ────────────────────────────────────────────
router.get('/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    return res.json({ success: true, user: { email: user.email } });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Error interno.' });
  }
});

module.exports = router;
