const jwt = require('jsonwebtoken');

const protect = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ success: false, message: 'No autorizado. Por favor inicia sesión.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.status(401).json({ success: false, message: 'Sesión inválida o expirada. Inicia sesión de nuevo.' });
  }
};

module.exports = { protect };
