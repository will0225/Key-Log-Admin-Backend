// authMiddleware.js
const jwt = require('jsonwebtoken');
require('dotenv').config();

const authenticateToken = (req, res, next) => {
  // Get token from authorization header
  const token = req.header('Authorization'); // "Bearer token"

  if (!token) {
    return res.status(403).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token.' });
      }

      // Attach user information to the request object
      req.user = user;
      next(); // Proceed to the next middleware or route handler
    });
  } catch (error) {
    return res.status(500).json({ message: 'Server error' });
  }
};

module.exports = authenticateToken;
