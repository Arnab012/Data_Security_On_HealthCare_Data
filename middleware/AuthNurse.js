const jwt = require("jsonwebtoken");

const User = require("../models/Nurse");

const authenticateTokens = async (req, res, next) => {
  try {
    // Get the JWT token from the Authorization header
    const { token } = req.cookies;
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access token is missing.",
      });
    }

    // Verify the token
    const decoded = jwt.verify(token, "your-secret-key");
    req.user = await User.findById(decoded.userId);
    next();
  } catch (error) {
    console.error(error);
    res.status(403).json({
      success: false,
      message: "Invalid token.",
    });
  }
};

module.exports = authenticateTokens;
