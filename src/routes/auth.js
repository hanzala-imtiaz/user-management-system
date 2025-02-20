const express = require("express");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const router = express.Router();
const winston = require("winston");

const failedLoginLogger = winston.createLogger({
  level: "warn",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: "auth-failures.log",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ],
});


router.get("/signup", (req, res) => {
  res.render("signup");
});

router.get("/login", (req, res) => {
  res.render("login");
});

// Signup route
router.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      return res.status(400).send("Email and password are required");
    }

    // Validate inputs
    if (!validator.isEmail(email)) {
      return res.status(400).send("Invalid email");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    const user = new User({ email, password });
    await user.save();
    res.status(201).send("User created");
  } catch (error) {
    res.status(500).send("Error during signup");
  }
});

// Middleware to check if user is authenticated
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect("/api/auth/login");

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) return res.redirect("/api/auth/login");
    req.user = user;
    next();
  });
};

// Profile route
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.render("profile", { user });
  } catch (error) {
    res.redirect("/api/auth/login");
  }
});


const getClientIP = (req) => {
  let ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

  // If running on localhost (::1 or 127.0.0.1), get local network IP
  if (ip === '::1' || ip === '127.0.0.1') {
      const { networkInterfaces } = require('os');
      const nets = networkInterfaces();
      for (const name of Object.keys(nets)) {
          for (const net of nets[name]) {
              if (net.family === 'IPv4' && !net.internal) {
                  ip = net.address; // Use the first non-internal IPv4 address
                  break;
              }
          }
      }
  }
  return ip;
};

// Update login route
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Get the correct IP (works even if behind a proxy)
    const clientIP = getClientIP(req);
    console.log("Client IP:",clientIP);

    const user = await User.findOne({ email });
    if (!user) {
        failedLoginLogger.warn(`Failed login attempt for non-existent user: ${email} from IP: ${clientIP}`);
        return res.status(400).send("Invalid email or password");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        failedLoginLogger.warn(`Failed login attempt for user: ${email} from IP: ${clientIP}`);
        return res.status(400).send("Invalid email or password");
    }

    const token = jwt.sign({ id: user._id }, "your-secret-key");
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/api/auth/profile");
} catch (error) {
    res.status(500).send("Error during login");
}

});

// Logout route
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/api/auth/login");
});

module.exports = router;
