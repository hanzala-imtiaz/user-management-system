const express = require("express");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const router = express.Router();
const logger = require("winston");

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
    logger.info(`New user signed up: ${email}`);
    res.status(201).send("User created");
  } catch (error) {
    logger.error(`Signup error: ${error.message}`);
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
    logger.error(`Profile error: ${error.message}`);
    res.redirect("/api/auth/login");
  }
});

// Update login route
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send("Invalid email or password");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send("Invalid email or password");
    }

    const token = jwt.sign({ id: user._id }, "your-secret-key");
    res.cookie("token", token, { httpOnly: true });
    logger.info(`User logged in: ${email}`);
    res.redirect("/api/auth/profile");
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).send("Error during login");
  }
});

// Logout route
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/api/auth/login");
});

module.exports = router;
