const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const authRoutes = require("./routes/auth");
const winston = require("winston");
const path = require("path");
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const csurf = require("csurf");
const dotenv = require("dotenv")


dotenv.config()

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const corsOptions = {
  origin: 'https://localhost:3000',
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});

app.use(limiter);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));

// Routes
app.get("/", (req, res) => {
  res.render("index"); // Render the index.ejs file
});

// Middleware
app.use(express.json());
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"], // Allow resources only from the same origin
        scriptSrc: ["'self'", "'unsafe-inline'", "https://trusted-cdn.com"], // Allow scripts from self and a trusted CDN
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow styles from self and inline styles
        imgSrc: ["'self'", "data:"], // Allow images from self and base64
        connectSrc: ["'self'"], // Restrict AJAX/WebSocket connections
        frameAncestors: ["'none'"], // Prevent embedding in iframes (Clickjacking protection)
        objectSrc: ["'none'"], // Block Flash & other plugins
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
  })
);

app.use(cookieParser());

// Logging setup
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    }), 
    new winston.transports.File({ 
      filename: "user-activity.log",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ],
});

// Add logging middleware
app.use((req, res, next) => {
  if (req.path.startsWith('/api/auth')) {
    logger.info(`Auth request: ${req.method} ${req.path}`);
  }
  next();
});

// Database connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => logger.info("Connected to MongoDB"))
  .catch((err) => logger.error("Failed to connect to MongoDB", err));

// Routes
app.use("/api/auth", authRoutes);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});
