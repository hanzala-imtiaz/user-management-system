const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const authRoutes = require("./routes/auth");
const winston = require("winston");
const path = require("path");
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));

// Routes
app.get("/", (req, res) => {
  res.render("index"); // Render the index.ejs file
});

// Middleware
app.use(express.json());
app.use(helmet());
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
  .connect("mongodb+srv://hanzalahimtiaz:112233xx@cluster0.kbaev.mongodb.net/")
  .then(() => logger.info("Connected to MongoDB"))
  .catch((err) => logger.error("Failed to connect to MongoDB", err));

// Routes
app.use("/api/auth", authRoutes);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});
