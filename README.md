User Management System

Description

The User Management System is a secure web application designed for user authentication and security testing. It allows users to sign up, log in, and manage their profiles securely while adhering to industry best practices. This project includes robust security measures such as password hashing, JWT authentication, logging mechanisms, intrusion detection, and API security hardening.

Features

User Authentication: Secure user signup and login with password hashing (bcrypt).

JWT-based Authentication: Implements JSON Web Tokens for session management.

Secure Password Storage: Uses bcrypt to hash passwords before storing them.

Logging & Monitoring: Utilizes Winston for activity logging and Fail2Ban for intrusion detection.

Intrusion Detection: Configured Fail2Ban to monitor and block multiple failed login attempts.

Security Best Practices: Implements security headers using Helmet and Content Security Policy (CSP).

API Security Hardening:

Implemented rate limiting using express-rate-limit to prevent brute-force attacks.

Configured CORS properly to restrict cross-origin requests.

Integrated API key authentication for added security.

MongoDB Integration: Securely stores user data in a MongoDB database.

EJS Templating Engine: Enables dynamic rendering of views.

Session Management: Securely manages user sessions with JWT authentication and logout functionality.

Technologies Used

Backend: Node.js, Express.js

Database: MongoDB (Mongoose ORM)

Authentication: JWT (JSON Web Token), bcrypt

Security: Helmet, cookie-parser, validator, Fail2Ban, express-rate-limit, CORS

Templating Engine: EJS

Logging: Winston

Installation

Prerequisites

Node.js installed (v14 or higher recommended)

MongoDB database (local or cloud-based)

Setup Instructions

Clone the repository:

git clone https://github.com/hanzalah-imtiaz/user-management-system.git
cd user-management-system

Install dependencies:

npm install

Set up environment variables:
Create a .env file in the root directory and add:

MONGO_URI=mongodb+srv://your-username:your-password@cluster0.mongodb.net/
JWT_SECRET=your-secret-key
API_KEY=your-api-key

Run the application:

npm start

or for development mode:

npm run dev

Access the application:
Open http://localhost:3000/ in your browser.

API Endpoints

Authentication Routes

Method

Endpoint

Description

GET

/api/auth/signup

Render signup page

POST

/api/auth/signup

Register a new user

GET

/api/auth/login

Render login page

POST

/api/auth/login

Authenticate user and issue JWT

GET

/api/auth/profile

Access protected user profile (JWT required)

GET

/api/auth/logout

Logout user

Security Features Implemented

Password Hashing: Ensures secure password storage using bcrypt.

JWT Authentication: Provides token-based authentication for secure access.

Helmet Middleware: Protects against common web vulnerabilities.

Content Security Policy (CSP): Mitigates script injection attacks.

HSTS (HTTP Strict Transport Security): Enforces secure HTTPS connections.

Rate Limiting: Protects against brute-force attacks using express-rate-limit.

CORS Configuration: Restricts cross-origin requests for enhanced security.

API Key Authentication: Adds an extra layer of security to API access.

Logging Mechanism: Winston logs login attempts and security events.

Intrusion Detection: Fail2Ban monitors and blocks repeated failed login attempts.

Contributing

Contributions are welcome! If you'd like to improve the security or functionality of this project, please fork the repository and submit a pull request.

Maintained by: Hanzalah Imtiaz

