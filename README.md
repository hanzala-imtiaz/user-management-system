# User Management System

## Description
The **User Management System** is a simple web application designed for **security testing** in user authentication. It allows users to **sign up, log in, and manage their profiles** securely. This project follows best security practices, including **password hashing, JWT authentication, and logging mechanisms**.

## Features
- **User Authentication:** Secure user signup and login with password hashing (bcrypt).
- **JWT-based Authentication:** Uses JSON Web Tokens for session management.
- **Secure Password Storage:** Passwords are hashed using bcrypt before storing in the database.
- **Logging & Monitoring:** Winston logging for tracking user activity.
- **Security Best Practices:** Uses Helmet to protect against common vulnerabilities.
- **MongoDB Integration:** User data is stored securely in a MongoDB database.
- **EJS Templating Engine:** Provides dynamic rendering of views.
- **Session Management:** Users can log in, access a protected profile page, and log out securely.

## Technologies Used
- **Backend:** Node.js, Express.js
- **Database:** MongoDB (Mongoose ORM)
- **Authentication:** JWT (JSON Web Token), bcrypt
- **Security:** Helmet, cookie-parser, validator
- **Templating Engine:** EJS
- **Logging:** Winston

## Installation

### Prerequisites
- Node.js installed (v14 or higher recommended)
- MongoDB database (local or cloud-based)

### Setup Instructions
1. **Clone the repository:**
   ```bash
   git clone https://github.com/hanzalah-imtiaz/user-management-system.git
   cd user-management-system
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   Create a `.env` file in the root directory and add:
   ```env
  MONGO_URI=mongodb+srv://your-username:your-password@cluster0.mongodb.net/
   JWT_SECRET=your-secret-key
   ```

4. **Run the application:**
   ```bash
   npm start
   ```
   or for development mode:
   ```bash
   npm run dev
   ```

5. **Access the application:**
   - Open `http://localhost:3000/` in your browser.

## API Endpoints

### Authentication Routes
| Method | Endpoint         | Description |
|--------|----------------|-------------|
| GET    | `/api/auth/signup` | Render signup page |
| POST   | `/api/auth/signup` | Register a new user |
| GET    | `/api/auth/login`  | Render login page |
| POST   | `/api/auth/login`  | Authenticate user and issue JWT |
| GET    | `/api/auth/profile` | Access protected user profile (JWT required) |
| GET    | `/api/auth/logout`  | Logout user |

## Security Features Implemented
- **Password Hashing:** Ensures secure password storage using bcrypt.
- **JWT Authentication:** Ensures only authenticated users can access protected routes.
- **Helmet Middleware:** Helps secure HTTP headers to protect against common attacks.
- **Input Validation:** Uses validator.js to sanitize and validate user inputs.
- **Logging Mechanism:** Winston tracks login attempts and other key activities.
