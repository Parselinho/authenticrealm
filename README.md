**AuthenticRealm - Node.js Authentication Framework**
AuthenticRealm is a comprehensive solution for handling user authentication and authorization in Node.js applications. It simplifies the process of implementing user registration, login, email verification, password reset, and role-based access control, making it ideal for rapid development.

**Features**
User registration and email verification
Secure user login with JWT token management
Password reset functionality
Role-based access control for routes
Extendable and customizable for various use cases
Built-in error handling and middleware support

**Prerequisites**
Node.js (version 12 or higher)
MongoDB set up and running
Sendgrid mailer set up
Basic understanding of Express.js and Mongoose

**Quick Start**
Install AuthenticRealm

npm install AuthenticRealm

\*\*\*\*Environment Setup
Create a .env file in your project root:

JWT_SECRET=your_jwt_secret
SENDGRID_API_KEY=your_sendgrid_api_key

const { authenticateUser } = require('AuthenticRealm');

app.get('/protected', authenticateUser, (req, res) => {
res.send('Protected content');
});

**OverView:**
This authentication framework provides a comprehensive solution for handling user authentication and authorization in Node.js applications. It includes support for user registration, login, email verification, password reset, and role-based access control.

**Installation**

npm install AuthenticRealm

**Components**

**Error Handling**
CustomError: Base class for custom errors.
BadRequest: Error for bad request (Status Code: 400).
Unauthenticated: Error for unauthenticated access (Status Code: 401).
Unauthorized: Error for unauthorized access (Status Code: 403).
NotFound: Error for not found resources (Status Code: 404).

**Middleware**
authenticateUser: Middleware to authenticate a user based on JWT tokens.
authorizePermissions: Middleware to authorize user based on their roles.
errorHandlerMiddleware: Middleware for handling errors in Express applications.
notFound: Middleware to handle 404 Not Found errors.
sessionTransactionMiddleware: Middleware for handling MongoDB transactions.

**Models**
User: Mongoose model for users.
Token: Mongoose model for storing refresh tokens.

**Services**
AuthService: Service for handling user login and logout processes.
UserService: Service for managing user data and operations.
RegisterService: Service for handling user registration.
EmailService: Service for sending emails using SendGrid.

**Utilities**
checkPermissions: Utility function to check user permissions.
cookiesHandler: Utility function to handle setting authentication tokens as cookies.

**Usage**

**User Registration:**
\*\*\*\* To register a new user
const { RegisterService } = require('AuthenticRealm');
const registerService = new RegisterService(User, EmailService);

// In your route handler
await registerService.registerUser(req.body);

**User Login**
\*\*\*\* To authenticate a user:

const { AuthService } = require('AuthenticRealm');
const authService = new AuthService();

// In your route handler
const user = await authService.login(email, password, req, res);

**UserService Method Example:**
// Import UserService
const { UserService } = require('authframework');
const userService = new UserService(User);

// In a controller, for updating user details
const updateUserDetails = async (req, res) => {
const updatedUser = await userService.updateUser(req.user.id, req.body.email, req.body.name);
res.status(200).json({ message: "User updated successfully.", user: updatedUser });
};

**Protecting Routes**
\*\*\*\* To protect routes using authentication and authorization middleware:
const { authenticateUser, authorizePermissions } = require('authframework');

router.get('/protected-route', authenticateUser, authorizePermissions('admin'), (req, res) => {
// Protected route logic
});

**User verification:**
// In your Express route handler
router.post('/verify-email', async (req, res) => {
const { verificationToken, email } = req.body;
try {
const user = await User.findOne({ email });
if (!user) {
throw new Unauthenticated("Email verification failed.");
}
user.verifyEmail(verificationToken);
await user.save();
res.status(200).json({ message: "Email successfully verified." });
} catch (error) {
res.status(500).json({ message: error.message });
}
});

**Pasword Reset Request**:
// In your Express route handler
router.post('/forgot-password', async (req, res) => {
const { email } = req.body;
try {
const user = await User.findOne({ email });
if (user) {
const resetToken = user.generatePasswordResetToken();
await user.save();
await EmailService.sendResetPasswordEmail(user, resetToken);
}
res.status(200).json({
message: "If an account with the provided email exists, a password reset link has been sent to it.",
});
} catch (error) {
res.status(500).json({ message: error.message });
}
});

**Resetting Password:**
// In your Express route handler
router.post('/reset-password', async (req, res) => {
const { token, email, password } = req.body;
try {
const user = await User.findOne({ email });
if (user) {
await user.resetPassword(token, password);
await user.save();
res.status(200).json({ message: "Your password has been successfully reset." });
}
} catch (error) {
res.status(500).json({ message: error.message });
}
});

**Using Cookies:**
// Import cookiesHandler from your framework
const { cookiesHandler } = require('authframework');

// In a controller function, after user authentication
const user = ...; // User object after authentication
cookiesHandler({ res, user });

// This sets access and refresh tokens as HTTP-only cookies in the response

**Handling Errors:**
// Import error classes
const { NotFound, BadRequest, Unauthorized } = require('authframework');

// In a controller function
const getUser = async (req, res) => {
const user = await User.findById(req.params.id);
if (!user) {
throw new NotFound("User not found.");
}

    // Check for other conditions
    if (someBadRequestCondition) {
        throw new BadRequest("Invalid request data.");
    }

    // Check for permissions
    if (!user.isAdmin) {
        throw new Unauthorized("Access denied.");
    }

    res.status(200).json({ user });

};

**Using Session Middleware:**
// Import sessionTransactionMiddleware
const { sessionTransactionMiddleware } = require('authframework');

// Wrap your controller logic
const updateUser = sessionTransactionMiddleware(
async (req, res, next, session) => {
// Use session in your database operations
const updatedUser = await User.findByIdAndUpdate(req.user.id, { name: req.body.name }, { new: true, session });
res.status(200).json({ message: "User updated successfully.", user: updatedUser });
}
);

// Use 'updateUser' in your route definition
router.patch('/user/update', authenticateUser, updateUser);

**Configuration:**
Make sure to configure the necessary environment variables such as 'JWT_SECRET' for JWT token generation and 'SENDGRID_API_KEY'

**Dependencies:**
The framework depends on several npm packages like 'express', 'mongoose', 'jsonwebtoken', '@sendgrid/mail', etc. Ensure therse are installed in your application.

**Support and Contact**
For support or feedback, please contact nextgencodeworks@gmail.com.