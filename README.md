**AuthenticRealm - Node.js Authentication Framework**
AuthenticRealm is a comprehensive solution for handling user authentication and authorization in Node.js applications. It simplifies the process of implementing user registration, login, email verification, password reset, and role-based access control, making it ideal for rapid development.

** search for **Code Examples** for In-depth explanation **

**Features**
User registration and email verification
Secure user login with JWT token management
Password reset functionality
Role-based access control for routes
Extendable and customizable for various use cases
Built-in error handling and middleware support

**Prerequisites**
Node.js (version 12 or higher)
Express
MongoDB set up and running with mongoose package
Sendgrid mailer set up
jsonwebtoken and bcryptjs
Basic understanding of Express.js and Mongoose

**Quick Start**
Install AuthenticRealm

```
npm install authenticrealm
```

\*\*\*\*Environment Setup
Create a .env file in your project root:

```
JWT_SECRET=your_jwt_secret
SENDGRID_API_KEY=your_sendgrid_api_key
```

```
const { authenticateUser } = require('AuthenticRealm');

app.get('/protected', authenticateUser, (req, res) => {
res.send('Protected content');
});
```

**OverView:**
This authentication framework provides a comprehensive solution for handling user authentication and authorization in Node.js applications. It includes support for user registration, login, email verification, password reset, and role-based access control.

**Installation**

npm install authenticrealm

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

**Before you start: Special NOTE**

**EmailService Customization**

In the EmailService class, you need to customize the this.fromEmail and this.origin fields to match your application's details. These fields are used when sending out verification and password reset emails.

**this.fromEmail**: Set this to the email address you wish to use as the sender for your emails. For example: "YourName <youremail@example.com>".
this.origin: This should be set to the base URL of your application. It's used for creating links in the email content, such as verification links or password reset links.

**Customizing Verification and Reset Email URLs**

In the EmailService methods **sendVerificationEmail and sendResetPasswordEmail**, ensure you adjust the URLs in the verifyEmailUrl and resetURL variables to match the routes in your application.

**verifyEmailUrl**: The URL for email verification. It should point to the route in your application that handles email verification.
**resetURL:** The URL for password reset. It should direct the user to the password reset page in your application.

**Usage**

**User Registration:**
\*\*\*\* To register a new user

```
const { RegisterService } = require('AuthenticRealm');
const registerService = new RegisterService(User, EmailService);

// In your route handler
await registerService.registerUser(req.body);
```

**User Login**
\*\*\*\* To authenticate a user:

```
const { AuthService } = require('AuthenticRealm');
const authService = new AuthService();

// In your route handler
const user = await authService.login(email, password, req, res);
```

**UserService Method Example:**

```
// Import UserService
const { UserService } = require('AuthenticRealm');
const userService = new UserService(User);

// In a controller, for updating user details
const updateUserDetails = async (req, res) => {
const updatedUser = await userService.updateUser(req.user.id, req.body.email, req.body.name);
res.status(200).json({ message: "User updated successfully.", user: updatedUser });
};
```

**Protecting Routes**
\*\*\*\* To protect routes using authentication and authorization middleware:

```
const { authenticateUser, authorizePermissions } = require('AuthenticRealm');

router.get('/protected-route', authenticateUser, authorizePermissions('admin'), (req, res) => {
// Protected route logic
});
```

**User verification:**

```
// In your Express route handler
router.post('/verify-email', async (req, res) => {
const { verificationToken, email } = req.body;

const user = await User.findOne({ email });
if (!user) {
throw new Unauthenticated("Email verification failed.");
}
user.verifyEmail(verificationToken);
await user.save();
res.status(200).json({ message: "Email successfully verified." });

});
```

**Pasword Reset Request**:

```
// In your Express route handler
router.post('/forgot-password', async (req, res) => {
const { email } = req.body;

const user = await User.findOne({ email });
if (user) {
const resetToken = user.generatePasswordResetToken();
await user.save();
await EmailService.sendResetPasswordEmail(user, resetToken);
}
res.status(200).json({
message: "If an account with the provided email exists, a password reset link has been sent to it.",
});

});
```

**Resetting Password:**

```
// In your Express route handler
router.post('/reset-password', async (req, res) => {
const { token, email, password } = req.body;

const user = await User.findOne({ email });
if (user) {
await user.resetPassword(token, password);
await user.save();
res.status(200).json({ message: "Your password has been successfully reset." });
}

});
```

**Using Cookies:**

```
// Import cookiesHandler from your framework
const { cookiesHandler } = require('AuthenticRealm');

// In a controller function, after user authentication
const user = ...; // User object after authentication
cookiesHandler({ res, user });

// This sets access and refresh tokens as HTTP-only cookies in the response
```

**Handling Errors:**

```
// Import error classes
const { NotFound, BadRequest, Unauthorized } = require('AuthenticRealm');

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
```

**Using Session Middleware:**

```
// Import sessionTransactionMiddleware
const { sessionTransactionMiddleware } = require('AuthenticRealm');

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
```

**Code Examples:**

**\*Controller example for auth:**

```
// Import necessary services and utilities from the 'authenticrealm' framework.
const {
  AuthService,
  RegisterService,
  EmailService,
  User,
  sessionTransactionMiddleware,
  BadRequest,
} = require("authenticrealm");

// Initialize the RegisterService and AuthService.
// RegisterService is responsible for handling user registration processes.
// AuthService handles login and logout functionalities.
const registerService = new RegisterService(User, EmailService);
const authService = new AuthService();

/**
 * User registration controller wrapped in sessionTransactionMiddleware.
 * This middleware ensures that all database operations within this controller
 * are part of a MongoDB transaction. This is crucial for maintaining data integrity,
 * especially when operations depend on each other (like user creation and email sending).
 */
const register = sessionTransactionMiddleware(
  async (req, res, next, session) => {
    // The registration process is invoked with the request body.
    // The session parameter ensures that this operation is part of the transaction.
    await registerService.registerUser(req.body, session);

    // If the registration process is successful, send a 201 response.
    res.status(201).json({
      msg: "Registration successful. Check your email for verification.",
    });
  }
);

// User login controller.
// This controller does not involve a transaction, as it's a straightforward authentication process.
const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.login(email, password, req, res);
  res.status(200).json({ user, msg: "Login successful." });
};

// User logout controller.
const logout = async (req, res) => {
  // The authService.logout method logs out the user based on their ID.
  await authService.logout(req.user.userId, res);
  res.status(200).json({ msg: "You have been successfully logged out." });
};

// Email verification controller.
// This controller allows users to verify their email address using a token sent to their email.
const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  const user = await User.findByEmailOrFail(email);
  user.verifyEmail(verificationToken);
  await user.save();
  res.status(200).json({ msg: "Email successfully verified." });
};

// Forgot password controller.
// This controller handles the process of sending a password reset link to the user's email.
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new BadRequest("A valid email address is required.");
  }
  const user = await User.findOne({ email });
  // If the user exists, generate a password reset token and send an email with the reset link.
  if (user) {
    const resetToken = user.generatePasswordResetToken();
    await user.save();
    await EmailService.sendResetPasswordEmail(user, resetToken);
  }
  // Send a response indicating that if an account exists, a reset link has been sent.
  res.status(200).json({
    msg: "If an account with the provided email exists, a password reset link has been sent to it.",
  });
};

// Password reset controller.
// This controller handles the actual password resetting using a token provided to the user.
const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    throw new BadRequest("All fields are required to reset the password.");
  }

  // Find the user by email and reset their password using the provided token.
  const user = await User.findOne({ email });
  if (user) {
    await user.resetPassword(token, password);
    await user.save();
    res.status(200).json({ msg: "Your password has been successfully reset." });
  }
};

// Export the controllers to be used in routes.
module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};

```

**Routes example:**

```
const express = require("express");
const router = express.Router();

// Import authentication middleware from 'authenticrealm' framework.
// This middleware is used to ensure that the user is authenticated for certain routes.
const { authenticateUser } = require("authenticrealm");

// Import controllers from the authController.
// These controllers handle the various authentication and user account operations.
const {
  register,
  verifyEmail,
  login,
  resetPassword,
  forgotPassword,
  logout,
} = require("../controller/authController");

// Define routes and associate them with their respective controllers.

// Route for user registration.
router.post("/register", register);

// Route for user login.
router.post("/login", login);

// Route for user logout. The authenticateUser middleware ensures that only logged-in users can access this route.
router.delete("/logout", authenticateUser, logout);

// Route for email verification.
router.post("/verify-email", verifyEmail);

// Route for password reset request (forgot password).
router.post("/forgot-password", forgotPassword);

// Route for resetting the password.
router.post("/reset-password", resetPassword);

// Export the router to be used in the application.
module.exports = router;

```

**User Controller:**

```
// Import necessary services, utilities, and custom errors from the 'authenticrealm' framework.
const {
  User,
  NotFound,
  BadRequest,
  checkPermissions,
  sessionTransactionMiddleware,
  UserService,
} = require("authenticrealm");

// Initialize UserService with the User model to handle user-related operations.
const userService = new UserService(User);

// Controller for getting all users. This controller is typically used by admin users.
const getAllUsers = async (req, res) => {
  const users = await userService.getAllUsers();
  res.status(200).json({ msg: "Users retrieved successfully.", users });
};

// Controller for getting a single user by their ID.
const getSingleUser = async (req, res) => {
  const user = await userService.getSingleUser(req.params.id);
  if (!user) {
    throw new NotFound(`User not found with id: ${req.params.id}`);
  }
  // Check if the authenticated user has permission to access this user's data.
  checkPermissions(req.user, user._id);
  res.status(200).json({ msg: "User retrieved successfully.", user });
};

// Controller to show the currently authenticated user's information.
const showCurrentUser = async (req, res) => {
  res.status(200).json({ msg: "Current user information.", user: req.user });
};

// Controller for updating user details, wrapped in sessionTransactionMiddleware to ensure transactional integrity.
const updateUser = sessionTransactionMiddleware(
  async (req, res, next, session) => {
    const { email, name } = req.body;
    if (!email || !name) {
      throw new BadRequest(
        "Email and name are required for updating user details."
      );
    }
    const updatedUser = await userService.updateUser(
      req.user.userId,
      email,
      name,
      session,
      res
    );
    res
      .status(200)
      .json({ msg: "User details updated successfully.", updatedUser });
  }
);

// Controller for updating the user's password, also wrapped in sessionTransactionMiddleware.
const updateUserPassword = sessionTransactionMiddleware(
  async (req, res, next, session) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      throw new BadRequest("Both old and new passwords should be provided");
    }
    await userService.updateUserPassword(
      req.user.userId,
      oldPassword,
      newPassword,
      session
    );
    res.status(200).json({ msg: "Password updated successfully" });
  }
);

// Export the controllers to be used in the routes file.
module.exports = {
  getAllUsers,
  getSingleUser,
  showCurrentUser,
  updateUser,
  updateUserPassword,
};

```

**User routes example:**

```
const express = require("express");
const router = express.Router();

// Import authentication and authorization middleware from 'authenticrealm'.
const { authenticateUser, authorizePermissions } = require("authenticrealm");

// Import user-related controllers.
const {
  getAllUsers,
  getSingleUser,
  showCurrentUser,
  updateUser,
  updateUserPassword,
} = require("../controller/userController");

// Define user-related routes and associate them with their respective controllers.

// Route to get all users. Accessible only by admin users.
router
  .route("/")
  .get(authenticateUser, authorizePermissions("admin"), getAllUsers);

// Route for the current user to view their own information.
router.route("/myInfo").get(authenticateUser, showCurrentUser);

// Route for the current user to update their details.
router.route("/updateUser").patch(authenticateUser, updateUser);

// Route for the current user to update their password.
router.route("/updateUserPassword").patch(authenticateUser, updateUserPassword);

// Route to get a single user by ID. Requires authentication.
router.route("/:id").get(authenticateUser, getSingleUser);

// Export the router to be used in the main application.
module.exports = router;

```

**User Model Methods:**

**comparePassword(userPassword)**
Purpose: Compares a provided plaintext password with the user's hashed password stored in the database.
Parameters:
userPassword: The plaintext password to compare against the hashed password.
Returns: A boolean value (true if the password matches, false otherwise).
Usage: Often used during the login process to validate a user's password.

**createTokenUser()**
Purpose: Creates a simplified user object suitable for generating JWT payloads. This method excludes sensitive information like the user's password.
Returns: An object containing selected user fields (e.g., name, userId, role).
Usage: Used when creating JWTs to ensure sensitive information is not included in the token.

**createJWT()**
Purpose: Generates a JSON Web Token (JWT) for user authentication.
Returns: A JWT string.
Usage: Called after a successful login or registration to create an access token for the user.

**generateTokens()**
Purpose: Generates both access and refresh tokens for the user.
Returns: An object containing accessToken and refreshToken.
Usage: Utilized during the login and registration process to provide the user with tokens for authentication and session management.

**getCookieOptions(isAccessToken)**
Purpose: Defines cookie options for setting cookies in HTTP responses.
Parameters:
isAccessToken: A boolean indicating if the cookie is for the access token (true) or the refresh token (false).
Returns: Cookie options object.
Usage: Called when setting access and refresh tokens as HTTP-only cookies.

**generateVerificationToken()**
Purpose: Generates a token for email verification.
Modifies: Sets a random token string to the verificationToken field of the user.
Usage: Called during user registration to create a token for verifying the user's email address.

**verifyEmail(token)**
Purpose: Verifies the user's email using a provided token.
Parameters:
token: The verification token to match.
Throws: An error if the token does not match.
Modifies: Updates the user's verification status if the token matches.
Usage: Used in the email verification process.

**generatePasswordResetToken()**
Purpose: Generates a password reset token.
Returns: The generated raw password reset token.
Modifies: Sets a random token string to the passwordToken field and defines its expiration date.
Usage: Called when a user requests a password reset.

**resetPassword(token, newPassword)**
Purpose: Resets the user's password using a provided reset token.
Parameters:
token: The password reset token to be matched.
newPassword: The new password to set for the user.
Throws: An error if the token is invalid or expired.
Modifies: Updates the user's password and clears the password reset token and expiration date.
Usage: Used in the password reset process.

**findByEmailOrFail(email)**
Purpose: Finds a user by email or throws an error if not found.
Parameters:
email: The email address to search for.
Returns: The found user document.
Throws: A NotFound error if no user is found with the given email.
Usage: Useful for operations where a user must be retrieved based on their email, such as during login or password reset.

**Configuration:**
Make sure to configure the necessary environment variables such as 'JWT_SECRET' for JWT token generation and 'SENDGRID_API_KEY'

**Dependencies:**
The framework depends on several npm packages like 'express', 'mongoose', 'jsonwebtoken', '@sendgrid/mail', etc. Ensure therse are installed in your application.

**Support and Contact**
For support or feedback, please contact nextgencodeworks@gmail.com.

**Special Thanks**
A special thanks to **John Smilga** for his invaluable contributions and insights. This package draws inspiration from his code and teachings in the realm of web development. His work has been instrumental in shaping various aspects of this framework.
