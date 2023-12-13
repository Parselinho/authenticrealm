const mongoose = require("mongoose");
const { Schema } = mongoose;

// External libraries for validation and encryption
const validator = require("validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// Custom error classes for handling specific error types
const { Unauthenticated, BadRequest, NotFound } = require("../errors");

/**
 * Schema definition for the User model.
 * This schema defines the structure and rules for user data in the database.
 */
const UserSchema = new Schema({
  // User's name field with minimum and maximum length validations
  name: {
    type: String,
    trim: true,
    required: [true, "Please provide name"],
    minlength: 3,
    maxlength: 50,
  },
  // User's email field with uniqueness and format validation
  email: {
    type: String,
    trim: true,
    unique: true,
    required: [true, "Please provide email"],
    validate: {
      validator: validator.isEmail,
      message: "Please provide valid email",
    },
  },
  // User's password field with minimum length validation
  password: {
    type: String,
    required: [true, "Please provide password"],
    minlength: 6,
  },
  // User's role field with predefined values (enum)
  role: {
    type: String,
    enum: ["admin", "user"],
    default: "user",
  },
  // Token used for email verification
  verificationToken: String,
  // Flag indicating whether the email is verified
  isVerified: {
    type: Boolean,
    default: false,
  },
  // Timestamp indicating when the email was verified
  verified: Date,
  // Token used for password reset
  passwordToken: {
    type: String,
  },
  // Expiration date for the password reset token
  passwordTokenExpirationDate: {
    type: Date,
  },
});

/**
 * Pre-save middleware for hashing the user's password.
 * Automatically called before saving a User document to the database.
 */
UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

/**
 * Instance method to compare a provided password with the user's hashed password.
 * @param {String} userPassword - Password to be compared.
 * @returns {Boolean} True if the password matches, false otherwise.
 */
UserSchema.methods.comparePassword = async function (userPassword) {
  return await bcrypt.compare(userPassword, this.password);
};

/**
 * Instance method to create a token-friendly user object.
 * Used to generate JWT payload and other purposes where sensitive data is excluded.
 * @returns {Object} A user object with selected fields.
 */
UserSchema.methods.createTokenUser = function () {
  return { name: this.name, userId: this._id, role: this.role };
};

/**
 * Instance method to create a JSON Web Token (JWT) for user authentication.
 * @returns {String} A JWT string.
 */
UserSchema.methods.createJWT = function () {
  const payload = { user: this.createTokenUser() };
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_LIFETIME,
  });
};

/**
 * Instance method to generate both access and refresh tokens for the user.
 * @returns {Object} An object containing accessToken and refreshToken.
 */
UserSchema.methods.generateTokens = function () {
  const tokenUser = this.createTokenUser();
  const accessToken = jwt.sign({ user: tokenUser }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_LIFETIME,
  });
  const refreshToken = jwt.sign({ user: tokenUser }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_LONGERLIFETIME,
  });
  return { accessToken, refreshToken };
};

/**
 * Instance method to define cookie options for setting cookies in responses.
 * @param {Boolean} isAccessToken - Flag to determine cookie expiration based on token type.
 * @returns {Object} Cookie options.
 */
UserSchema.methods.getCookieOptions = function (isAccessToken = true) {
  return {
    httpOnly: true,
    expires: new Date(
      Date.now() +
        (isAccessToken ? 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000)
    ),
    secure: process.env.NODE_ENV === "production",
    signed: true,
  };
};

/**
 * Instance method to generate a token for email verification.
 * Sets a random token string to the verificationToken field of the user.
 */
UserSchema.methods.generateVerificationToken = function () {
  this.verificationToken = crypto.randomBytes(40).toString("hex");
};

/**
 * Instance method to verify the email using a provided token.
 * @param {String} token - The verification token to be matched.
 * Throws an error if the token does not match or updates the user's verification status.
 */
UserSchema.methods.verifyEmail = function (token) {
  if (token !== this.verificationToken) {
    throw new Unauthenticated("Verification Failed");
  }
  this.isVerified = true;
  this.verified = Date.now();
  this.verificationToken = "";
};

/**
 * Instance method to generate a password reset token.
 * Sets a random token string to the passwordToken field and defines its expiration date.
 * @returns {String} The generated raw password reset token.
 */
UserSchema.methods.generatePasswordResetToken = function () {
  const rawToken = crypto.randomBytes(70).toString("hex");
  this.passwordToken = rawToken;
  const fifteenMinutes = 1000 * 60 * 15;
  this.passwordTokenExpirationDate = new Date(Date.now() + fifteenMinutes);
  return rawToken;
};

/**
 * Instance method to reset the user's password.
 * @param {String} token - The password reset token to be matched.
 * @param {String} newPassword - The new password to be set for the user.
 * Verifies the token and sets the new password if valid.
 */
UserSchema.methods.resetPassword = async function (token, newPassword) {
  const currentDate = new Date();
  if (
    this.passwordToken !== token ||
    this.passwordTokenExpirationDate < currentDate
  ) {
    throw new BadRequest("Invalid Credentials");
  }
  this.password = newPassword;
  this.passwordToken = null;
  this.passwordTokenExpirationDate = null;
};

/**
 * Static method to find a user by email or throw a NotFound error if not found.
 * @param {String} email - The email to search for.
 * @returns {Document} The found user document.
 */
UserSchema.statics.findByEmailOrFail = async function (email) {
  const user = await this.findOne({ email });
  if (!user) {
    throw new NotFound("User Not Found");
  }
  return user;
};

// Export the User model with the defined schema
module.exports = mongoose.model("User", UserSchema);
