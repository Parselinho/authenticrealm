// AuthService.js

// Import necessary models and utilities
const User = require("../models/User");
const Token = require("../models/Token");
const crypto = require("crypto");
const cookiesHandler = require("../utils/cookies");
const { Unauthenticated, BadRequest } = require("../errors");

// AuthService class definition
class AuthService {
  /**
   * Handles user login process.
   *
   * @param {String} email - User's email address.
   * @param {String} password - User's password.
   * @param {Object} req - Express request object, used to access request headers.
   * @param {Object} res - Express response object, used to set cookies.
   * @returns {Object} Token-friendly user object.
   * @throws {BadRequest} If email or password is not provided.
   * @throws {Unauthenticated} If credentials are invalid or email is not verified.
   */
  async login(email, password, req, res) {
    // Validate email and password presence
    if (!email || !password) {
      throw new BadRequest("Email and password are required for login.");
    }

    // Retrieve user by email and check password validity
    const user = await User.findByEmailOrFail(email);
    const isPasswordCorrect = await user.comparePassword(password);

    // Check if the provided password is correct
    if (!isPasswordCorrect) {
      throw new Unauthenticated("The provided credentials are incorrect.");
    }

    // Verify if the user's email is verified
    if (!user.isVerified) {
      throw new Unauthenticated("Your email address has not been verified.");
    }

    // Generate a new refresh token
    let refreshToken = crypto.randomBytes(40).toString("hex");
    let existingToken = await Token.findOne({ user: user._id });

    // Update or create the token in the database
    if (existingToken) {
      if (!existingToken.isValid) {
        throw new Unauthenticated(
          "Your authentication credentials have expired."
        );
      }
      existingToken.refreshToken = refreshToken;
      await existingToken.save();
    } else {
      await Token.create({
        user: user._id,
        refreshToken,
        userAgent: req.headers["user-agent"],
        ip: req.ip,
      });
    }

    // Generate an access token and set cookies
    const accessToken = user.createJWT();
    cookiesHandler({ res, user, accessToken, refreshToken });

    return user.createTokenUser();
  }

  /**
   * Handles user logout process.
   *
   * @param {String} userId - ID of the user to log out.
   * @param {Object} res - Express response object, used to clear cookies.
   */
  async logout(userId, res) {
    // Delete the token associated with the user
    await Token.findOneAndDelete({ user: userId });

    // Clear access and refresh tokens from cookies
    res.cookie("accessToken", "logout", {
      httpOnly: true,
      expires: new Date(Date.now()),
    });
    res.cookie("refreshToken", "logout", {
      httpOnly: true,
      expires: new Date(Date.now()),
    });
  }
}

// Export the AuthService class for use in other modules
module.exports = AuthService;
