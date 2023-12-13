const jwt = require("jsonwebtoken");
const { Unauthorized, Unauthenticated } = require("../errors");
const Token = require("../models/Token");
const { User } = require("../models/User");
const cookiesHandler = require("../utils/cookies");

/**
 * Middleware to authenticate a user based on JWT tokens.
 * This function checks for valid JWT tokens in the request's signed cookies
 * and verifies the user's identity.
 *
 * @param {Object} req - The Express request object.
 * @param {Object} res - The Express response object.
 * @param {Function} next - The next middleware function in the Express middleware chain.
 */
const authenticateUser = async (req, res, next) => {
  // Extracts refreshToken and accessToken from signed cookies
  const { refreshToken, accessToken } = req.signedCookies;

  let payload;
  let user;

  // Process the access token if it exists
  if (accessToken) {
    try {
      // Decode the accessToken to get the payload
      payload = jwt.verify(accessToken, process.env.JWT_SECRET);
    } catch (error) {
      // If token verification fails, throw an Unauthenticated error
      throw new Unauthenticated(
        "Access denied. No user found with provided credentials."
      );
    }

    // Find the user in the database based on userId in the payload
    user = await User.findById(payload.user.userId);
    if (!user) {
      // If no user is found, throw an Unauthenticated error
      throw new Unauthenticated(
        "Access denied. No user found with provided credentials."
      );
    }

    // Attach the user details to the request object
    req.user = user.createTokenUser();
    return next();
  }

  // Process the refresh token if it exists
  if (refreshToken) {
    try {
      // Decode the refreshToken to get the payload
      payload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    } catch (error) {
      // If token verification fails, throw an Unauthenticated error
      throw new Unauthenticated(
        "Access denied. No user found with provided credentials."
      );
    }

    // Find the token document in the database
    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken,
    });

    if (!existingToken || !existingToken.isValid) {
      // If token is not valid, throw an Unauthenticated error
      throw new Unauthenticated(
        "Access denied. No user found with provided credentials."
      );
    }

    // Find the user in the database based on userId in the payload
    user = await User.findById(payload.user.userId);
    // Refresh the cookies with new tokens using cookiesHandler utility
    cookiesHandler({ res, user });
    // Attach the user details to the request object
    req.user = user.createTokenUser();
    return next();
  }

  // If neither accessToken nor refreshToken are valid, throw an Unauthenticated error
  throw new Unauthenticated(
    "Access denied. No user found with provided credentials."
  );
};

/**
 * Middleware to authorize user based on their roles.
 * It allows access only to users who have one of the specified roles.
 *
 * @param {...String} roles - A list of roles that are authorized to access the route.
 * @returns {Function} A middleware function that checks the user's role.
 */
const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      // If the user's role is not in the list of authorized roles, throw an Unauthorized error
      throw new Unauthorized("Access forbidden. Insufficient permissions.");
    }
    // If the user's role is authorized, proceed to the next middleware
    next();
  };
};

// Export the authentication and authorization middleware
module.exports = {
  authenticateUser,
  authorizePermissions,
};
