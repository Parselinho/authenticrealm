/**
 * Handles setting authentication tokens as cookies in the HTTP response.
 * This function is used to attach access and refresh tokens to the response object,
 * allowing client-side scripts to securely use these tokens for subsequent requests.
 *
 * @param {Object} param0 - An object containing the response object and the user object.
 * @param {Object} param0.res - The Express response object.
 * @param {Object} param0.user - The user object, typically containing methods to generate tokens and cookie options.
 */
const cookiesHandler = ({ res, user }) => {
  // Generate access and refresh tokens using the user's method
  const { accessToken, refreshToken } = user.generateTokens();

  // Retrieve cookie options for access and refresh tokens
  // 'true' indicates that the options are for the access token, 'false' for the refresh token
  const accessTokenOptions = user.getCookieOptions(true);
  const refreshTokenOptions = user.getCookieOptions(false);

  // Set the access token in an HTTP-only cookie, using the options defined
  res.cookie("accessToken", accessToken, accessTokenOptions);

  // Set the refresh token in an HTTP-only cookie, using the options defined
  res.cookie("refreshToken", refreshToken, refreshTokenOptions);
};

// Export the cookiesHandler function for use in other parts of the application
module.exports = cookiesHandler;
