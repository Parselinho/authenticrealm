const { Unauthorized } = require("../errors");

/**
 * Checks if the requesting user has the necessary permissions to access a resource.
 * This function ensures that either the user has an 'admin' role or is the owner of the resource.
 *
 * @param {Object} requestUser - The user object extracted from the request, typically after authentication.
 * @param {String|Object} resourceUserId - The user ID associated with the resource being accessed.
 *                              This could be the creator or owner of the resource.
 * @throws {UnauthorizedError} - Throws an UnauthorizedError if the user does not have permission.
 */
const checkPermissions = (requestUser, resourceUserId) => {
  // Grant access if the requesting user has an 'admin' role
  if (requestUser.role === "admin") return;

  // Grant access if the requesting user's ID matches the resource's user ID
  // The toString() method is used to ensure both IDs are compared as strings
  if (requestUser.userId === resourceUserId.toString()) return;

  // If neither condition is met, throw an UnauthorizedError
  throw new Unauthorized("You do not have permission to perform this action.");
};

// Export the checkPermissions function for use in other parts of the application
module.exports = checkPermissions;
