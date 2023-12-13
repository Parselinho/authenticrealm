// Import utilities
const { cookiesHandler } = require("../utils/cookies");
const { BadRequest, Unauthenticated } = require("../errors");

/**
 * Class to handle user-related operations.
 * This service encapsulates the business logic for managing users.
 */
class UserService {
  /**
   * Constructs the UserService.
   * @param {Model} userModel - Mongoose model representing the User.
   */
  constructor(userModel) {
    this.User = userModel;
  }

  /**
   * Retrieves all users with the role 'user', excluding their password and verification token.
   * @returns {Promise<Array>} A promise that resolves to an array of user objects.
   */
  async getAllUsers() {
    return await this.User.find({ role: "user" }).select(
      "-password -verificationToken"
    );
  }

  /**
   * Retrieves a single user by their ID, excluding their password.
   * @param {String} userId - The ID of the user to retrieve.
   * @returns {Promise<Object>} A promise that resolves to the user object.
   */
  async getSingleUser(userId) {
    return await this.User.findOne({ _id: userId }).select("-password");
  }

  /**
   * Updates a user's email and name. If the user's details have changed, it also handles token generation and sets cookies.
   * @param {String} userId - The ID of the user to update.
   * @param {String} email - The new email of the user.
   * @param {String} name - The new name of the user.
   * @param {Object} session - The current Mongoose session for transaction management.
   * @param {Object} res - The Express response object, used for setting cookies.
   * @returns {Promise<Object>} A promise that resolves to the updated user object.
   * @throws {BadRequest} If no changes are made to the user's email or name.
   */
  async updateUser(userId, email, name, session, res) {
    const user = await this.User.findOne({ _id: userId }).session(session);
    if (user.email === email && user.name === name) {
      throw new BadRequest("No changes is made");
    }
    user.email = email;
    user.name = name;
    await user.save();

    // Token generation and cookie setting
    const tokens = user.generateTokens();
    const { accessToken, refreshToken } = tokens;
    cookiesHandler({ res, user, accessToken, refreshToken });

    return user;
  }

  /**
   * Updates a user's password after verifying their old password.
   * @param {String} userId - The ID of the user whose password is being updated.
   * @param {String} oldPassword - The current password of the user.
   * @param {String} newPassword - The new password to set for the user.
   * @param {Object} session - The current Mongoose session for transaction management.
   * @returns {Promise<Object>} A promise that resolves to the updated user object.
   * @throws {Unauthenticated} If the old password is incorrect.
   */
  async updateUserPassword(userId, oldPassword, newPassword, session) {
    const user = await this.User.findOne({ _id: userId }).session(session);
    const isPasswordCorrect = await user.comparePassword(oldPassword);
    if (!isPasswordCorrect) {
      throw new Unauthenticated("Invalid Credentials");
    }
    user.password = newPassword;
    await user.save();
    return user;
  }
}

// Export the UserService class for use in other parts of the application
module.exports = UserService;
