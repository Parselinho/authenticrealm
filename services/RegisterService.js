const { BadRequest } = require("../errors");
/**
 * RegisterService class to handle user registration logic.
 * This class encapsulates the functionality for registering a new user,
 * including checks for existing users and sending verification emails.
 */
class RegisterService {
  /**
   * RegisterService constructor.
   * @param {Model} UserModel - Mongoose model representing the User.
   * @param {Object} EmailService - Service for handling email operations.
   */
  constructor(UserModel, EmailService) {
    this.User = UserModel;
    this.EmailService = EmailService;
  }

  /**
   * Registers a new user.
   * @param {Object} param0 - An object containing the user's name, email, and password.
   * @param {String} param0.name - The user's name.
   * @param {String} param0.email - The user's email address.
   * @param {String} param0.password - The user's password.
   * @param {Object} session - Mongoose session for transactional operations.
   * @returns {Object} The created user object.
   * @throws {BadRequest} If the email already exists in the database.
   */
  async registerUser({ name, email, password }, session) {
    // Check if a user with the given email already exists
    const emailAlreadyExist = await this.User.findOne({ email }).session(
      session
    );
    if (emailAlreadyExist) {
      throw new BadRequest("User already exists");
    }

    // Determine if the new account is the first account, assigning 'admin' role if true
    const isFirstAccount =
      (await this.User.countDocuments({}).session(session)) === 0;
    const role = isFirstAccount ? "admin" : "user";

    // Create a new user with the provided details
    const user = new this.User({ name, email, password, role });
    // Generate a verification token for the user
    user.generateVerificationToken();
    // Save the new user to the database within the session
    await user.save({ session });

    // Send a verification email to the new user
    await this.EmailService.sendVerificationEmail(user);
    return user;
  }
}

// Export the RegisterService class to be used elsewhere in the application
module.exports = RegisterService;
