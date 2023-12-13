const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Schema definition for the Token model.
 * This schema is used to store tokens for user authentication, especially for refresh tokens.
 * It includes details about the token itself, the user's IP and user agent to track the origin of the token,
 * and a flag to indicate if the token is valid.
 */
const TokenSchema = new Schema(
  {
    // The actual refresh token string.
    // This is a unique string used to validate user sessions and generate new access tokens.
    refreshToken: { type: String, required: true },

    // The IP address from which the token was requested/generated.
    // Storing the IP can be useful for security and auditing purposes.
    ip: { type: String, required: true },

    // The user agent (browser or device information) from which the token was requested.
    // This helps in identifying where (which device or browser) the token was used.
    userAgent: { type: String, required: true },

    // A flag to indicate whether the token is currently valid.
    // This allows for tokens to be invalidated for security reasons without deleting them from the database.
    isValid: { type: Boolean, default: true },

    // Reference to the User model.
    // This associates the token with a specific user.
    user: {
      type: mongoose.Types.ObjectId, // ObjectID of the user to whom this token belongs.
      ref: "User", // Reference to the User model.
      required: true, // Every token must be associated with a user.
    },
  },
  {
    timestamps: true, // Automatically add createdAt and updatedAt timestamps.
  }
);

// Export the model, allowing it to be used in other parts of the application.
module.exports = mongoose.model("Token", TokenSchema);
