// Import the CustomError class from the errors module.
const { CustomError } = require("../errors");

/**
 * Error handling middleware for Express applications.
 * This middleware function is responsible for handling errors that occur in the application.
 * It standardizes the error response format and handles specific error types.
 *
 * @param {Object} err - The error object thrown by previous middleware or route handlers.
 * @param {Object} req - The Express request object.
 * @param {Object} res - The Express response object.
 * @param {Function} next - The next middleware function in the Express middleware chain.
 */
const errorHandlerMiddleware = (err, req, res, next) => {
  // Log the error for debugging purposes.
  console.log(err);

  // Initialize a default structure for the custom error response.
  let customError = {
    statusCode: err.statusCode || 500, // Default to 500 if no specific status code is provided.
    msg: err.message || "Something went wrong try again later", // Default error message.
  };
  // Handle Mongoose validation errors (ValidationError).
  // These errors occur when a model validation fails (e.g., required fields missing).
  if (err.name === "ValidationError") {
    customError.msg = Object.values(err.errors)
      .map((item) => item.message) // Extract messages from each validation error.
      .join(","); // Combine all messages into a single string.
    customError.statusCode = 400; // Set status code to 400 for client-side validation errors.
  }

  // Handle Mongoose duplicate key errors (error code 11000).
  // These errors occur when a unique field receives a value that already exists in the database.
  if (err.code && err.code === 11000) {
    customError.msg = `Duplicate value entered for ${Object.keys(
      err.keyValue
    )} field, please choose another value`;
    customError.statusCode = 400; // Set status code to 400 for duplicate key errors.
  }

  // Handle Mongoose CastError.
  // This error typically occurs when an invalid ID is provided for operations like findById.
  if (err.name === "CastError") {
    customError.msg = `No item found with id : ${err.value}`;
    customError.statusCode = 404; // Set status code to 404 when an item is not found.
  }

  // Send the custom error response.
  return res.status(customError.statusCode).json({ msg: customError.msg });
};

// Export the errorHandlerMiddleware to be used in the Express application.
module.exports = errorHandlerMiddleware;
