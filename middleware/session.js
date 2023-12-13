const mongoose = require("mongoose");

/**
 * Middleware for handling MongoDB transactions in an Express application.
 * This function wraps a handler function in a MongoDB session and transaction,
 * ensuring that all database operations within the handler are part of a single transaction.
 *
 * @param {Function} handler - The handler function to be wrapped in a transaction.
 *                             This function is expected to be an async function
 *                             accepting the Express request (req), response (res),
 *                             next middleware function (next), and the MongoDB session (session).
 * @returns {Function} An Express middleware function.
 */
function sessionTransactionMiddleware(handler) {
  return async (req, res, next) => {
    // Start a new MongoDB session
    const session = await mongoose.startSession();
    try {
      // Start a transaction within this session
      await session.startTransaction();

      // Execute the handler function, passing the MongoDB session along with standard Express parameters
      await handler(req, res, next, session);

      // Commit the transaction if the handler executes successfully
      await session.commitTransaction();
    } catch (error) {
      // Abort the transaction in case of any errors during handler execution
      await session.abortTransaction();

      // Respond with an error status and message
      res.status(500).json({ msg: error.message });
    } finally {
      // End the session whether the transaction was successful or not
      await session.endSession();
    }
  };
}

// Export the middleware for use in other parts of the application
module.exports = sessionTransactionMiddleware;
