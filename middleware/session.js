const mongoose = require("mongoose");

/**
 * Middleware for handling MongoDB transactions within an Express.js route handler.
 * This middleware creates a session and transaction for the MongoDB operations
 * executed in the route handler. If an error occurs during these operations,
 * the transaction is aborted to ensure data consistency.
 *
 * @param {Function} handler - The route handler function that performs MongoDB operations.
 *                             It should be an async function that accepts standard Express.js
 *                             request and response objects, the next middleware function,
 *                             and a MongoDB session.
 * @returns {Function} A middleware function that can be used in Express.js routes.
 */
module.exports = function sessionTransactionMiddleware(handler) {
  return async (req, res, next) => {
    // Start a new MongoDB session for this request
    const session = await mongoose.startSession();

    // Begin a transaction within this session
    session.startTransaction();
    try {
      // Execute the provided route handler function, passing in the session
      await handler(req, res, next, session);

      // If the handler completes successfully, commit the transaction
      await session.commitTransaction();
    } catch (error) {
      // If an error occurs in the handler, abort the transaction to maintain data integrity
      await session.abortTransaction();

      // Forward the error to the next middleware (typically an error handler)
      next(error);
    } finally {
      // End the session regardless of transaction success or failure
      session.endSession();
    }
  };
};
