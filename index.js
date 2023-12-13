require("dotenv").config();
require("express-async-errors");
const AuthService = require("./services/AuthService");
const UserService = require("./services/UserService");
const RegisterService = require("./services/RegisterService");
const EmailService = require("./services/EmailService");
const User = require("./models/User");
const Token = require("./models/Token");
const checkPermissions = require("./utils/checkPermissions");
const cookiesHandler = require("./utils/cookies");
const { authenticateUser, authorizePermissions } = require("./middleware/auth");
const errorHandlerMiddleware = require("./middleware/errorHandler");
const notFound = require("./middleware/notFound");
const sessionTransactionMiddleware = require("./middleware/session");
const {
  BadRequest,
  NotFound,
  Unauthenticated,
  Unauthorized,
  CustomError,
} = require("./errors");

module.exports = {
  AuthService,
  UserService,
  RegisterService,
  EmailService,
  User,
  Token,
  checkPermissions,
  cookiesHandler,
  authenticateUser,
  authorizePermissions,
  errorHandlerMiddleware,
  notFound,
  sessionTransactionMiddleware,
  BadRequest,
  NotFound,
  Unauthenticated,
  Unauthorized,
  CustomError,
};
