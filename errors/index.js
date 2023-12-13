class CustomError extends Error {
  constructor(message) {
    super(message);
  }
}

class BadRequest extends CustomError {
  constructor(message) {
    super(message);
    this.statusCode = 400;
  }
}

class Unauthenticated extends CustomError {
  constructor(message) {
    super(message);
    this.statusCode = 401;
  }
}

class Unauthorized extends CustomError {
  constructor(message) {
    super(message);
    this.statusCode = 403;
  }
}

class NotFound extends CustomError {
  constructor(message) {
    super(message);
    this.statusCode = 404;
  }
}

module.exports = {
  BadRequest,
  NotFound,
  Unauthenticated,
  Unauthorized,
  CustomError,
};
