const sgMail = require("@sendgrid/mail");
const { CustomError } = require("../errors");

/**
 * EmailService class to handle email operations using SendGrid.
 * This class encapsulates the functionality for sending different types of emails,
 * such as verification emails and password reset emails.
 */
class EmailService {
  /**
   * EmailService constructor.
   * Initializes the SendGrid mail service with an API key and sets default parameters.
   */
  constructor() {
    // Set the API key for SendGrid mail service
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);

    // Default sender email address
    this.fromEmail = "NextGen Code <nextgencodeworks@gmail.com>";

    // Base URL for the application, used for creating email links
    this.origin = "http://localhost:3000";
  }

  /**
   * Sends an email using the SendGrid service.
   * @param {Object} param0 - An object containing the recipient, subject, and HTML content.
   * @param {String} param0.to - The recipient's email address.
   * @param {String} param0.subject - The subject of the email.
   * @param {String} param0.html - The HTML content of the email.
   */
  async sendEmail({ to, subject, html }) {
    try {
      const msg = {
        from: this.fromEmail,
        to,
        subject,
        html,
      };
      // Send the email using SendGrid
      await sgMail.send(msg);
    } catch (error) {
      console.error("error sending email:", error);
      throw new CustomError("Failed to send email.");
    }
  }

  /**
   * Sends a verification email to a user.
   * @param {Object} param0 - An object containing the user's name, email, and verification token.
   * @param {String} param0.name - The user's name.
   * @param {String} param0.email - The user's email address.
   * @param {String} param0.verificationToken - The token for email verification.
   */
  async sendVerificationEmail({ name, email, verificationToken }) {
    // Construct the verification URL
    const verifyEmailUrl = `${this.origin}/user/verify-email?token=${verificationToken}&email=${email}`;
    // Email message content
    const message = `<p>Please confirm your email by clicking on the following link : 
    <a href="${verifyEmailUrl}">Verify Email</a> </p>`;

    // Utilize sendEmail to send the verification email
    return this.sendEmail({
      to: email,
      subject: "Email Confirmation",
      html: `<h4> Hello, ${name}</h4> ${message}`,
    });
  }

  /**
   * Sends a password reset email to a user.
   * @param {Object} param0 - An object containing the user's name and email.
   * @param {String} param0.name - The user's name.
   * @param {String} param0.email - The user's email address.
   * @param {String} token - The password reset token.
   */
  async sendResetPasswordEmail({ name, email }, token) {
    // Construct the password reset URL
    const resetURL = `${this.origin}/user/reset-password?token=${token}&email=${email}`;
    // Email message content for password reset
    const message = `<p>Please reset password by clicking on the following link : 
    <a href="${resetURL}">Reset Password</a></p>`;

    // Utilize sendEmail to send the password reset email
    return this.sendEmail({
      to: email,
      subject: "Reset Password",
      html: `<h4>Hello, ${name}</h4> ${message}`,
    });
  }
}

// Exporting the EmailService instance
module.exports = new EmailService();
