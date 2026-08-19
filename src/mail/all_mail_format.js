import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config({quiet:true})

// Create a transporter using SMTP
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

export const sendOTPEmail = async (email, name, otp) => {
    try {
        const info = await transporter.sendMail({
            from: `"E-Shop" <${process.env.SMTP_FROM_EMAIL || 'noreply@eshop.com'}>`,
            to: email,
            subject: "Email Verification OTP",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Hello ${name},</h2>
                    <p>Thank you for registering with E-Shop. Please use the following OTP to verify your email address:</p>
                    <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otp}
                    </div>
                    <p>This OTP is valid for 10 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <p style="margin-top: 30px; color: #666; font-size: 12px;">© ${new Date().getFullYear()} E-Shop. All rights reserved.</p>
                </div>
            `
        });

        console.log("OTP email sent: %s", info.messageId);
        return { success: true, messageId: info.messageId };
    } 
    catch (err) { console.error('Error sending OTP email:', err)
        throw new Error('Failed to send OTP email') }
}

export const sendPasswordResetEmail = async (email, name, otp) => {
    try {
        const info = await transporter.sendMail({
            from: `"E-Shop" <${process.env.SMTP_FROM_EMAIL || 'noreply@eshop.com'}>`,
            to: email,
            subject: "Password Reset OTP",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Hello ${name},</h2>
                    <p>You have requested to reset your password. Please use the following OTP to reset your password:</p>
                    <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otp}
                    </div>
                    <p>This OTP is valid for 10 minutes.</p>
                    <p>If you didn't request this, please ignore this email or contact support.</p>
                    <p style="margin-top: 30px; color: #666; font-size: 12px;">© ${new Date().getFullYear()} E-Shop. All rights reserved.</p>
                </div>
            `
        })

        console.log("Password reset email sent: %s", info.messageId)
        return { success: true, messageId: info.messageId }
     } 
    catch (err) { console.error('Error sending password reset email:', err)
        throw new Error('Failed to send password reset email') }
};