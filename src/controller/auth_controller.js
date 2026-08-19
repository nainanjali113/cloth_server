import User from '../model/User.js';
import { generateOTP, isAccountLocked, getRemainingLockTime, calculateLockDuration } from '../utils/otpUtils.js';
import { sendOTPEmail, sendPasswordResetEmail } from '../mail/emailService.js';
import { validateRegister, isValidEmail } from '../validation/validation.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const OTP_EXPIRY_MINUTES = 10;

// Create Account
export const createAccount = async (req, res) => {
    try {
        const { first_name, last_name, gender, email, password } = req.body;

        // Validate input
        const validation = validateRegister(req.body);
        if (!validation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: validation.errors
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists with this email'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        // Create user
        const user = new User({
            first_name,
            last_name,
            gender,
            email: email.toLowerCase(),
            password: hashedPassword,
            verification: {
                otp: otp,
                otp_expiry: otpExpiry,
                is_verified: false,
                otp_attempts: 0,
                max_otp_attempts: 3,
                lock_until: null,
                lock_count: 0,
                last_otp_sent: new Date()
            },
            is_active: true,
            is_delete: false,
            address_list: []
        });

        await user.save();

        // Send OTP email
        await sendOTPEmail(email, first_name, otp);

        res.status(201).json({
            success: true,
            message: 'Account created successfully. Please verify your email with OTP.',
            data: {
                email: user.email,
                name: `${user.first_name} ${user.last_name}`
            }
        });

    } catch (error) {
        console.error('Create account error:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating account',
            error: error.message
        });
    }
};

// Verify OTP
export const verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user);
            return res.status(403).json({
                success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime
            });
        }

        // Check if already verified
        if (user.verification.is_verified) {
            return res.status(400).json({
                success: false,
                message: 'Email already verified'
            });
        }

        // Check OTP expiry
        if (new Date(user.verification.otp_expiry) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired. Please request a new one.'
            });
        }

        // Check OTP
        if (user.verification.otp !== otp) {
            user.verification.otp_attempts += 1;
            
            // Check if max attempts reached
            if (user.verification.otp_attempts >= user.verification.max_otp_attempts) {
                // Lock the account
                user.verification.lock_count += 1;
                const lockDuration = calculateLockDuration(user.verification.lock_count);
                user.verification.lock_until = new Date(Date.now() + lockDuration.milliseconds);
                user.verification.otp_attempts = 0;
                
                await user.save();
                
                return res.status(403).json({
                    success: false,
                    message: `Too many failed attempts. Account locked for ${lockDuration.duration} ${lockDuration.unit}(s).`,
                    lock_duration: lockDuration.duration,
                    lock_unit: lockDuration.unit,
                    lock_count: user.verification.lock_count
                });
            }
            
            await user.save();
            
            return res.status(400).json({
                success: false,
                message: `Invalid OTP. ${user.verification.max_otp_attempts - user.verification.otp_attempts} attempts remaining.`,
                attempts_remaining: user.verification.max_otp_attempts - user.verification.otp_attempts
            });
        }

        // OTP is correct - verify user
        user.verification.is_verified = true;
        user.verification.otp = null;
        user.verification.otp_expiry = null;
        user.verification.otp_attempts = 0;
        user.verification.lock_until = null;
        user.is_active = true;
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            success: true,
            message: 'Email verified successfully',
            data: {
                token,
                user: {
                    id: user._id,
                    email: user.email,
                    name: `${user.first_name} ${user.last_name}`,
                    role: user.role,
                    is_verified: user.verification.is_verified
                }
            }
        });

    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Error verifying OTP',
            error: error.message
        });
    }
};

// Resend OTP
export const resendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if already verified
        if (user.verification.is_verified) {
            return res.status(400).json({
                success: false,
                message: 'Email already verified'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user);
            return res.status(403).json({
                success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime
            });
        }

        // Check if OTP was sent recently (prevent spam)
        if (user.verification.last_otp_sent) {
            const lastSent = new Date(user.verification.last_otp_sent);
            const now = new Date();
            const diffMinutes = (now - lastSent) / (1000 * 60);
            
            if (diffMinutes < 2) {
                return res.status(429).json({
                    success: false,
                    message: 'Please wait 2 minutes before requesting a new OTP'
                });
            }
        }

        // Generate new OTP
        const newOtp = generateOTP();
        const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        user.verification.otp = newOtp;
        user.verification.otp_expiry = otpExpiry;
        user.verification.otp_attempts = 0;
        user.verification.last_otp_sent = new Date();
        await user.save();

        // Send new OTP
        await sendOTPEmail(email, user.first_name, newOtp);

        res.status(200).json({
            success: true,
            message: 'New OTP sent successfully to your email'
        });

    } catch (error) {
        console.error('Resend OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Error resending OTP',
            error: error.message
        });
    }
};

// Login User
export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user);
            return res.status(403).json({
                success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime
            });
        }

        // Check if email is verified
        if (!user.verification.is_verified) {
            return res.status(403).json({
                success: false,
                message: 'Please verify your email before logging in'
            });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Update last login
        user.last_login = new Date();
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                token,
                user: {
                    id: user._id,
                    email: user.email,
                    name: `${user.first_name} ${user.last_name}`,
                    role: user.role,
                    is_verified: user.verification.is_verified,
                    profile_img: user.profileImg
                }
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error logging in',
            error: error.message
        });
    }
};

// Forgot Password - Send OTP
export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user);
            return res.status(403).json({
                success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime
            });
        }

        // Generate OTP for password reset
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        // Store OTP in verification
        user.verification.otp = otp;
        user.verification.otp_expiry = otpExpiry;
        user.verification.otp_attempts = 0;
        user.verification.last_otp_sent = new Date();
        await user.save();

        // Send password reset OTP
        await sendPasswordResetEmail(email, user.first_name, otp);

        res.status(200).json({
            success: true,
            message: 'Password reset OTP sent to your email'
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Error sending password reset OTP',
            error: error.message
        });
    }
};

// Reset Password with OTP
export const resetPassword = async (req, res) => {
    try {
        const { email, otp, new_password } = req.body;

        if (!email || !otp || !new_password) {
            return res.status(400).json({
                success: false,
                message: 'Email, OTP, and new password are required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user);
            return res.status(403).json({
                success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime
            });
        }

        // Check OTP expiry
        if (new Date(user.verification.otp_expiry) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired. Please request a new one.'
            });
        }

        // Check OTP
        if (user.verification.otp !== otp) {
            user.verification.otp_attempts += 1;
            
            if (user.verification.otp_attempts >= user.verification.max_otp_attempts) {
                user.verification.lock_count += 1;
                const lockDuration = calculateLockDuration(user.verification.lock_count);
                user.verification.lock_until = new Date(Date.now() + lockDuration.milliseconds);
                user.verification.otp_attempts = 0;
                
                await user.save();
                
                return res.status(403).json({
                    success: false,
                    message: `Too many failed attempts. Account locked for ${lockDuration.duration} ${lockDuration.unit}(s).`,
                    lock_duration: lockDuration.duration,
                    lock_unit: lockDuration.unit
                });
            }
            
            await user.save();
            
            return res.status(400).json({
                success: false,
                message: `Invalid OTP. ${user.verification.max_otp_attempts - user.verification.otp_attempts} attempts remaining.`,
                attempts_remaining: user.verification.max_otp_attempts - user.verification.otp_attempts
            });
        }

        // Reset password
        const hashedPassword = await bcrypt.hash(new_password, 10);
        user.password = hashedPassword;
        user.verification.otp = null;
        user.verification.otp_expiry = null;
        user.verification.otp_attempts = 0;
        user.verification.lock_until = null;
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Error resetting password',
            error: error.message
        });
    }
};