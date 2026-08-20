import express from 'express';
import user_model from '../model/user_model.js'
import { generateOTP, isAccountLocked, getRemainingLockTime, calculateLockDuration } from '../utils/otpUtils.js'
import { sendOTPEmail, sendPasswordResetEmail } from '../mail/all_mail_format.js'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config({ quiet: true })

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'
const OTP_EXPIRY_MINUTES = 10

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) { return res.status(401).json({ success: false, message: 'Access token required' }) }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { return res.status(403).json({ success: false, message: 'Invalid or expired token' }) }
        req.user = user
        next()
    })
}

const checkUserActive = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId)
        if (!user || !user.is_active || user.is_delete) {
            return res.status(403).json({ success: false, message: 'Account is inactive or deleted' }) }
        next()
    }
    catch (error) {
        return res.status(500).json({ success: false, message: 'Error checking user status', error: error.message }) }
}

// Create Account
router.post('/auth/register', async (req, res) => {
    try {
        const { first_name, last_name, gender, email, password } = req.body

        // Validate required fields
        if (!first_name || !last_name || !gender || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields are required' }) }

        // Check if user already exists
        const existingUser = await User.findOne({ email: email.toLowerCase() })
        if (existingUser) { return res.status(400).json({ success: false, message: 'User already exists with this email' }) }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10)

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)

        // Create user
        const user = new User({ first_name, last_name, gender, email: email.toLowerCase(),
            password: hashedPassword,
            verification: { otp: otp, otp_expiry: otpExpiry, is_verified: false, otp_attempts: 0, max_otp_attempts: 3,
                lock_until: null, lock_count: 0, last_otp_sent: new Date() },
            is_active: true, is_delete: false, address_list: [] })

        await user.save()

        // Send OTP email
        await sendOTPEmail(email, first_name, otp)

        res.status(201).json({ success: true, message: 'Account created successfully. Please verify your email with OTP.',
            data: { email: user.email, name: `${user.first_name} ${user.last_name}` } }) }
        catch (error) { console.error('Create account error:', error)
        res.status(500).json({ success: false, message: 'Error creating account', error: error.message }) }
})

// Verify OTP
router.post('/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) { return res.status(400).json({ success: false, message: 'Email and OTP are required' }) }

        const user = await User.findOne({ email: email.toLowerCase() })
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // Check if account is locked
        if (isAccountLocked(user)) { const remainingTime = getRemainingLockTime(user)
            return res.status(403).json({
                success: false, message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime }) }

        // Check if already verified
        if (user.verification.is_verified) { return res.status(400).json({ success: false, message: 'Email already verified' }) }

        // Check OTP expiry
        if (new Date(user.verification.otp_expiry) < new Date()) {
            return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' }) }

        // Check OTP
        if (user.verification.otp !== otp) {
            user.verification.otp_attempts += 1

            // Check if max attempts reached
            if (user.verification.otp_attempts >= user.verification.max_otp_attempts) {
                // Lock the account
                user.verification.lock_count += 1
                const lockDuration = calculateLockDuration(user.verification.lock_count)
                user.verification.lock_until = new Date(Date.now() + lockDuration.milliseconds)
                user.verification.otp_attempts = 0

                await user.save()

                return res.status(403).json({ success: false,
                    message: `Too many failed attempts. Account locked for ${lockDuration.duration} ${lockDuration.unit}(s).`,
                    lock_duration: lockDuration.duration, lock_unit: lockDuration.unit, lock_count: user.verification.lock_count }) }

            await user.save()

            return res.status(400).json({ success: false,
                message: `Invalid OTP. ${user.verification.max_otp_attempts - user.verification.otp_attempts} attempts remaining.`,
                attempts_remaining: user.verification.max_otp_attempts - user.verification.otp_attempts })
        }

        // OTP is correct - verify user
        user.verification.is_verified = true
        user.verification.otp = null
        user.verification.otp_expiry = null
        user.verification.otp_attempts = 0
        user.verification.lock_until = null
        user.is_active = true
        await user.save()

        // Generate JWT token
        const token = jwt.sign( { userId: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' } )

        res.status(200).json({ success: true, message: 'Email verified successfully',
            data: { token,
                user: { id: user._id, email: user.email, name: `${user.first_name} ${user.last_name}`,
                    role: user.role, is_verified: user.verification.is_verified } } 
        }) }
     catch (error) { console.error('Verify OTP error:', error);
        res.status(500).json({ success: false, message: 'Error verifying OTP', error: error.message }) }
})

// Resend OTP
router.post('/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body

        if (!email) { return res.status(400).json({ success: false, message: 'Email is required' }) }

        const user = await User.findOne({ email: email.toLowerCase() })
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // Check if already verified
        if (user.verification.is_verified) { return res.status(400).json({ success: false, message: 'Email already verified' }) }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user)
            return res.status(403).json({ success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime }) }

        // Check if OTP was sent recently (prevent spam)
        if (user.verification.last_otp_sent) {
            const lastSent = new Date(user.verification.last_otp_sent)
            const now = new Date()
            const diffMinutes = (now - lastSent) / (1000 * 60)

            if (diffMinutes < 2) {
                return res.status(429).json({ success: false, message: 'Please wait 2 minutes before requesting a new OTP' }) }
        }

        // Generate new OTP
        const newOtp = generateOTP()
        const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)

        user.verification.otp = newOtp
        user.verification.otp_expiry = otpExpiry
        user.verification.otp_attempts = 0
        user.verification.last_otp_sent = new Date()
        await user.save()

        // Send new OTP
        await sendOTPEmail(email, user.first_name, newOtp)

        res.status(200).json({ success: true, message: 'New OTP sent successfully to your email' })

    } 
    catch (error) { console.error('Resend OTP error:', error)
        res.status(500).json({ success: false, message: 'Error resending OTP', error: error.message }) }
})

// Login User
router.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) { return res.status(400).json({ success: false, message: 'Email and password are required' }) }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) { return res.status(401).json({ success: false, message: 'Invalid credentials' }) }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user)
            return res.status(403).json({ success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime }) }

        // Check if email is verified
        if (!user.verification.is_verified) {
            return res.status(403).json({ success: false, message: 'Please verify your email before logging in' }) }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password)
        if (!isPasswordValid) { return res.status(401).json({ success: false, message: 'Invalid credentials' }) }

        // Update last login
        user.last_login = new Date()
        await user.save()

        // Generate JWT token
        const token = jwt.sign ( { userId: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' } )

        res.status(200).json({ success: true, message: 'Login successful',
            data: { token, user: { id: user._id, email: user.email, name: `${user.first_name} ${user.last_name}`,
                    role: user.role, is_verified: user.verification.is_verified, profile_img: user.profileImg } } 
        }) } 

    catch (error) { console.error('Login error:', error)
        res.status(500).json({ success: false, message: 'Error logging in', error: error.message }) }
})

// Forgot Password - Send OTP
router.post('/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) { return res.status(400).json({ success: false, message: 'Email is required' }) }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user)
            return res.status(403).json({ success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime }) }

        // Generate OTP for password reset
        const otp = generateOTP()
        const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)

        // Store OTP in verification
        user.verification.otp = otp
        user.verification.otp_expiry = otpExpiry
        user.verification.otp_attempts = 0
        user.verification.last_otp_sent = new Date()
        await user.save()

        // Send password reset OTP
        await sendPasswordResetEmail(email, user.first_name, otp)

        res.status(200).json({ success: true, message: 'Password reset OTP sent to your email' })

    } 
    catch (error) { console.error('Forgot password error:', error)
        res.status(500).json({ success: false, message: 'Error sending password reset OTP', error: error.message }) }
})

// Reset Password with OTP
router.post('/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, new_password } = req.body;

        if (!email || !otp || !new_password) {
            return res.status(400).json({ success: false, message: 'Email, OTP, and new password are required' }) }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // Check if account is locked
        if (isAccountLocked(user)) {
            const remainingTime = getRemainingLockTime(user)
            return res.status(403).json({ success: false,
                message: `Account is locked. Please try again after ${Math.ceil(remainingTime / 60)} minutes.`,
                remaining_time: remainingTime }) }

        // Check OTP expiry
        if (new Date(user.verification.otp_expiry) < new Date()) {
            return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' }) }

        // Check OTP
        if (user.verification.otp !== otp) {
            user.verification.otp_attempts += 1

            if (user.verification.otp_attempts >= user.verification.max_otp_attempts) {
                user.verification.lock_count += 1
                const lockDuration = calculateLockDuration(user.verification.lock_count)
                user.verification.lock_until = new Date(Date.now() + lockDuration.milliseconds)
                user.verification.otp_attempts = 0

                await user.save()

                return res.status(403).json({ success: false,
                    message: `Too many failed attempts. Account locked for ${lockDuration.duration} ${lockDuration.unit}(s).`,
                    lock_duration: lockDuration.duration, lock_unit: lockDuration.unit }) }

            await user.save()

            return res.status(400).json({ success: false,
                message: `Invalid OTP. ${user.verification.max_otp_attempts - user.verification.otp_attempts} attempts remaining.`,
                attempts_remaining: user.verification.max_otp_attempts - user.verification.otp_attempts })
        }

        // Reset password
        const hashedPassword = await bcrypt.hash(new_password, 10)
        user.password = hashedPassword
        user.verification.otp = null
        user.verification.otp_expiry = null
        user.verification.otp_attempts = 0
        user.verification.lock_until = null
        await user.save()

        res.status(200).json({ success: true, message: 'Password reset successfully' })

    } 
    catch (error) { console.error('Reset password error:', error)
        res.status(500).json({ success: false, message: 'Error resetting password', error: error.message }) }
})

// ============ USER PROFILE CONTROLLERS (Protected Routes) ============

// Get User Profile
router.get('/user/profile', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId;
        const user = await User.findById(userId)
            .select('-password -verification.otp -verification.otp_expiry')

        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        res.status(200).json({ success: true, data: user })

    } 
    catch (error) { console.error('Get profile error:', error)
        res.status(500).json({ success: false, message: 'Error fetching profile', error: error.message }) }
})

// Update Profile
router.put('/user/profile', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId
        const { first_name, last_name, gender } = req.body

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // Update fields
        if (first_name) user.first_name = first_name
        if (last_name) user.last_name = last_name
        if (gender) user.gender = gender

        await user.save()

        res.status(200).json({ success: true, message: 'Profile updated successfully',
            data: { first_name: user.first_name, last_name: user.last_name, gender: user.gender } })

    } 
    catch (error) { console.error('Update profile error:', error)
        res.status(500).json({ success: false, message: 'Error updating profile', error: error.message }) }
})

// Update Profile Image
router.patch('/user/profile-image', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId
        const { profileImg } = req.body

        if (!profileImg) { return res.status(400).json({ success: false, message: 'Profile image data is required' }) }

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        user.profileImg = profileImg
        await user.save()

        res.status(200).json({ success: true, message: 'Profile image updated successfully', data: { profileImg: user.profileImg }
        })

    } 
    catch (error) { console.error('Update profile image error:', error)
        res.status(500).json({ success: false, message: 'Error updating profile image', error: error.message }) }
})

// Change Password
router.post('/user/change-password', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId
        const { current_password, new_password } = req.body

        if (!current_password || !new_password) {
            return res.status(400).json({ success: false, message: 'Current password and new password are required' }) }

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false,  message: 'User not found' }) }

        // Verify current password
        const isPasswordValid = await bcrypt.compare(current_password, user.password)
        if (!isPasswordValid) { return res.status(401).json({ success: false, message: 'Current password is incorrect' }) }

        // Hash new password
        const hashedPassword = await bcrypt.hash(new_password, 10)
        user.password = hashedPassword
        await user.save()

        res.status(200).json({ success: true, message: 'Password changed successfully' })

    } 
    catch (error) { console.error('Change password error:', error)
        res.status(500).json({ success: false, message: 'Error changing password', error: error.message }) }
})

// ============ ADDRESS CONTROLLERS (Protected Routes) ============

// Get All Addresses
router.get('/user/addresses', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        res.status(200).json({ success: true, data: user.address_list })

    } 
    catch (error) { console.error('Get addresses error:', error)
        res.status(500).json({ success: false, message: 'Error fetching addresses', error: error.message }) }
})

// Add Address
router.post('/user/addresses', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId
        const addressData = req.body

        // Validate required fields
        const requiredFields = ['full_name', 'phone', 'address_line1', 'city', 'state', 'pincode', 'country']
        for (const field of requiredFields) { if (!addressData[field]) {
                return res.status(400).json({ success: false, message: `${field} is required` }) } }

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // If this is the first address or marked as default
        if (addressData.is_default || user.address_list.length === 0) {
            user.address_list.forEach(addr => addr.is_default = false) }

        user.address_list.push(addressData)
        await user.save()

        res.status(201).json({ success: true, message: 'Address added successfully', data: user.address_list })

    }
    catch (error) { console.error('Add address error:', error)
        res.status(500).json({ success: false, message: 'Error adding address', error: error.message }) }
})

// Update Address
router.put('/user/addresses/:addressId', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId
        const { addressId } = req.params
        const updateData = req.body

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        // Find address index
        const addressIndex = user.address_list.findIndex( addr => addr._id.toString() === addressId )

        if (addressIndex === -1) { return res.status(404).json({ success: false, message: 'Address not found' }) }

        // If setting as default, unset others
        if (updateData.is_default) { user.address_list.forEach(addr => addr.is_default = false) }

        // Update address fields
        Object.keys(updateData).forEach(key => { if (key !== '_id' && key !== '__v') {
            user.address_list[addressIndex][key] = updateData[key] } })

        await user.save()

        res.status(200).json({ success: true, message: 'Address updated successfully', data: user.address_list })

    } 
    catch (error) { console.error('Update address error:', error)
        res.status(500).json({ success: false, message: 'Error updating address', error: error.message }) }
})

// Delete Address
router.delete('/user/addresses/:addressId', authenticateToken, checkUserActive, async (req, res) => {
    try {
        const userId = req.user.userId
        const { addressId } = req.params

        const user = await User.findById(userId)
        if (!user) { return res.status(404).json({ success: false, message: 'User not found' }) }

        user.address_list = user.address_list.filter( addr => addr._id.toString() !== addressId )
        await user.save()

        res.status(200).json({ success: true, message: 'Address deleted successfully', data: user.address_list })

    } 
    catch (error) { console.error('Delete address error:', error)
        res.status(500).json({ success: false, message: 'Error deleting address', error: error.message }) }
})

export default router