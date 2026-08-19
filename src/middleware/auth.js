import jwt from 'jsonwebtoken';
import User from '../model/User.js';
import dotenv from 'dotenv';

dotenv.config({quiet:true})

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'

export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) { return res.status(401).json({ success: false, message: 'Access token required' }) }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { return res.status(403).json({ success: false, message: 'Invalid or expired token' }) }
        req.user = user
        next()
    })
}

export const checkUserActive = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user || !user.is_active || user.is_delete) {
            return res.status(403).json({ success: false, message: 'Account is inactive or deleted' }) }
        next()
    } 
    catch(error) { return res.status(500).json({ success: false, message: 'Error checking user status', error: error.message }) }
}