import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    profileImg: { type: Object, default: null },
    first_name: { type: String, required: true, trim: true },
    last_name: { type: String, required: true, trim: true },
    gender: { type: String, enum: ['male', 'female', 'other'], required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user', required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    is_active: { type: Boolean, default: true },
    is_delete: { type: Boolean, default: false },
    address_list: [{
        full_name: { type: String, required: true },
        phone: { type: String, required: true },
        address_line1: { type: String, required: true },
        address_line2: { type: String },
        city: { type: String, required: true },
        state: { type: String, required: true },
        pincode: { type: String, required: true },
        country: { type: String, required: true },
        is_default: { type: Boolean, default: false }
    }],
    verification: {
        otp: { type: String },
        otp_expiry: { type: Date },
        is_verified: { type: Boolean, default: false },
        otp_attempts: { type: Number, default: 0 },
        max_otp_attempts: { type: Number, default: 3 },
        lock_until: { type: Date },
        lock_count: { type: Number, default: 0 },
        last_otp_sent: { type: Date }
    },
    order_list: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }],
    cart_list: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Cart' }],
    last_login: { type: Date }
}, {
    timestamps: true
})

export default mongoose.model('User', userSchema);