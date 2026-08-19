export const validateRegister = (data) => {
    const errors = [];
    
    if (!data.first_name || data.first_name.trim().length < 2) {
        errors.push('First name is required and must be at least 2 characters');
    }
    
    if (!data.last_name || data.last_name.trim().length < 2) {
        errors.push('Last name is required and must be at least 2 characters');
    }
    
    if (!data.gender || !['male', 'female', 'other'].includes(data.gender)) {
        errors.push('Gender is required and must be male, female, or other');
    }
    
    if (!data.email || !isValidEmail(data.email)) {
        errors.push('Valid email is required');
    }
    
    if (!data.password || data.password.length < 6) {
        errors.push('Password is required and must be at least 6 characters');
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};

export const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

export const validateAddress = (data) => {
    const errors = [];
    const requiredFields = ['full_name', 'phone', 'address_line1', 'city', 'state', 'pincode', 'country'];
    
    for (const field of requiredFields) {
        if (!data[field] || data[field].trim().length === 0) {
            errors.push(`${field} is required`);
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};