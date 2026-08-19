import crypto from 'crypto';

export const generateOTP = () => { return Math.floor(100000 + Math.random() * 900000).toString() }

export const generateResetToken = () => { return crypto.randomBytes(32).toString('hex') }

export const calculateLockDuration = (lockCount) => {
    const durations = [
        { duration: 1, unit: 'minute' },
        { duration: 5, unit: 'minute' },
        { duration: 10, unit: 'minute' },
        { duration: 30, unit: 'minute' },
        { duration: 1, unit: 'hour' },
        { duration: 24, unit: 'hour' }
    ];

    const index = Math.min(lockCount, durations.length - 1);
    const lock = durations[index];

    let milliseconds = lock.duration * 60 * 1000;
    if (lock.unit === 'hour') { milliseconds = lock.duration * 60 * 60 * 1000 }

    return { duration: lock.duration, unit: lock.unit, milliseconds: milliseconds }
}

export const isAccountLocked = (user) => {
    if (!user.verification.lock_until) return false;
    return new Date(user.verification.lock_until) > new Date()
}

export const getRemainingLockTime = (user) => {
    if (!user.verification.lock_until) return 0
    const lockUntil = new Date(user.verification.lock_until)
    const now = new Date()
    if (lockUntil <= now) return 0
    return Math.floor((lockUntil - now) / 1000);
};