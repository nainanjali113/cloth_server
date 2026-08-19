import express from 'express'
import mongoose from 'mongoose'
import dotenv from 'dotenv'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'

import router from './routes/routes.js'

dotenv.config({ quiet: true })

const app = express()

const PORT = process.env.PORT || 8080

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, }))

app.use(cors({
    origin: process.env.CLIENT_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}))

app.use(express.json({ limit: '10kb' }))

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests. Please try again later.', },
})

app.use(limiter)

app.use('/', router)

app.listen(PORT, () => { console.log(`Server is running on port ${PORT}`) })


