import pool from '../database/db.js'
import express from 'express'
import bcrypt from "bcrypt"
import rateLimit from 'express-rate-limit'
import { body, validationResult } from 'express-validator'

const router = express.Router()

// Rate limiter middleware
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: { message: "Too many login attempts, please try again later" }
})

// Validation middleware
const loginValidation = [
    body('username').trim().notEmpty().escape(),
    body('password').trim().notEmpty()
]

const registerValidation = [
    body('fName').trim().notEmpty().escape(),
    body('lName').trim().notEmpty().escape(),
    body('username').trim().notEmpty().escape(),
    body('password').trim().isLength({ min: 6 }),
    body('dob').isISO8601().toDate()
]

// ... existing code ...

router.post('/login', loginLimiter, loginValidation, async(req, res) => {
    // Validate input
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    
    // ... rest of existing login code ...
})

router.post('/register', registerValidation, async (req, res) => {
    // Validate input
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    // ... rest of existing register code ...
})

// ... existing code ...


