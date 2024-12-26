import pool from '../database/db.js'
import express from 'express'
import bcrypt from "bcrypt"
import jwt from 'jsonwebtoken'

const router = express.Router()

//Logging Request
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const queryLogin = `SELECT * FROM users WHERE username = $1`;
    const loginValues = [email];

    try {
        const loginAuthentication = await pool.query(queryLogin, loginValues);
        const user = loginAuthentication.rows[0];

        if (user) {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                // Create JWT token
                const token = jwt.sign(
                    { id: user.user_id, username: user.username},
                    process.env.JWT_SECRET,
                    { expiresIn: '1h' } // Token expires in 1 hour
                );

                res.status(200).json({
                    message: "Welcome to the Jungle",
                    token // Send token to the client
                });
            } else {
                res.status(400).json({ message: "The username or password are incorrect" });
            }
        } else {
            res.status(400).json({ message: "No user has been found" });
        }
    } catch (error) {
        res.status(500).json({ message: "Server error occurred", error: error.message });
        console.error("Something went wrong", error.message);
    }
});

router.post('/register', async (req,res)=>{
    const {fName, mName, lName, username, password, dob} = req.body

    // Input validation
    if(!fName || !lName || !username || !password || !dob) {
        return res.status(400).json({
            message: "Required fields are missing"
        })
    }

    try {
        // Check if username already exists
        const checkUser = await pool.query('SELECT username FROM users WHERE username = $1', [username])
        if(checkUser.rows.length > 0) {
            return res.status(400).json({
                message: "Username already exists"
            })
        }

        // Hash password
        const saltRounds = 10
        const hashedPassword = await bcrypt.hash(password, saltRounds)

        // Insert new user
        const registerUsers = `INSERT INTO users(firstName, middleName, lastName, username, password, dob) 
                             VALUES ($1,$2,$3,$4,$5,$6)`
        const userValues = [fName, mName, lName, username, hashedPassword, dob]
        
        await pool.query(registerUsers, userValues)

        res.status(201).json({
            message: "User registered successfully"
        })

    } catch (error) {
        res.status(500).json({
            message: "Server error occurred",
            error: error.message
        })
        console.error("Registration error:", error.message)
    }
})


export default router