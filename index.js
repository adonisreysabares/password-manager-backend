import express from "express"
import dotenv from "dotenv"
import users from './routes/users.js'
import accountRouter from "./routes/accounts.js"
import session from 'express-session'
import pgSession from 'connect-pg-simple'
import pool from './database/db.js'
import cors from 'cors'
dotenv.config()

const app = express()
const PORT = process.env.PORT

// Initialize PG session store
const PgSession = pgSession(session)

const corsOptions = {
    origin: 'http://localhost:5173',
    credentials: false,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type"], 
}
// Session store configuration
const sessionConfig = session({
    store: new PgSession({
        pool: pool,
        tableName: 'sessions'   // Table to store sessions
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
})


//Middleware

app.use(cors(corsOptions))
app.use(express.json())
app.use(express.urlencoded({extended: true}))

//API Router of the data
app.use('/auth', users)
app.use('/account', accountRouter)


app.listen(3000, ()=>{
    console.log(`Server is running on port http://localhost:${PORT}` )
})