import pg from 'pg'
import dotenv from 'dotenv'

dotenv.config()

const {Pool} = pg

const pool = new Pool({
    user:process.env.DB_USER,
    host:process.env.DB_HOST,
    database:process.env.DB_NAME,
    password:process.env.DB_PASSWORD,
    port:process.env.DB_PORT,
})

pool.connect()
.then(()=>{
    console.log("Database is Connected")
})
.catch((error)=>{
    console.error(error.message)
})

export default pool