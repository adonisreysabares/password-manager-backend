import express from 'express';
import crypto from 'crypto';
import pool from '../database/db.js';
import { verifyToken } from '../middleware/verifyToken.js';
const accountRouter = express.Router();

// Encryption settings (AES-256)
const algorithm = 'aes-256-cbc';
const ivLength = 16; // AES IV length for CBC mode
const keyLength = 32; // AES-256 uses a 32-byte key

// Function to derive a key from a master password (using PBKDF2)
function deriveKey(masterPassword, salt) {
    return crypto.pbkdf2Sync(masterPassword, salt, 100000, keyLength, 'sha256'); // 32 bytes key for AES-256
}

// Encrypt the password using AES encryption
function encryptPassword(password, masterPassword) {
    const iv = crypto.randomBytes(ivLength); // Generate random IV for encryption
    const salt = crypto.randomBytes(16); // Generate random salt for key derivation
    const key = deriveKey(masterPassword, salt);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encryptedPassword = cipher.update(password, 'utf8', 'hex');
    encryptedPassword += cipher.final('hex');

    return { encryptedPassword, iv: iv.toString('hex'), salt: salt.toString('hex') };
}

// POST /creation: Create an account
accountRouter.post('/creation', verifyToken, async (req, res) => {
    const { accountType, password, masterPassword, website, username } = req.body;

    if (!masterPassword) {
        return res.status(400).json({ message: "Master password is required" });
    }

    if(!req.user.id){
        return res.status(400).json({
            message: "No user is authenticated"
        })
    }

    // Encrypt the password using the master password
    const { encryptedPassword, iv, salt } = encryptPassword(password, masterPassword);

    // Insert into the accounts table with website and username
    const insertData = `
        INSERT INTO accounts (account_type, password, iv, salt, user_id, website, username)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `;
    const data = [accountType, encryptedPassword, iv, salt, req.user.id, website, username];

    try {
        const account = await pool.query(insertData, data);
        if (account.rowCount === 0) {
            return res.status(401).json({
                message: 'An error occurred, please try again',
            });
        }
        return res.status(200).json({
            message: 'Account created successfully',
        });
    } catch (error) {
        console.error("Error inserting account:", error);
        return res.status(500).json({
            error: error.message,
        });
    }
});


// GET /accounts: Retrieve all accounts for the authenticated user
accountRouter.post('/accounts', verifyToken, async (req, res) => {
    const userId = req.user.id; // Get the authenticated user ID
    let { masterPassword } = req.body;

    if (!userId) {
        return res.status(401).json({ message: "User not authenticated" });
    }

    const accountsQuery = `
        SELECT account_id, account_type, password, iv, salt, website, username
        FROM accounts
        WHERE user_id = $1
    `;
    const userAccounts = [userId];

    try {
        const result = await pool.query(accountsQuery, userAccounts);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No accounts found for this user" });
        }

        let accountList = [];
        let decryptionFailed;

        do {
            decryptionFailed = false;
            accountList = result.rows.map(account => {
                const decryptedPassword = decryptPassword(account.password, account.iv, account.salt, masterPassword);

                if (decryptedPassword === null) {
                    decryptionFailed = true;
                }

                return {
                    id: account.account_id,
                    account_type: account.account_type,
                    website: account.website,      // Include the website
                    username: account.username,    // Include the username
                    password: decryptedPassword !== null ? decryptedPassword : "Error decrypting password"
                };
            });

            if (decryptionFailed) {
                return res.status(400).json({ message: "Incorrect master password. Please try again." });
            }

        } while (decryptionFailed);

        return res.status(200).json({
            accountData: accountList,
            message: "Successfully retrieved accounts",
        });

    } catch (error) {
        console.error("Error fetching accounts:", error);
        return res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

// Function to decrypt the password using AES
function decryptPassword(encryptedPassword, ivHex, saltHex, masterPassword) {
    const iv = Buffer.from(ivHex, 'hex');
    const salt = Buffer.from(saltHex, 'hex');
    const key = deriveKey(masterPassword, salt);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decryptedPassword;

    try {
        decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf8');
        decryptedPassword += decipher.final('utf8');
    } catch (error) {
        console.error("Error decrypting password:", error);
        return null; // Return null if decryption fails
    }

    return decryptedPassword;
}


// Updating an account (changing password or account type)
accountRouter.put('/accounts/:id', async (req, res) => {
    const { id } = req.params;
    const { accountType, password, masterPassword, website, username } = req.body;

    // Encrypt the new password
    const { encryptedPassword, iv, salt } = encryptPassword(password, masterPassword);

    const updateAccount = `
        UPDATE accounts
        SET account_type = $1, password = $2, iv = $3, salt = $4, website = $5, username = $6
        WHERE account_id = $7
        RETURNING *
    `;

    try {
        const updatedAccount = await pool.query(updateAccount, [accountType, encryptedPassword, iv, salt, website, username, id]);

        if (updatedAccount.rowCount > 0) {
            return res.status(200).json({
                message: 'Account updated successfully',
            });
        } else {
            return res.status(400).json({
                message: 'Account not found',
            });
        }
    } catch (error) {
        return res.status(500).json({
            error: error.message,
        });
    }
});

// Deletion of an account
accountRouter.delete('/accounts/:id', async (req, res) => {
    const { id } = req.params;
    const deleteAccount = `
        DELETE FROM accounts 
        WHERE account_id = $1
        RETURNING *
    `;

    try {
        const deletedAccount = await pool.query(deleteAccount, [id]);

        if (deletedAccount.rowCount > 0) {
            return res.status(200).json({
                message: 'Account deleted successfully',
            });
        } else {
            return res.status(400).json({
                message: 'Account not found',
            });
        }
    } catch (error) {
        return res.status(500).json({
            error: error.message,
        });
    }
});

export default accountRouter;
