// backend/middleware/verifyToken.js
import jwt from 'jsonwebtoken';

export const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from Authorization header
    if (!token) return res.status(401).json({ message: "Access Denied. No token provided." });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // Add the decoded user info to the request object
        next();
    } catch (err) {
        res.status(400).json({ message: "Invalid Token" });
    }
};
