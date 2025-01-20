const jwt = require('jsonwebtoken');
const secretKey = process.env.JWT_SECRET;

async function generateToken(user) {
    try {
        const token = jwt.sign(
            { user_id: user.user_id, role: user.role }, 
            secretKey, 
            { expiresIn: '1h' } // Token valid for 1 hour
        );
        return token;
    } catch (error) {
        console.error("Error generating token:", error);
    }
}



const USER = async (req, res, next) => {
    try {
        const token = req.headers.authorization.split(' ')[1]; // Extract token
        const decoded = jwt.verify(token, secretKey); // Validate token
        req.user = decoded; // Attach user details to request
        next(); // Proceed to the route logic
    } catch (error) {
        res.status(401).send('Invalid token'); // Error response
    }
};

module.exports = {
    generateToken,
    USER
};
