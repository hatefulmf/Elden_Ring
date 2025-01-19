const jwt = require('jsonwebtoken');
const secretKey = process.env.JWT_SECRET;

async function generateToken(user) {
    try {
        const token = jwt.sign({ user_id: user.user_id, role: user.role }, secretKey, { expiresIn: '1h' });
        return token;
    } catch (error) {
        console.error("Error generating token:", error);
    }
}

const ADMIN = async (req, res, next) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        if (decoded.role === 'admin') {
            req.user = decoded;
            next();
        } else {
            res.status(403).send('Access denied');
        }
    } catch (error) {
        res.status(401).send('Invalid token');
    }
};

const USER = async (req, res, next) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).send('Invalid token');
    }
};

module.exports = {
    generateToken,
    ADMIN,
    USER
};
