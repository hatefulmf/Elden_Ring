const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const rateLimit = require('express-rate-limit');


const JWT_SECRET = process.env.JWT_SECRET;
const app = express();
const port = process.env.port || 8080;
const uri = process.env.MONGO_URI; // Use MONGO_URI from .env

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true
    }
});

// Middleware to verify the token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send("Token is required");
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send("Invalid or expired token");
        }

        req.user = decoded;
        next();
    });
};

// Middleware to verify admin role
const verifyAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send("Access denied, admin privileges required.");
    }
    next();
};

async function connectToDatabase() {
    try {
        await client.connect();
        console.log("Connected to MongoDB");
        
        // Create unique index on username field
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');
        await usersCollection.createIndex({ username: 1 }, { unique: true });

        // Initialize counter document if it doesn't exist
        const countersCollection = database.collection('counters');
        const counter = await countersCollection.findOne({ _id: 'user_id' });
        if (!counter) {
            await countersCollection.insertOne({ _id: 'user_id', seq: 0 });
            console.log("Counter document initialized");
        }

        return client;
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1); // Exit if the database connection fails
    }
}

app.use(express.json());

// Function to get the next user ID
async function getNextUserId(db) {
    const countersCollection = db.collection('counters');
    const result = await countersCollection.findOneAndUpdate(
        { _id: 'user_id' },
        { $inc: { seq: 1 } },
        { returnDocument: 'after', upsert: true }
    );
    return result.value.seq;
}

// Routes
app.get('/', (req, res) => {
    res.send('Welcome to the API');
});

const bcrypt = require('bcrypt'); // Import bcrypt
// Create user route with auto-increment user_id
// Adjusted createUser route to allow role
app.post('/createUser', async (req, res) => {
    try {
        const { username, password, email, role } = req.body; // Add role here
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');

        // Basic validation
        if (!username || !password || !email) {
            return res.status(400).send("Missing required fields: username, password, or email");
        }

        // Check for duplicate username
        const existingUser = await usersCollection.findOne({ username });
        if (existingUser) {
            return res.status(409).send("Username already exists");
        }

        // Check for duplicate email
        const existingEmail = await usersCollection.findOne({ email });
        if (existingEmail) {
            return res.status(409).send("Email address already been used");
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Generate a unique user_id using uuid
        const user_id = uuidv4();

        const user = {
            user_id,
            username,
            password: hashedPassword,
            email,
            registration_date: new Date().toISOString(),
            profile: {
                level: 1,
                experience: 0,
                attributes: { strength: 0, dexterity: 0, intelligence: 0 }
            },
            inventory: [],
            role: role || 'user' // Default to 'user' if role is not provided
        };

        // Insert the user into the database
        await usersCollection.insertOne(user);
        res.status(201).json({ user_id: user.user_id, message: "User created successfully" });
    } catch (error) {
        console.error("Error in createUser route:", error);
        res.status(500).send("Error creating user");
    }
});

//to test whether the environment variables are loaded
app.get('/testEnv', (req, res) => {
    res.json({
        JWT_SECRET: process.env.JWT_SECRET || "Not set",
        MONGO_URI: process.env.MONGO_URI ? "Loaded" : "Not set",
        PORT: process.env.PORT || "Not set"
    });
});

// Set up a rate limiter for login attempts on wrong password
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 3, // Allow 3 failed attempts per minute per username
    message: "Too many failed login attempts, please try again in 1 minute",
    keyGenerator: (req) => req.body.username, // Rate limit by username
    standardHeaders: true,
    legacyHeaders: false,
    onLimitReached: (req, res) => {
        console.log(`Rate limit reached for ${req.body.username}`);
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Missing required fields: username or password");
    }

    const database = client.db('Cluster');
    const collection = database.collection('users');

    try {
        // Find the user by username
        const user = await collection.findOne({ username });

        if (!user) {
            return res.status(404).send("User not found");
        }

        // If password doesn't match, apply rate limit
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            // Apply rate limiter for failed login attempt
            loginLimiter(req, res, () => {});

            return res.status(401).send("Invalid password");
        }

        // If login is successful, generate JWT
        const token = jwt.sign({ user_id: user.user_id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Error in login route:", error);
        res.status(500).send("Error logging in");
    }
});

// Example protected route
app.get('/protectedRoute', verifyToken, (req, res) => {
    res.status(200).send(`Hello ${req.user.username}, this is a protected route.`);
});

const ADMIN = async (req, res, next) => {
    try {
        const token = req.headers.authorization.split(' ')[1]; // Extract token from header
        const decoded = jwt.verify(token, JWT_SECRET); // Validate token with secret key
        if (decoded.role === 'admin') { // Check role for admin access
            req.user = decoded; // Attach user details to request object
            next(); // Proceed to next middleware or route
        } else {
            res.status(403).send('Access denied'); // Role mismatch
        }
    } catch (error) {
        res.status(401).send('Invalid token'); // Invalid or expired token
    }
};

// Level Up endpoint
app.post('/levelUp', verifyToken, async (req, res) => {
    try {
        const { user_id } = req.user; // Getting user_id from the JWT token

        // Connect to the database
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');

        // Find the user by user_id
        const user = await usersCollection.findOne({ user_id });

        if (!user) {
            return res.status(404).send("User not found");
        }

        // Update the user's level and experience
        const newLevel = user.profile.level + 1;
        const newExperience = user.profile.experience + 100; // Just an example increment

        // Update the user in the database
        await usersCollection.updateOne(
            { user_id },
            {
                $set: {
                    "profile.level": newLevel,
                    "profile.experience": newExperience,
                },
            }
        );

        res.status(200).json({ message: "Level up successful", newLevel, newExperience });
    } catch (error) {
        console.error("Error in levelUp route:", error);
        res.status(500).send("Error leveling up user");
    }
});

app.put('/updateProfile', verifyToken, async (req, res) => {
    try {
        const { email, attributes } = req.body; // Attributes can be an object like { strength, dexterity, intelligence }
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');

        // Find and update the user
        const result = await usersCollection.updateOne(
            { user_id: req.user.user_id },
            {
                $set: {
                    ...(email && { email }), // Update email if provided
                    ...(attributes && { "profile.attributes": attributes }) // Update attributes if provided
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).send("User not found");
        }

        res.status(200).send("Profile updated successfully");
    } catch (error) {
        console.error("Error in updateProfile route:", error);
        res.status(500).send("Error updating profile");
    }
});

app.post('/interactItem', verifyToken, async (req, res) => {
    try {
        const { item_id, action } = req.body; // Action can be 'add' or 'remove'
        const database = client.db('Cluster');
        const usersCollection = database.collection('users');
        const itemsCollection = database.collection('items');

        // Check if the item exists
        const item = await itemsCollection.findOne({ item_id });
        if (!item) {
            return res.status(404).send("Item not found");
        }

        // Find the user
        const user = await usersCollection.findOne({ user_id: req.user.user_id });
        if (!user) {
            return res.status(404).send("User not found");
        }

        if (action === 'add') {
            // Add the item to the user's inventory
            user.inventory.push(item_id);
        } else if (action === 'remove') {
            // Remove the item from the user's inventory
            user.inventory = user.inventory.filter(id => id !== item_id);
        } else {
            return res.status(400).send("Invalid action. Use 'add' or 'remove'.");
        }

        // Update the user's inventory in the database
        await usersCollection.updateOne(
            { user_id: user.user_id },
            { $set: { inventory: user.inventory } }
        );

        res.status(200).send(`Item ${action === 'add' ? 'added to' : 'removed from'} your inventory.`);
    } catch (error) {
        console.error("Error in interactItem route:", error);
        res.status(500).send("Error interacting with item");
    }
});

app.post('/fightMonster', verifyToken, async (req, res) => {
    try {
        const { monster_id } = req.body;
        const database = client.db('Cluster');
        const monstersCollection = database.collection('monsters');
        const usersCollection = database.collection('users');

        // Check if the monster exists
        const monster = await monstersCollection.findOne({ monster_id });
        if (!monster) {
            return res.status(404).send("Monster not found");
        }

        // Simulate a battle (e.g., user wins by default for simplicity)
        const xpGained = monster.attributes.difficulty * 10; // Example XP calculation

        // Find and update the user's experience
        const user = await usersCollection.findOne({ user_id: req.user.user_id });
        if (!user) {
            return res.status(404).send("User not found");
        }

        user.profile.experience += xpGained;

        // Update the user's profile in the database
        await usersCollection.updateOne(
            { user_id: user.user_id },
            { $set: { "profile.experience": user.profile.experience } }
        );

        res.status(200).send(`You defeated the monster and gained ${xpGained} XP!`);
    } catch (error) {
        console.error("Error in fightMonster route:", error);
        res.status(500).send("Error fighting monster");
    }
});


app.post('/createItem', ADMIN, async (req, res) => {
    try {
        const { item_id, name, description, type, attributes, rarity } = req.body;
        const database = client.db('Cluster');
        const collection = database.collection('items');

        // Basic validation
        if (!item_id || !name || !description || !type || !attributes || !rarity) {
            return res.status(400).send("Missing required fields: item_id, name, description, type, attributes, or rarity");
        }

        const item = {
            item_id,
            name,
            description,
            type,
            attributes,
            rarity
        };

        // Insert the item into the database
        await collection.insertOne(item);
        res.status(201).send("Item created successfully");
    } catch (error) {
        console.error("Error in createItem route:", error);
        res.status(500).send("Error creating item");
    }
});


app.post('/createMonster', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { monster_id, name, attributes, location } = req.body;
        const database = client.db('Cluster');
        const collection = database.collection('monsters');

        // Basic validation
        if (!monster_id || !name || !attributes || !location) {
            return res.status(400).send("Missing required fields: monster_id, name, attributes, or location");
        }

        const monster = {
            monster_id,
            name,
            attributes,
            location
        };

        // Insert the monster into the database
        await collection.insertOne(monster);
        res.status(201).send("Monster created successfully");
    } catch (error) {
        console.error("Error in createMonster route:", error);
        res.status(500).send("Error creating monster");
    }
});

app.post('/createWeapon', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { weapon_id, name, description, damage, type, attributes } = req.body;
        const database = client.db('Cluster');
        const collection = database.collection('weapons');

        // Basic validation
        if (!weapon_id || !name || !description || !damage || !type || !attributes) {
            return res.status(400).send("Missing required fields: weapon_id, name, description, damage, type, or attributes");
        }

        const weapon = {
            weapon_id,
            name,
            description,
            damage,
            type,
            attributes
        };

        // Insert the weapon into the database
        await collection.insertOne(weapon);
        res.status(201).send("Weapon created successfully");
    } catch (error) {
        console.error("Error in createWeapon route:", error);
        res.status(500).send("Error creating weapon");
    }
});

app.get('/', (req, res) => {
    res.send('Welcome to the API');
});

// Check if a user exists
app.get('/checkUser/:user_id', async (req, res) => {
    try {
        const { user_id } = req.params;
        const userExists = await existingUser(client, user_id);

        if (userExists) {
            res.status(200).send(`User with ID ${user_id} exists.`);
        } else {
            res.status(404).send(`User with ID ${user_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking user existence:", error);
        res.status(500).send("Error checking user existence");
    }
});

// Check if an item exists
app.get('/checkItem/:item_id', async (req, res) => {
    try {
        const { item_id } = req.params;
        const itemExists = await existingItem(client, item_id);

        if (itemExists) {
            res.status(200).send(`Item with ID ${item_id} exists.`);
        } else {
            res.status(404).send(`Item with ID ${item_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking item existence:", error);
        res.status(500).send("Error checking item existence");
    }
});

// Check if a monster exists
app.get('/checkMonster/:monster_id', async (req, res) => {
    try {
        const { monster_id } = req.params;
        const monsterExists = await existingMonster(client, monster_id);

        if (monsterExists) {
            res.status(200).send(`Monster with ID ${monster_id} exists.`);
        } else {
            res.status(404).send(`Monster with ID ${monster_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking monster existence:", error);
        res.status(500).send("Error checking monster existence");
    }
});

// Check if a weapon exists
app.get('/checkWeapon/:weapon_id', async (req, res) => {
    try {
        const { weapon_id } = req.params;
        const weaponExists = await existingWeapon(client, weapon_id);

        if (weaponExists) {
            res.status(200).send(`Weapon with ID ${weapon_id} exists.`);
        } else {
            res.status(404).send(`Weapon with ID ${weapon_id} does not exist.`);
        }
    } catch (error) {
        console.error("Error checking weapon existence:", error);
        res.status(500).send("Error checking weapon existence");
    }
});

app.listen(port, async () => {
    await connectToDatabase(); // Ensure the database is connected before starting the server
    console.log(`Server is running on port ${port}`);
});