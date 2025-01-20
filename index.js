const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const rateLimit = require('express-rate-limit');

const credentials = process.env.CERTIFICATE; // Use CERTIFICATE from .env
const JWT_SECRET = process.env.JWT_SECRET;
const app = express();
const port = process.env.PORT || 8080;
const uri = process.env.MONGO_URI; // Use MONGO_URI from .env

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
  });

// Middleware to parse JSON requests
app.use(express.json());

// Connect to MongoDB when the server starts
async function connectToDB() {
    try {
      client = new MongoClient(uri, {
        tlsCertificateKeyFile: credentials,
        serverApi: ServerApiVersion.v1,
      });
      await client.connect();
      console.log("Connected to MongoDB");
    } catch (error) {
      console.error("Error connecting to MongoDB:", error.message);
    }
  }
  
  // Call connectToDB once when the app starts
  connectToDB();
  
// Middleware to verify the token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    // Ensure the header exists and starts with 'Bearer'
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).send("Token is required or improperly formatted");
    }

    // Extract the token from the header
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error("JWT verification error:", err.message); // Log the error for debugging
            return res.status(401).send("Invalid or expired token");
        }

        req.user = decoded; // Attach the decoded user information to the request
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

app.use(express.json());

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

// Login route

// Apply rate limiter only for login route
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 3, // Allow 3 failed attempts per minute per username
    keyGenerator: (req) => req.body.username || req.ip, // Use username if available, fallback to IP
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.log(`Rate limit exceeded for ${req.body.username || req.ip}`);
        res.status(429).send("Too many failed login attempts, please try again later.");
    }
});

// Login route with rate limiter middleware
app.post('/login', loginLimiter, async (req, res) => {
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

        // Check password validity
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).send("Invalid password");
        }

        // Generate JWT token on successful login
        const token = jwt.sign({ user_id: user.user_id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Error in login route:", error);
        res.status(500).send("Error logging in");
    }
});

module.exports = loginLimiter;

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