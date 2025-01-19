const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');


const JWT_SECRET = "Syah021015*@"; // Secure key

const app = express();
const port = process.env.port || 8080;

// MongoDB URI
const uri = "mongodb+srv://syahhasrizal:syah5599@thegame.ymr5c.mongodb.net/?retryWrites=true&w=majority&appName=TheGame";

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true
    }
});

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

// Create user route with auto-increment user_id
app.post('/createUser', async (req, res) => {
    try {
        const { username, password, email } = req.body;
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

        // Generate a unique user_id using uuid
        const user_id = uuidv4();

        const user = {
            user_id,  // Using uuid as user_id
            username,
            password,
            email,
            registration_date: new Date().toISOString(),
            profile: {
                level: 1,
                experience: 0,
                attributes: {
                    strength: 0,
                    dexterity: 0,
                    intelligence: 0
                }
            },
            inventory: []
        };

        // Insert the user into the database
        await usersCollection.insertOne(user);
        res.status(201).json({ user_id: user.user_id, message: "User created successfully" });
    } catch (error) {
        console.error("Error in createUser route:", error);
        res.status(500).send("Error creating user");
    }
});

// Login route
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).send("Missing required fields: username or password");
        }

        // Access the users collection
        const database = client.db('Cluster');
        const collection = database.collection('users');

        // Find the user by username
        const user = await collection.findOne({ username });

        if (!user) {
            return res.status(404).send("User not found");
        }

        // Check if the password matches (you should hash passwords in a real application)
        if (user.password !== password) {
            return res.status(401).send("Invalid password");
        }

        // Generate a JWT token using the hardcoded JWT_SECRET
        const token = jwt.sign({ user_id: user.user_id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

        // Respond with the token
        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Error in login route:", error);
        res.status(500).send("Error logging in");
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

// Example protected route
app.get('/protectedRoute', verifyToken, (req, res) => {
    res.status(200).send(`Hello ${req.user.username}, this is a protected route.`);
});

app.post('/createItem', async (req, res) => {
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

app.post('/createMonster', async (req, res) => {
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

app.post('/createTransaction', async (req, res) => {
    try {
        const { transaction_id, user_id, item_id, transaction_type, amount, date } = req.body;
        const database = client.db('Cluster');

        // Check if user exists
        const usersCollection = database.collection('users');
        const userExists = await usersCollection.findOne({ user_id });
        if (!userExists) {
            return res.status(404).send(`User with ID ${user_id} does not exist.`);
        }

        // Check if item exists
        const itemsCollection = database.collection('items');
        const itemExists = await itemsCollection.findOne({ item_id });
        if (!itemExists) {
            return res.status(404).send(`Item with ID ${item_id} does not exist.`);
        }

        // Insert the transaction
        const transactionsCollection = database.collection('transactions');
        const transaction = { transaction_id, user_id, item_id, transaction_type, amount, date };
        await transactionsCollection.insertOne(transaction);

        res.status(201).send("Transaction created successfully");
    } catch (error) {
        console.error("Error in createTransaction route:", error);
        res.status(500).send("Error creating transaction");
    }
});

app.post('/createWeapon', async (req, res) => {
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