async function createUser(client, user_id, username, password, email) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        const user = {
            user_id: user_id,
            username: username,
            password: password,
            email: email,
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

        await collection.insertOne(user);
        console.log("User created successfully");
    } catch (error) {
        console.error("Error creating user:", error);
    }
}

async function createItem(client, item_id, name, description, type, attributes, rarity) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('items');

        const item = {
            item_id: item_id,
            name: name,
            description: description,
            type: type,
            attributes: attributes,
            rarity: rarity
        };

        await collection.insertOne(item);
        console.log("Item created successfully");
    } catch (error) {
        console.error("Error creating item:", error);
    }
}

async function createMonster(client, monster_id, name, attributes, location) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('monster');

        const monster = {
            monster_id: monster_id,
            name: name,
            attributes: attributes,
            location: location
        };

        await collection.insertOne(monster);
        console.log("Monster created successfully");
    } catch (error) {
        console.error("Error creating monster:", error);
    }
}

async function createTransaction(client, transaction_id, user_id, item_id, transaction_type, amount, date) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('transaction');

        const transaction = {
            transaction_id: transaction_id,
            user_id: user_id,
            item_id: item_id,
            transaction_type: transaction_type,
            amount: amount,
            date: date
        };

        await collection.insertOne(transaction);
        console.log("Transaction created successfully");
    } catch (error) {
        console.error("Error creating transaction:", error);
    }
}

async function createWeapon(client, weapon_id, name, description, damage, type, attributes) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('weapons');

        const weapon = {
            weapon_id: weapon_id,
            name: name,
            description: description,
            damage: damage,
            type: type,
            attributes: attributes
        };

        await collection.insertOne(weapon);
        console.log("Weapon created successfully");
    } catch (error) {
        console.error("Error creating weapon:", error);
    }
}

module.exports = {
    createUser,
    createItem,
    createMonster,
    createTransaction,
    createWeapon
};
