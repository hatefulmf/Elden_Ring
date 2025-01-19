async function existingUser(client, user_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id: user_id });
        return user !== null;
    } catch (error) {
        console.error("Error checking existing user:", error);
    }
}

async function existingItem(client, item_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('items');

        const item = await collection.findOne({ item_id: item_id });
        return item !== null;
    } catch (error) {
        console.error("Error checking existing item:", error);
    }
}

async function existingMonster(client, monster_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('monsters');

        const monster = await collection.findOne({ monster_id: monster_id });
        return monster !== null;
    } catch (error) {
        console.error("Error checking existing monster:", error);
    }
}

async function existingWeapon(client, weapon_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('weapons');

        const weapon = await collection.findOne({ weapon_id: weapon_id });
        return weapon !== null;
    } catch (error) {
        console.error("Error checking existing weapon:", error);
    }
}

module.exports = {
    existingUser,
    existingItem,
    existingMonster,
    existingWeapon
};
