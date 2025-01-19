async function findUserByUsername(client, username) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        const user = await collection.findOne({ username: username });
        return user;
    } catch (error) {
        console.error("Error finding user by username:", error);
    }
}

async function findUserById(client, user_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id: user_id });
        return user;
    } catch (error) {
        console.error("Error finding user by ID:", error);
    }
}

module.exports = {
    findUserByUsername,
    findUserById
};
