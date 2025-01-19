async function monsterslain(client, user_id, monster_id) {
    try {
        const database = client.db('TheDune');
        const usersCollection = database.collection('users');
        const monstersCollection = database.collection('monster');

        const user = await usersCollection.findOne({ user_id: user_id });
        const monster = await monstersCollection.findOne({ monster_id: monster_id });

        if (user && monster) {
            user.profile.experience += monster.attributes.experience;
            await usersCollection.updateOne({ user_id: user_id }, { $set: { profile: user.profile } });
            return user.profile;
        } else {
            throw new Error('User or monster not found');
        }
    } catch (error) {
        console.error("Error in monsterslain:", error);
    }
}

async function deleteUser(client, user_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        await collection.deleteOne({ user_id: user_id });
        console.log("User deleted successfully");
    } catch (error) {
        console.error("Error deleting user:", error);
    }
}

async function reportUser(client, user_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id: user_id });
        if (user) {
            return {
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                profile: user.profile
            };
        } else {
            throw new Error('User not found');
        }
    } catch (error) {
        console.error("Error reporting user:", error);
    }
}

module.exports = {
    monsterslain,
    deleteUser,
    reportUser
};
