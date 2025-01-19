async function viewLeaderboard(client, user_id) {
    try {
        const database = client.db('TheDune');
        const usersCollection = database.collection('users');

        const leaderboard = await usersCollection.find().sort({ 'profile.experience': -1 }).limit(10).toArray();
        return leaderboard;
    } catch (error) {
        console.error("Error in viewLeaderboard:", error);
    }
}

async function viewUserByAdmin(client, user_id) {
    try {
        const database = client.db('TheDune');
        const collection = database.collection('users');

        const user = await collection.findOne({ user_id: user_id });
        if (user) {
            return user;
        } else {
            throw new Error('User not found');
        }
    } catch (error) {
        console.error("Error in viewUserByAdmin:", error);
    }
}

module.exports = {
    viewLeaderboard,
    viewUserByAdmin
};
