const fs = require('fs')

/**
 * Check if user exist on the database
 * @param username
 * @returns {Promise<boolean|*>}
 */

const checkIfUserExists = (username) => {
    console.log('Checking if user exists')

    const users = JSON.parse(fs.readFileSync('./data/users.json'))

    const user = users.users.find(u => u.username == username)
    console.log(user)
    if(user) {
        return true
    }
    console.log('No ha retornat true')
    return false;
};

const insertUser = async (username, password) => {

    console.log('Inserting user')

    const users = JSON.parse(fs.readFileSync('./data/users.json'))
    console.log('Fitxer llegit')
    const newUser = {
        "username": username,
        "password": password
    };

    users.users.push(newUser)

    fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2))

    console.log('Inserted user')
}

module.exports = {
    checkIfUserExists,
    insertUser,
};