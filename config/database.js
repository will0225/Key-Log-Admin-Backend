const mysql = require('mysql2');

require('dotenv').config();

function connectToDatabase() {

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

connection.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database');
});

return connection;

}

let connection = connectToDatabase();

// If connection is closed, reconnect
connection.on('error', function(err) {
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
      console.log('Connection lost. Reconnecting...');
      connection = connectToDatabase(); // Reconnect on lost connection
    }
  });
  
module.exports = connection;