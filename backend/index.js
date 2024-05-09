require('dotenv').config();

console.log('process.env');

const pg = require('pg');

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors')
const bcrypt = require('bcrypt');
const {callback} = require("pg/lib/native/query");

const port = 3000;

const pool = new pg.Pool({
    user: process.env.PGUSER,
    host: process.env.PGHOST,
    database: process.env.PGDATABASE,
    password: process.env.PGPASSWORD,
    port: process.env.PGPORT,
    connectionTimeoutMillis: 5000
})

console.log("Connecting...:")

app.use(cors());
app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

const whitelist = ["http://localhost:8080"];
const corsOptions = {
    origin: function (origin, callback) {
        if (whitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
};

app.use(cors(corsOptions));

app.get('/authenticate/:username/:password', async (request, response) => {
    const username = request.params.username;
    const password = request.params.password;

    const query = 'SELECT * FROM users WHERE user_name=$1';
    const values = [username];

    pool.query(query, values, async (error, results) => {
        if (error) {
            throw error;
        }

        if (results.rows.length === 0) {
            response.status(401).json({authenticated: false});
            return;
        }

        const user = results.rows[0];
        const hashedPassword = user.password;

        try {
            const match = await bcrypt.compare(password, hashedPassword);
            if (match) {
                response.status(200).json({authenticated: true});
            } else {
                response.status(401).json({authenticated: false});
            }
        } catch (error) {
            console.error('Error comparing passwords:', error);
            response.status(500).json({error: 'Internal server error'});
        }
    });
});

app.listen(port, () => {
    console.log(`App running on port ${port}.`);
});

