// 1. Load our secret .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Tell the server to accept and read JSON data from the frontend
// UPGRADED FOR DEPLOYMENT: Increased payload limit to 50mb
app.use(cors()); 
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 3. Set up the Database Connection using our secret keys
// --- UPGRADED: ADDED AIVEN SSL AND PORT REQUIREMENTS ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306, // Aiven uses custom ports!
    ssl: {
        rejectUnauthorized: false // CRITICAL: Aiven will block the connection without this!
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// 4. Test the connection to MySQL
db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('✅ Successfully connected to the Secure Aiven MySQL database!');
        connection.release(); // Important: Release connection back to the pool
    }
});

// --- NEW API ROUTE ---
app.get('/api/products', (req, res) => {
    db.query('SELECT * FROM products', (err, results) => {
        if (err) {
            console.error('Error fetching products:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        // Temporarily add default sizes to our products until we build a size manager
        const productsWithSizes = results.map(product => {
            return { ...product, sizes: ["S", "M", "L", "XL"], img: product.image_url };
        });

        res.json(productsWithSizes);
    });
});

// --- SECURE ADMIN LOGIN API ---
app.post('/api/admin/login', (req, res) => {
    console.log("--- NEW LOGIN ATTEMPT ---");
    
    const sqlQuery = 'SELECT * FROM admins WHERE username = ?';
    db.query(sqlQuery, ['admin'], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
        
        if (results.length > 0) {
            const databaseHash = results[0].password;
            const isMatch = await bcrypt.compare(req.body.password, databaseHash);
            
            if (isMatch) {
                res.json({ success: true, message: 'Login successful' });
            } else {
                res.status(401).json({ success: false, message: 'Incorrect password' });
            }
        } else {
            console.log("Admin user not found in database!");
            res.status(401).json({ success: false, message: 'Admin not found' });
        }
    });
});

// --- PLACE NEW ORDER API ---
app.post('/api/orders', (req, res) => {
    const { id, date, items, total, method, status, shipping_charge, shipping_zone } = req.body;
    const itemsJson = JSON.stringify(items);

    const sqlQuery = 'INSERT INTO orders (order_id, order_date, items, total, payment_method, status, shipping_charge, shipping_zone) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    
    db.query(sqlQuery, [id, date, itemsJson, total, method, status, shipping_charge, shipping_zone], (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        res.json({ success: true, message: 'Order saved successfully' });
    });
});

// Serve the frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// ==========================================
// CUSTOMER AUTHENTICATION ROUTES
// ==========================================

const JWT_SECRET = process.env.JWT_SECRET || 'hollywood_collections_secret_key_2026';

// 1. Customer Registration
app.post('/api/register', async (req, res) => {
    const { name, email, password, phone } = req.body;

    try {
        db.query('SELECT email FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error("Database Error during registration:", err.message);
                return res.status(500).json({ error: 'Database error: Ensure users table exists.' });
            }

            if (results.length > 0) return res.status(400).json({ error: 'Email already in use.' });

            const hashedPassword = await bcrypt.hash(password, 10);
            const insertQuery = 'INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)';
            
            db.query(insertQuery, [name, email, hashedPassword, phone], (err) => {
                if (err) {
                    console.error("Database Error saving user:", err.message);
                    return res.status(500).json({ error: 'Could not save user.' });
                }
                res.status(201).json({ message: 'Registration successful! Please log in.' });
            });
        });
    } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. Customer Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error("Database Error during login:", err.message);
            return res.status(500).json({ error: 'Database connection issue.' });
        }

        if (results.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(401).json({ error: 'Invalid email or password.' });

        const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            message: 'Login successful', 
            token, 
            user: { name: user.name, email: user.email, phone: user.phone } 
        });
    });
});

// Start the server
// UPGRADED FOR DEPLOYMENT: Cloud hosts assign a dynamic PORT environment variable.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running for Hollywood Collections on port ${PORT}`);
});
