// config/db.js
const mysql = require('mysql2/promise');

let pool;
let dbReady = false;

// Validate that required environment variables are set
if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_NAME) {
  console.error("❌ Error: Database environment variables are not properly set");
  console.error("Please set DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME environment variables");
  // Don't exit immediately as this might be imported as a module
}

async function initializeDatabase() {
  try {
    console.log('Initializing database connection...');
    
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      timezone: 'Z',
      enableKeepAlive: true,
      keepAliveInitialDelay: 10000,
      ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
      }
    });

    // Test connection
    const conn = await pool.getConnection();
    await conn.query('SELECT 1 + 1 AS solution');
    conn.release();
    
    dbReady = true;
    console.log("✅ Database pool created successfully");
    return pool;
  } catch (err) {
    console.error("❌ DB connection failed:", err.message);
    
    // Try to reconnect every 5 seconds
    setTimeout(() => {
      console.log('Attempting database reconnection...');
      initializeDatabase();
    }, 5000);
    throw err;
  }
}

// Get the pool directly
function getPool() {
  if (!dbReady) {
    throw new Error('Database not ready');
  }
  return pool;
}

// Check if database is ready
function isReady() {
  return dbReady;
}

// For direct queries like in your example
async function query(sql, params) {
  if (!dbReady) {
    throw new Error('Database not ready');
  }
  return await pool.query(sql, params);
}

// Export both the pool and the functions for flexibility
module.exports = pool;
module.exports.initializeDatabase = initializeDatabase;
module.exports.getPool = getPool;
module.exports.isReady = isReady;
module.exports.query = query;