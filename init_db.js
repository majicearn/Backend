const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs"); // Changed to bcryptjs for consistency

// 🔧 Use environment variables for database credentials
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "majicearn_db",
  port: process.env.DB_PORT || 3306,
  multipleStatements: false // Important: Disable multiple statements
};

// Check if required environment variables are set
if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_NAME) {
  console.error("❌ Error: Database environment variables are not properly set");
  console.error("Please set DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME environment variables");
  process.exit(1);
}

async function initDB() {
  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    console.log("Connected to database ✅");

    // ---------------- SCHEMA (Split into individual statements) ----------------
    const schemaStatements = [
      `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(40) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        referral_code VARCHAR(40) UNIQUE,
        balance DECIMAL(14,2) DEFAULT 0.00,
        current_vip_level INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

      `CREATE TABLE IF NOT EXISTS vip_levels (
        id INT AUTO_INCREMENT PRIMARY KEY,
        level INT UNIQUE NOT NULL,
        price DECIMAL(14,2) NOT NULL,
        daily_earnings DECIMAL(14,2) NOT NULL,
        earning_days INT NOT NULL,
        withdrawal_rules JSON NOT NULL DEFAULT ('{}')
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

      `CREATE TABLE IF NOT EXISTS user_vip_purchases (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        vip_level_id INT NOT NULL,
        purchase_date DATETIME NOT NULL,
        expiry_date DATETIME NOT NULL,
        status ENUM('active','expired','cancelled') DEFAULT 'active',
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (vip_level_id) REFERENCES vip_levels(id),
        INDEX idx_user_vip (user_id),
        INDEX idx_vip_level (vip_level_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

      `CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type ENUM('recharge','withdrawal','earning','referral_bonus','vip_purchase','admin_adjustment') NOT NULL,
        amount DECIMAL(14,2) NOT NULL,
        status ENUM('pending','approved','rejected') DEFAULT 'pending',
        details TEXT,
        receipt_data LONGBLOB NULL,
        receipt_filename VARCHAR(255) NULL,
        receipt_type VARCHAR(100) NULL,
        account_number VARCHAR(255) NULL,
        account_name VARCHAR(255) NULL,
        notes TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        INDEX idx_user_type (user_id, type)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

      `CREATE TABLE IF NOT EXISTS referrals (
        id INT AUTO_INCREMENT PRIMARY KEY,
        referrer_id INT NOT NULL,
        referred_id INT NOT NULL,
        referral_date DATE NOT NULL,
        bonus_earned DECIMAL(14,2) DEFAULT 0.00,
        first_recharge_bonus_paid TINYINT(1) NOT NULL DEFAULT 0,
        FOREIGN KEY (referrer_id) REFERENCES users(id),
        FOREIGN KEY (referred_id) REFERENCES users(id),
        INDEX idx_referrer_id (referrer_id),
        INDEX idx_referred_id (referred_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

      `CREATE TABLE IF NOT EXISTS announcements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        visibility ENUM('all','vip','new_users') DEFAULT 'all',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
    ];

    // Execute each statement separately
    for (const statement of schemaStatements) {
      await connection.query(statement);
    }
    console.log("Tables created ✅");

    // ---------------- DEFAULT DATA ----------------
    await connection.query(`
      INSERT INTO vip_levels (level, price, daily_earnings, earning_days, withdrawal_rules)
      VALUES
      (1, 100.00, 5.00, 30, JSON_OBJECT('default', JSON_OBJECT('amount', 5000, 'fee_rate', 0.15))),
      (2, 500.00, 30.00, 30, JSON_OBJECT('default', JSON_OBJECT('amount', 10000, 'fee_rate', 0.12))),
      (3, 1000.00, 70.00, 30, JSON_OBJECT('default', JSON_OBJECT('amount', 20000, 'fee_rate', 0.10)))
      ON DUPLICATE KEY UPDATE 
        price=VALUES(price), 
        daily_earnings=VALUES(daily_earnings), 
        earning_days=VALUES(earning_days),
        withdrawal_rules=VALUES(withdrawal_rules);
    `);
    console.log("VIP levels inserted ✅");

    // Use environment variable for admin password or generate a random one
    const adminPassword = process.env.ADMIN_PASSWORD || Math.random().toString(36).slice(-10);
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    await connection.query(`
      INSERT INTO users (username, email, phone, password, referral_code, balance, current_vip_level)
      VALUES ('admin', 'admin@majicearn.com', '+1111111111', ?, 'ADMIN123', 0.00, 0)
      ON DUPLICATE KEY UPDATE username=VALUES(username);
    `, [hashedPassword]);
    
    console.log("Admin user inserted ✅");
    console.log("Admin password:", adminPassword); // Only log this in development

    await connection.query(`
      INSERT INTO announcements (title, content, visibility)
      VALUES ('Welcome to MajicEarn', 'We are live! Start earning by purchasing VIP plans.', 'all')
      ON DUPLICATE KEY UPDATE title=VALUES(title);
    `);
    console.log("Welcome announcement inserted ✅");

    console.log("Database setup completed 🎉");
  } catch (err) {
    console.error("Error setting up DB ❌", err);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

// Only run if called directly (not when imported as a module)
if (require.main === module) {
  initDB().catch(err => {
    console.error("Unhandled error in initDB:", err);
    process.exit(1);
  });
}

module.exports = { initDB };