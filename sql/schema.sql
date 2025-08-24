-- MySQL schema for MajicEarn (optimized version)

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  phone VARCHAR(40) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL, -- store only hashed password (bcrypt)
  referral_code VARCHAR(40) UNIQUE,
  balance DECIMAL(14,2) DEFAULT 0.00,
  current_vip_level INT DEFAULT 0,
  withdrawal_account_number VARCHAR(255) DEFAULT NULL,
  withdrawal_account_name VARCHAR(255) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vip_levels (
  id INT AUTO_INCREMENT PRIMARY KEY,
  level INT UNIQUE NOT NULL,
  price DECIMAL(14,2) NOT NULL,
  daily_earnings DECIMAL(14,2) NOT NULL,
  earning_days INT NOT NULL,
  withdrawal_rules JSON NOT NULL DEFAULT ('{}')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_vip_purchases (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  vip_level_id INT NOT NULL,
  purchase_date DATETIME NOT NULL,
  expiry_date DATETIME NOT NULL,
  active TINYINT(1) DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (vip_level_id) REFERENCES vip_levels(id),
  INDEX idx_user_vip (user_id),
  INDEX idx_vip_level (vip_level_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  type ENUM('recharge','withdrawal','earning','referral_bonus','vip_purchase','admin_adjustment') NOT NULL,
  amount DECIMAL(14,2) NOT NULL,
  status ENUM('pending','approved','rejected') DEFAULT 'pending',
  details TEXT,
  account_number VARCHAR(255),
  account_name VARCHAR(255),
  receipt_data LONGBLOB,
  receipt_filename VARCHAR(255),
  receipt_type VARCHAR(100),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  INDEX idx_user_id (user_id),
  INDEX idx_type (type),
  INDEX idx_user_type (user_id, type),
  INDEX idx_created_at (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS referrals (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS announcements (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  visibility ENUM('all','vip','new_users') DEFAULT 'all',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Default Data Bootstrap

-- Insert VIP levels
INSERT INTO vip_levels (level, price, daily_earnings, earning_days, withdrawal_rules)
VALUES
(1, 100.00, 5.00, 30, JSON_OBJECT('min_withdrawal', 50, 'max_withdrawal', 500)),
(2, 500.00, 30.00, 30, JSON_OBJECT('min_withdrawal', 100, 'max_withdrawal', 2000)),
(3, 1000.00, 70.00, 30, JSON_OBJECT('min_withdrawal', 200, 'max_withdrawal', 5000))
ON DUPLICATE KEY UPDATE level=VALUES(level);

-- Insert admin user (password must be bcrypt-hashed!)
INSERT INTO users (username, email, phone, password, referral_code, balance, current_vip_level)
VALUES ('admin', 'admin@majicearn.com', '+1111111111', 'HASHED_PASSWORD_HERE', 'ADMIN123', 0.00, 0)
ON DUPLICATE KEY UPDATE username=VALUES(username);

-- Insert welcome announcement
INSERT INTO announcements (title, content, visibility)
VALUES ('Welcome to MajicEarn', 'We are live! Start earning by purchasing VIP plans.', 'all')
ON DUPLICATE KEY UPDATE title=VALUES(title);
