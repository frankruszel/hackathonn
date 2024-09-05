# finlit
Prerequisite:
1. Create folder just for github repos
2. Have python version >=38.0

To use (not working yet as https issue):
1. git clone -b master https://github.com/frankruszel/finlit.git
2. pip install rsa
3. pip install user_agents
4. pip install device_detector
5. Go to MySQL>Local Instance > "Open script file in query tab" > paste below:

CREATE DATABASE IF NOT EXISTS pythonlogin DEFAULT CHARACTER SET utf8 COLLATE
utf8_general_ci;
USE pythonlogin;
CREATE TABLE IF NOT EXISTS accounts (
	id int(11) NOT NULL AUTO_INCREMENT,
	username varchar(50) NOT NULL,
	password varchar(255) NOT NULL,
	email varchar(100) NOT NULL,
    google_auth_enabled boolean default false,
    google_auth_secret varchar(255) default null,
    balance DECIMAL(10, 2) DEFAULT 1000,
	PRIMARY KEY (id)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
Alter table accounts add phone varchar(20);
SHOW CREATE TABLE accounts;
CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    recipient_id INT,
    amount DECIMAL(10, 2),
    transaction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('valid', 'invalid') DEFAULT 'valid',
    FOREIGN KEY (user_id) REFERENCES accounts(id),
    FOREIGN KEY (recipient_id) REFERENCES accounts(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    transaction_id INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Successful', 'Unsuccessful'),
    details VARCHAR(300),
    FOREIGN KEY (user_id) REFERENCES accounts(id),
    FOREIGN KEY (transaction_id) REFERENCES transactions(id)
);


select * from accounts;
select * from logs;
ALTER TABLE transactions ADD COLUMN date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_id VARCHAR(255),
    ip_address VARCHAR(255),
    user_agent VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE sessions ADD COLUMN device_name VARCHAR(255);
ALTER TABLE sessions ADD country VARCHAR(50);
show create table sessions;
SELECT * FROM sessions;
select * from accounts;
CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    blocked_until DATETIME NOT NULL,
    UNIQUE(ip_address)
);
select * from blocked_ips;

INSERT INTO accounts (username, password, email, phone)
VALUES ('test', 'test', 'test@test.com', '12345678');
SHOW CREATE TABLE accounts;
select * from accounts;
select * from transactions;
select * from logs;

ALTER TABLE logs 
DROP FOREIGN KEY logs_ibfk_1;

ALTER TABLE logs 
ADD CONSTRAINT logs_ibfk_1 
FOREIGN KEY (user_id) 
REFERENCES accounts(id) 
ON DELETE CASCADE;

ALTER TABLE transactions 
DROP FOREIGN KEY transactions_ibfk_1;

ALTER TABLE transactions 
ADD CONSTRAINT transactions_ibfk_1 
FOREIGN KEY (user_id) 
REFERENCES accounts(id) 
ON DELETE CASCADE;

ALTER TABLE accounts
ADD COLUMN deleted boolean default false;
