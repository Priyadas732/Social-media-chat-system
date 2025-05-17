CREATE DATABASE chatdb;

USE chatdb;

CREATE TABLE chat_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255),
    receiver VARCHAR(255),
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
