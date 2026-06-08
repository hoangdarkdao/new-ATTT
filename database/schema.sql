-- Create database
CREATE DATABASE IF NOT EXISTS blog_db;
USE blog_db;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    bio TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create posts table
CREATE TABLE IF NOT EXISTS posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    content LONGTEXT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create comments table
CREATE TABLE IF NOT EXISTS comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content TEXT NOT NULL,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sample data
INSERT INTO users (username, email, password, bio) VALUES 
('admin', 'admin@blog.local', 'admin123', 'Blog Administrator'),
('user1', 'user1@blog.local', 'password123', 'First user on the blog');

INSERT INTO posts (title, content, user_id) VALUES 
('Welcome to Our Blog', 'This is the first post on our blog. Feel free to explore and comment!', 1),
('Security Testing', 'A post about security testing and authentication mechanisms.', 2);

INSERT INTO comments (content, post_id, user_id) VALUES 
('Great post! Thanks for sharing.', 1, 2),
('Very informative article.', 2, 1);
