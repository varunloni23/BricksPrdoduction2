-- Create database
CREATE DATABASE IF NOT EXISTS bricks_production;
USE bricks_production;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'customer') NOT NULL DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    image_url VARCHAR(255) DEFAULT 'default.jpg',
    featured BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id VARCHAR(50) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled', 'Paid') DEFAULT 'Pending',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Order items table
CREATE TABLE IF NOT EXISTS order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id VARCHAR(50) NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

-- Insert admin user
INSERT INTO users (username, email, password, role)
VALUES ('admin', 'admin@example.com', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwlOLrgK6Kb/PZr0D/QJmPn7u0W', 'admin');

-- Insert sample products
INSERT INTO products (name, description, price, stock, image_url, featured) VALUES
('Red Clay Bricks', 'High-quality red clay bricks perfect for exterior walls and facades.', 0.75, 5000, 'red_brick.jpg', 1),
('Concrete Blocks', 'Durable concrete blocks ideal for foundations and structural walls.', 1.20, 3000, 'concrete_block.jpg', 1),
('Facing Bricks', 'Premium facing bricks with a smooth finish for decorative purposes.', 1.50, 2000, 'facing_brick.jpg', 1),
('Engineering Bricks', 'High-density engineering bricks with excellent load-bearing capacity.', 1.35, 4000, 'engineering_brick.jpg', 0),
('Hollow Bricks', 'Lightweight hollow bricks for interior walls with improved insulation.', 0.90, 3500, 'hollow_brick.jpg', 0),
('Fly Ash Bricks', 'Eco-friendly fly ash bricks made from recycled materials.', 0.80, 2500, 'fly_ash_brick.jpg', 1),
('Fire Bricks', 'Heat-resistant fire bricks for fireplaces, kilns, and furnaces.', 2.25, 1500, 'fire_brick.jpg', 0),
('Interlocking Bricks', 'Modern interlocking bricks for quick and easy construction.', 1.80, 2000, 'interlocking_brick.jpg', 1); 