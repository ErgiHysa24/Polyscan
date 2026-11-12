-- shop-app demo data. DELIBERATELY INSECURE: passwords are unsalted MD5.
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, password_md5 TEXT NOT NULL);
CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT NOT NULL, price NUMERIC(8,2) NOT NULL);
INSERT INTO users (name, password_md5) VALUES ('alice', md5('alice-demo-pw'));
INSERT INTO products (name, price) VALUES ('running shoes', 59.90), ('leather shoes', 89.00), ('socks', 4.50);
