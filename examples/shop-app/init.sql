-- shop-app demo data. DELIBERATELY INSECURE: passwords are unsalted MD5.
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, password_md5 TEXT NOT NULL,
                    totp_secret TEXT, totp_last_step BIGINT NOT NULL DEFAULT -1);
CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT NOT NULL, price NUMERIC(8,2) NOT NULL);
-- alice logs in with the password only; bob also needs the code of an authenticator app.
-- bob's secret is public demo data (JBSWY3DPEHPK3PXP): a real secret is never written in a file.
INSERT INTO users (name, password_md5) VALUES ('alice', md5('alice-demo-pw'));
INSERT INTO users (name, password_md5, totp_secret) VALUES ('bob', md5('bob-demo-pw'), 'JBSWY3DPEHPK3PXP');
INSERT INTO products (name, price) VALUES ('running shoes', 59.90), ('leather shoes', 89.00), ('socks', 4.50);
