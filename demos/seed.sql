-- Reproducible schema for the "blast radius" demo (README demo 2 / demo 2.tape).
-- Usage: createdb shop && psql -d shop -f demos/seed.sql
DROP TABLE IF EXISTS audit_log, sessions, orders, users CASCADE;
CREATE TABLE users     (id serial PRIMARY KEY, email text);
CREATE TABLE orders    (id serial PRIMARY KEY, user_id int REFERENCES users(id), total numeric);
CREATE TABLE sessions  (id serial PRIMARY KEY, user_id int REFERENCES users(id), token text);
CREATE TABLE audit_log (id serial PRIMARY KEY, actor_id int REFERENCES users(id), action text);
INSERT INTO users (email)       SELECT 'user'||g||'@example.com'            FROM generate_series(1,50000) g;
INSERT INTO orders (user_id,total) SELECT (random()*49999)::int+1, random()*100 FROM generate_series(1,240000);
INSERT INTO sessions (user_id,token) SELECT (random()*49999)::int+1, md5(g::text) FROM generate_series(1,120000) g;
ANALYZE;
