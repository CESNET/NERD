CREATE TABLE IF NOT EXISTS users (
	id	VARCHAR PRIMARY KEY,
	groups	VARCHAR[] NOT NULL,
	name	VARCHAR,
	email	VARCHAR,
	org	VARCHAR,
	api_id	VARCHAR,
	api_secret VARCHAR
);
-- testing user (used when testing on localhost by directly running nerd_main.py)
INSERT INTO users (id,groups,name,email) VALUES ('test_user','{"registered","test"}','Mr. Test','test@example.org') ON CONFLICT DO NOTHING;


