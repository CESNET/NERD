------ users ------
CREATE TABLE IF NOT EXISTS users (
	id	VARCHAR PRIMARY KEY,
	groups	VARCHAR[] NOT NULL,
	name	VARCHAR,
	email	VARCHAR,
	org	VARCHAR,
	api_token	VARCHAR,
	rl_bs	REAL,
	rl_tps	REAL,
	t_last_login	VARCHAR,
	t_last_api_call	VARCHAR
);
-- testing users
--INSERT INTO users (id,groups,name,email) VALUES ('devel:devel_admin','{"admin","registered"}','Mr. Developer','test@example.org') ON CONFLICT DO NOTHING;
--INSERT INTO users (id,groups,name,email) VALUES ('local:test','{"registered"}','Mr. Test','test@example.org') ON CONFLICT DO NOTHING;
--INSERT INTO users (id,groups,name,api_token) VALUES ('api_user','{"registered"}','API_USER','TOKEN') ON CONFLICT DO NOTHING;
