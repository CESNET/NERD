------ users ------
CREATE TABLE IF NOT EXISTS users (
	id	VARCHAR PRIMARY KEY,
	groups	VARCHAR[] NOT NULL,
	name	VARCHAR,
	email	VARCHAR,
	org	VARCHAR,
	api_token	VARCHAR
);
-- testing user (used when testing on localhost by directly running nerd_main.py)
INSERT INTO users (id,groups,name,email) VALUES ('test_user','{"registered","test"}','Mr. Test','test@example.org') ON CONFLICT DO NOTHING;


------ event database (IDEA messages) ------
CREATE TABLE IF NOT EXISTS events (
    id          VARCHAR PRIMARY KEY,
    sources     inet[], -- list of IP addresses or CIDR ranges (TODO: if "from-to" range is in IDEA, it's converted to a set of CIDR ranges)
    targets     inet[],
    detecttime  timestamp NOT NULL, -- DetectTime
    starttime   timestamp, -- EventTime or WinStartTime 
    endtime     timestamp, -- CeaseTime or WinEndTime
    idea        jsonb NOT NULL
);

--CREATE INDEX IF NOT EXISTS sources_idx ON events USING GIN (sources);
--CREATE INDEX IF NOT EXISTS targets_idx ON events USING GIN (targets);
CREATE INDEX IF NOT EXISTS detecttime_idx ON events (detecttime DESC);
CREATE INDEX IF NOT EXISTS category_idx ON events USING GIN ((idea -> 'Category'));


CREATE TABLE IF NOT EXISTS events_sources (
    source_ip inet NOT NULL,
    -- source_tags VARCHAR[] DEFAULT NULL,
    message_id VARCHAR NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    detecttime timestamp
);
CREATE INDEX IF NOT EXISTS events_sources_message_id_idx ON events_sources (message_id);
CREATE INDEX IF NOT EXISTS events_sources_ip_time_idx ON events_sources (source_ip,detecttime DESC);
CREATE INDEX IF NOT EXISTS events_sources_time_idx ON events_sources (detecttime DESC);

CREATE TABLE IF NOT EXISTS events_targets (
    target_ip inet NOT NULL,
    -- target_tags VARCHAR[] DEFAULT NULL,
    message_id VARCHAR NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    detecttime timestamp
);
CREATE INDEX IF NOT EXISTS events_targets_message_id_idx ON events_targets (message_id);
CREATE INDEX IF NOT EXISTS events_targets_ip_time_idx ON events_targets (target_ip,detecttime DESC);
CREATE INDEX IF NOT EXISTS events_targets_time_idx ON events_targets (detecttime DESC);

-- Query:
-- SELECT e.idea FROM events_sources as es INNER JOIN events as e ON es.message_id = e.id WHERE es.source_ip = %s ORDER BY es.detecttime DESC LIMIT %s

