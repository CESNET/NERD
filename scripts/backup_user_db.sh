#!/usr/bin/sh
# Dump NERD user database into an .sql file "./db_backup_<current_date>.sql".
date=$(date -I)
pg_dump -U nerd nerd_users -t users -f db_backup_$date.sql
echo "Dump of database 'nerd_users' (table 'users' only) stored into db_backup_$date.sql"

