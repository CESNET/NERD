#!/bin/sh
# Remove all events older then 14 days from Event DB
d="$(date -d "-14 days" -I)T00:00:00"
echo "Removing all events older than $d ..."
psql -U nerd -d nerd_warden -c "DELETE FROM events WHERE detecttime < '$d'; DELETE FROM events_sources WHERE detecttime < '$d'; DELETE FROM events_targets WHERE detecttime < '$d';"
echo Done
