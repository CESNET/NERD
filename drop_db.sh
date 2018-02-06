/usr/bin/mongo nerd --quiet --eval 'db.ip.drop(); db.asn.drop(); db.bgppref.drop(); db.ipblock.drop(); db.org.drop()'
/usr/bin/psql -c 'delete from events;' nerd nerd