#!/bin/bash
# Copyright (c) 2016 Mattermost, Inc. All Rights Reserved.
# See License.txt for license information.

echo "Starting MySQL"
/entrypoint.sh mysqld &

until mysqladmin -hlocalhost -P3306 -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" processlist &> /dev/null; do
	echo "MySQL still not ready, sleeping"
	sleep 5
done

echo "Updating CA certificates"
update-ca-certificates --fresh >/dev/null

if [ ! -e "/mm/mattermost-data/users" ]; then
    echo "-- Adding ntc admin user --"
    mattermost user create --system_admin --email "ntc@ntc.com" --username "ntc" --password "N3t2c0d3!!" &> /dev/null
	echo "-- Adding nautobot user --"
	mattermost user create --system_admin --email "nautobot@ntc.com" --username "nautobot" --password "P455word!!" &> /dev/null
	echo "-- Converting user to bot --"
	mattermost user convert nautobot --bot
	echo "-- Creating NTC team --"
	mattermost team create --name ntc --display_name "NTC"
	echo "-- Adding users to NTC team"
	mattermost team add NTC ntc nautobot
	echo "Starting platform"
	cd mattermost
	exec mattermost --config=config/config_docker.json
else
	echo "Starting platform"
	cd mattermost
	exec mattermost --config=config/config_docker.json
fi
