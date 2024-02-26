#!/bin/sh
#
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.
#

set -e
set -u
#set -x

if [ -z "${PSQL:-}" ]; then
	PSQL=psql
fi

if [ -z "${DBUSER:-}" ]; then
	DBUSER=$(whoami)
fi

if [ -z "${DBNAME:-}" ]; then
	echo "must provide DBNAME"
	exit 1
fi


if [ -z "${DBSOCKET:-}" ]; then
	DBSOCKET=""
fi

psqlexecute() {
	local dbname=$1
	shift 1
	DATABASE_URL="postgres://${DBUSER}@:/${dbname}?host=${DBSOCKET}"
	${PSQL} ${DATABASE_URL} "$@"
}

applysql() {
	for sqlfile in ${@}; do
		echo "Applying $sqlfile"
		psqlexecute ${DBNAME} -f ${sqlfile}
	done
}

createdb() {
	echo "Creating database ${DBNAME}"
	psqlexecute postgres -c "CREATE DATABASE ${DBNAME};"
	upgradedb
}

dropdb() {
	echo "Dropping database ${DBNAME}"
	psqlexecute postgres -c "DROP DATABASE ${DBNAME};"
}

populatedb() {
	SQLFILES=$(ls testdata/*.sql | sort -n)
	applysql ${SQLFILES}
}

upgradedb() {
	echo "Upgrading database..."
	local dbexists=$(psqlexecute template1 -t -c "SELECT 'exists' FROM pg_database WHERE datname='${DBNAME}'" | head -n 1 | sed 's/\s//g')
	if [ -z "${dbexists}" ]; then
		echo "Database '${DBNAME}' does not exist, aborting..."
		return
	fi
	local exists=$(psqlexecute ${DBNAME} -t -c "SELECT 'exists' FROM pg_tables WHERE tablename = 'version'" | head -n 1 | sed 's/\s//g')
	version=0
	if [ -n "${exists}" ]; then
		version=$(psqlexecute ${DBNAME} -t -c "SELECT version FROM version;" | head -n 1 | sed 's/\s//g')
	fi
	echo "Current version: $version"

	SQLFILES=$(ls *.sql | sort -n)
	for sqlfile in ${SQLFILES}; do
		fv=$(echo $sqlfile | cut -d. -f1)
		if [ $version -lt $fv ]; then
			echo "Applying $sqlfile"
			applysql $sqlfile
		fi
	done
}
