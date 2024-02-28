#!/bin/sh
#
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.
#

if [ -z ${PSQL} ]; then
	PSQL=psql
fi

if [ -z ${DBNAME} ]; then
	DBNAME=tbcdb
fi

. ../../scripts/db.sh
