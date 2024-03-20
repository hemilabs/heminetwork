# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM postgres:16@sha256:3648b6c2ac30de803a598afbaaef47851a6ee1795d74b4a5dcc09a22513b15c9

COPY ./database/bfgd/scripts/*.sql /docker-entrypoint-initdb.d/
