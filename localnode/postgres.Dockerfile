# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM postgres:16.3-alpine3.20@sha256:36ed71227ae36305d26382657c0b96cbaf298427b3f1eaeb10d77a6dea3eec41

COPY ./database/bfgd/scripts/*.sql /docker-entrypoint-initdb.d/
