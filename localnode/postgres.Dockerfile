# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM postgres:16.9-alpine3.20@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054

COPY ./database/bfgd/scripts/*.sql /docker-entrypoint-initdb.d/
