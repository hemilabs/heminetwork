# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.


FROM golang:1.25.5@sha256:fef2fb55ebc8bbaf57c25561d76661ae404672e53941082a15b99c5a91808cfa

WORKDIR /synctest

COPY . .

RUN go build -o /bin/synctest

CMD /bin/synctest
