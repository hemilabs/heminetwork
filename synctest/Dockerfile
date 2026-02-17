# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.


FROM golang:1.25.5@sha256:fef2fb55ebc8bbaf57c25561d76661ae404672e53941082a15b99c5a91808cfa AS build

WORKDIR /synctest

COPY . .

RUN CGO_ENABLED=0 go build -o /bin/synctest

FROM cgr.dev/chainguard/static@sha256:99a5f826e71115aef9f63368120a6aa518323e052297718e9bf084fb84def93c

COPY --from=build /bin/synctest /bin/synctest

ENTRYPOINT /bin/synctest
