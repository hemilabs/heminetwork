# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.22.2-alpine@sha256:cdc86d9f363e8786845bea2040312b4efa321b828acdeb26f393faa864d887b0

WORKDIR /mocktimism

COPY . .

RUN go build -o ./mocktimism ./e2e/mocktimism 

CMD /mocktimism/mocktimism