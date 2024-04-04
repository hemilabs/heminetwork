# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.22.0@sha256:03082deb6ae090a0caa4e4a8f666bc59715bc6fa67f5fd109f823a0c4e1efc2a

WORKDIR /mocktimism

COPY . .

RUN go build -o ./mocktimism ./e2e/mocktimism 

CMD /mocktimism/mocktimism