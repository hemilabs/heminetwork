# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM node:22-alpine@sha256:4162c8a0f1fef9d3b003eb1fd3d8a26db46815288832aa453d829f4129d4dfd3

# Build metadata
ARG VERSION
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.created=$BUILD_DATE \
  org.opencontainers.image.authors="Hemi Labs" \
  org.opencontainers.image.url="https://github.com/hemilabs/heminetwork" \
  org.opencontainers.image.source="https://github.com/hemilabs/heminetwork" \
  org.opencontainers.image.version=$VERSION \
  org.opencontainers.image.revision=$VCS_REF \
  org.opencontainers.image.vendor="Hemi Labs" \
  org.opencontainers.image.licenses="MIT" \
  org.opencontainers.image.title="PoP stats" \
  org.label-schema.build-date=$BUILD_DATE \
  org.label-schema.name="PoP stats" \
  org.label-schema.url="https://github.com/hemilabs/heminetwork" \
  org.label-schema.vcs-url="https://github.com/hemilabs/heminetwork" \
  org.label-schema.vcs-ref=$VCS_REF \
  org.label-schema.vendor="Hemi Labs" \
  org.label-schema.version=$VERSION \
  org.label-schema.schema-version="1.0"

WORKDIR /home/node/app

COPY package.json pnpm-lock.yaml .
RUN corepack enable
RUN pnpm install --prod
COPY . .

USER node

CMD [ "node", "server.js"]
