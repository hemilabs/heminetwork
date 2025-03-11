FROM blockstream/esplora@sha256:1fb16180f430f75da28eca37a265630c7192b3c103aafd9b9ba4bf5b6d9c8ea8

RUN apt update

RUN apt install -y netcat

HEALTHCHECK --interval=5s --timeout=5s --retries=999999 CMD nc -vz 0.0.0.0 50001
