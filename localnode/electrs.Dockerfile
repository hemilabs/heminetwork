FROM blockstream/esplora@sha256:1db92e95b55cdea9e1fcb80f94dabff66f6aa370574a02af4baeecefd1d6c236

RUN apt update

RUN apt install -y netcat

HEALTHCHECK --interval=5s --timeout=5s --retries=999999 CMD nc -vz 0.0.0.0 50001
