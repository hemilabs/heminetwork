#! /bin/bash

set -erx

just build-image

just run $HOLOCENE_DEPLOY_CONFIG_PATH