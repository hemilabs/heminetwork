FROM node:20.9.0-alpine3.18@sha256:cb2301e2c5fe3165ba2616591efe53b4b6223849ac0871c138f56d5f7ae8be4b

WORKDIR /app

# put this in a package.json file 
RUN npm install --save-dev-exact hardhat@2.26.0
