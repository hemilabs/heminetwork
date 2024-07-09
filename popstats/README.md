# PoP stats

This PR adds a service that will identify all the PoP payout transactions, summarize, calculate the incentive program points and report those to Absinthe.

## How it works

This service is prepared to be run once a day as a cron job.
On each run, it gets all the HEMI token mint operations (transfers coming from the null address), filters those originated by the depositor address (0x8888...8888), summarize the events by recipient address, do some data formatting and send it to Absinthe.

In order to walk through the history more efficiently, the service processes the blocks in chunks of 7200, which is roughly 1 day worth of Hemi Network blocks.
Then it reports the results before taking care of the next chunk.
The intended side-effect is to report points once per day, even during the initial run where many days need to be reported.

In addition, within each chunk, the network is queried for those transfer events in sub-chunks of 1200 blocks (4 hours) to minimize the impact on the RPC nodes. Additional rate limits were set with the same goal.

The state of the process is stored in a single key in a Redis database so the service knows where to start at the beginning of each run.
That state is the number of the last blocks processed and reported to Absinthe.

The data sent to Absinthe includes the address receiving the PoP payouts, the amount of points granted and some metadata just intended for tracking/auditing purposes.

## How to run locally

Set the following environment variables in a `.env` file:

- ABSINTHE_API_URL and ABSINTHE_API_KEY: URL of the Absinthe GraphQL API and authentication JWT
- REDIS_URL: Full URI of the Redis database

Optionally, start a Redis instance:

```sh
npm run redis:start
```

Finally, build the Docker image and start a container:

```sh
npm run docker:build
npm run docker:run
```

The process will then start identifying and reporting all PoP payouts, then will exit.
