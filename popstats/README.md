# PoP stats

This is a service that identifies all the PoP payout transactions, summarizes, calculates the incentive program points,
and reports those to Absinthe.

## How it works

This service is prepared to be run once a day as a cron job.
On each run, it gets all the HEMI token mint operations (transfers coming from the null address), filters those
originated by the depositor address (0x8888...8888), summarizes the events by recipient address, does some data
formatting and sends it to Absinthe.

In order to walk through the history more efficiently, the service processes the blocks in chunks of 7200, which is
roughly 1 day's worth of Hemi Network blocks.
Then it reports the results before taking care of the next chunk.
The intended side-effect is to report points once per day, even during the initial run where many days need to be
reported.

In addition, within each chunk, the network is queried for those transfer events in sub-chunks of 1200 blocks (4 hours)
to minimize the impact on the RPC nodes. Additional rate limits were set with the same goal.

The state of the process is stored in a single key in a Redis database so the service knows where to start at the
beginning of each run.
That state is the number of the last blocks processed and reported to Absinthe.

The data sent to Absinthe includes the address receiving the PoP payouts, the amount of points granted and some metadata
just intended for tracking/auditing purposes.

## How to run locally

Set the following environment variables in a `.env` file:

- ABSINTHE_API_URL and ABSINTHE_API_KEY: URL of the Absinthe GraphQL API and authentication JWT
- REDIS_URL: Full URI of the Redis database

Optionally, start a Redis instance and use `redis://host.docker.internal:6379` as the Redis URL:

```sh
docker run -d -p 6379:6379 -v ./redis-data:/data --name pop-stats-redis --rm redis:7-alpine redis-server --save 60 1
```

Finally, build the Docker image and start a container:

```sh
docker build -t hemilabs/pop-stats:latest .
docker run -it --env-file .env --name pop-stats --rm hemilabs/pop-stats:latest
```

The process will then start identifying and reporting all PoP payouts, then will exit.

Redis can be easily stopped by running:

```sh
docker stop $(docker ps -aqf \"name=pop-stats-redis\")
```
