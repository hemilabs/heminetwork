## Running extended tests

Create a user that has CREATEDB privilege.
```
sudo -u postgres psql -c "CREATE ROLE tbcdtest WITH LOGIN PASSWORD 'password' NOSUPERUSER CREATEDB;"
```

run tests:
```
PGTESTURI="postgres://tbcdtest:password@localhost/postgres" go test -v ./...
```
