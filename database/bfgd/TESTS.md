## Running extended tests

Create a user that has CREATEDB privilege.
```
sudo -u postgres psql -c "CREATE ROLE bfgdtest WITH LOGIN PASSWORD 'password' NOSUPERUSER CREATEDB;"
```

run tests:
```
PGTESTURI="postgres://bfgdtest:password@localhost/postgres" go test -v ./...
```
