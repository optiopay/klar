# Klar
Integration of Clair and Docker Registry

Klar is a simple tool to analyze images stored in a private or public  Docker registry for security vulnerabilities using Clair https://github.com/coreos/clair. Klar is designed to be used as an integration tool so it relies on enviroment variables. It's a single binary which requires no dependencies.

## Installation

Make sure you have Go language compiler installed and configured https://golang.org/doc/install

If your Go binary folder is in your `PATH` (e.g. `export PATH=$PATH:/usr/local/go/bin`) you may want to:

    go install .

Otherwise you can just build it in the project folder

    go build .

And copy `klar` binary to a folder in your `PATH`.


## Usage

Klar process returns `0` if number of detected high severity vulnerabilities in an image is less or equals than threshold (see below), otherwise it returns `1`.

Klar can be configured via the following environment variables:

* `CLAIR_ADDR` - address of Clair server, the most complete form is `protocol://host:port`
protocol and port may be omited, `http` and `6060` are used by default

* `CLAIR_THRESHOLD` - how many high severity vulnerabilities Klar can tolerate before returning `1`. Default is 0.

* `DOCKER_USER` - Docker registry account name

* `DOCKER_PASSWORD` - Docker registry account password

Usage:

    CLAIR_ADDR=http://localhost CLAIR_THRESHOLD=10 DOCKER_USER=me DOCKER_PASSWORD=secret klar postgres:9.5.1

## Dockerized version

Klar can be dockerized. Build Klar in project root first:

    go build .

If you are on Mac don't forget to build it for Linux:

    GOOS=linux go build .

To build Docker image run in the project root (replace `klar` with fully qualified name if you like):
   
    docker build -t klar .

Then create an env file or pass env vars as separate ``--env` arguments. For example save it as `my-klar.env`
    
    CLAIR_ADDR=http://localhost
    CLAIR_THRESHOLD=10
    DOCKER_USER=me
    DOCKER_PASSWORD=secret

Then run

    docker run --env-file=my-klar-env klar postgres:9.5.1


