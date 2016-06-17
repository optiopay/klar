# Klar
Integration of Clair and Docker Registry

Kalr is a simple tool to analyze images stored in a private Docker registry for security vulnerabilities using Clair https://github.com/coreos/clair. The current version doesn't support Registry authorization. Klar is designed to be used as an integration tool so it relies on enviroment variables.

Klar returns 0 if number of found high severity vulnerabilities in an image is less or equals than threshold (see below), otherwise it returns 1. 

Env vars:
* `CLAIR_ADDR` - address of Clair server, the most complete form is `http://host:port`
protocol and port may be omited, `http` and `6060` are used by default

* `CLAIR_THREHOLD` - how many high severity vulnerabilities Klar can tolerate. Default is 0

* `HTTPS_REGISTRY` - [yes|no] if the value is yes Klar will use HTTPS and port 443 to contact a Registry, otherwise HTTP and port 5000 is used. Defualt is yes.

Usage:

    CLAIR_ADDR=http://localhost CLAIR_THRESHOLD=10 ./klar docker-registry.optiopay.com/logstash:47c9e4e2e7


