# go-opensaml

Retrieve SAML token using default external browser and write it to stdin.

Using [go browser pkg](https://pkg.go.dev/github.com/pkg/browser)

## Installation

```shell
go install github.com/swchck/go-opensaml@latest
```

## Usage

```shell
go-opensaml -s <server> [-p <port>] [-r <realm>] [-t]
Usage of ./opensaml:
  -p, --port int        Port to connect to (default 8020)
  -r, --realm string    Realm to authenticate to
  -s, --server string   Server to connect to
  -t, --trust-all       Trust all certificates
```

## Using wth openfortivpn

### bash

```shell
srv=<server-url>; go-opensaml -s $srv | sudo openfortivpn $srv --cookie-on-stdin
```

### fish

```shell
set srv <server-url>; go-opensaml -s $srv | sudo openfortivpn $srv --cookie-on-stdin
```

## Build Locally

For local build, run task `build`:

```shell
task build
```
Binary file will be created in `bin` directory.