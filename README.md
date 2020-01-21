# gcs-static-webserver

[![Travis Status](https://travis-ci.org/neomantra/gcs-static-webserver.svg?branch=master)](https://travis-ci.org/neomantra/gcs-static-webserver)  [![](https://images.microbadger.com/badges/image/neomantra/gcs-static-webserver.svg)](https://microbadger.com/#/images/neomantra/gcs-static-webserver "microbadger.com")

`gcs-static-webserver` is a Golang-based webserver that can serve static content from a path or GCS bucket.

It also exposes the following paths:
 * `/metrics` for Prometheus metrics
 * `/healthz` and `/readiness` for orchestrators

It generates an access log file to `stdout`.

## Configuration

`gcs-static-webserver` is configured with environment variables:

|Name              |Type    |Default        |Description  |
|:---------------- |:------:|:------------- |:----------- |
| DEBUG            | bool   | `false`       | Debug mode (`true` to enable) |
| ADDRESS          | string | `""`          | Address to listen to |
| PORT             | int    | 80            | Port to listen on  |
| SUB_PATH         | string |               | Sub-path to PathPrefix |
| STATIC_DIR       | string |               | Static directory to serve |
| STATIC_SUB_PATH  | string | `"/static"`   | URL sub-path to serve `STATIC_DIR` from |
| BUCKET           | string |               | GCS Bucket to serve |
| BUCKET_SUB_PATH  | string | `"/"`         | URL sub-path to serve GCS bucket from |
| BUCKET_CRED_PATH | string | `"/key.json"` | Bucket Service Account JSON Credentials Path |
| AUTH_DOMAIN      | string |               | Authentication Policy Domain for JWT verification |
| AUTH_AUD         | string |               | Authentication Policy Audience (AUD) for JWT verification |
| AUTH_HEADER      | string |               | Header Key to check for for JWT verification |

## Build and Run

Native:

```
go build

PORT=8000 STATIC_DIR=my/path STATIC_SUB_PATH=/foo ./gcs-static-webserver
```

Containerized:

```
docker build -t gcs-static-webserver .

docker run \
    -v service_key.json:/key.json:ro \
    -p 8000:8000 \
    --env PORT=8000 \
    --env BUCKET=my-bucket \
    --env BUCKET_SUB_PATH=/foo \
    gcs-static-webserver
```

----

## License

Copyright (c) 2020 Neomantra Corp.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
