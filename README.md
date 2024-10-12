# gitea-act-dynamic

A tiny service that spools up an AWS instance as a Gitea act runner in response to webhook events, and optionally it can watch the gitea database (currently only sqlite is supported) for pending jobs.

## Configuration

| Environment Variable  | Required | Example Value       | Description |
| :-------------------- | -------- | :------------------ | :---------- |
| AWS_REGION            | yes      |                     |             |
| AWS_ACCESS_KEY_ID     | yes      |                     |             |
| AWS_SECRET_ACCESS_KEY | yes      |                     |             |
| GAD__PASSWORD         | yes      | MYSECRETPASSWORD    |             |
| GAD__INSTANCE_ID      | yes      | i-054c4b7e340dfdbda |             |
| GAD__TIMEOUT          | no       | 1h                  |             |
| GAD__DB_FILE          | no       | /path/to/gitea.db   |             |

## Deployment

Docker image is available on dockerhub: [`lfrisken/gitea-act-dynamic`](https://hub.docker.com/repository/docker/lfrisken/gitea-act-dynamic/general).

## Routes


| Route      | Description                                                                                                                                           |
| :--------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/start`   | Start the instance. Supports authentication via basic `Authorization` header (compatible with browser basic auth), or via `password` query parameter. |
| `/stop`    | Stop the instance. Supports authentication via basic `Authorization` header (compatible with browser basic auth), or via `password` query parameter.  |
| `/version` | prints the version of this application.                                                                                                               |

## Future

We are waiting for <https://github.com/go-gitea/gitea/issues/23796> to be implemented to make this react to manually triggered actions using webhooks only instead of requiring database access.