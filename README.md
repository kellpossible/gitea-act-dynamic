# gitea-act-dynamic

A tiny service that spools up an AWS instance as a Gitea act runner in response to any webhooks triggered by commits or other actions, etc.

## Problems

We are waiting for https://github.com/go-gitea/gitea/issues/23796 to be implemented to make this react to manually triggered actions. This could also support an option where this instance is stopped immediately when a job completes.