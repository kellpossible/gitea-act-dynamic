# Build the images that are published to dockerhub.
docker-build:
    docker build --tag "lfrisken/gitea-act-dynamic:$(./version.sh)" --tag "lfrisken/gitea-act-dynamic:latest"  .

# Build and publish the images to dockerhub.
docker-publish:
    just docker-build
    docker push "lfrisken/gitea-act-dynamic:latest"
    docker push "lfrisken/gitea-act-dynamic:$(./version.sh)"