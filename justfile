# Build the images that are published to dockerhub.
docker-build:
    echo "Building version $(./version.sh)"
    docker build --tag "lfrisken/gitea-act-dynamic:$(./version.sh)" --tag "lfrisken/gitea-act-dynamic:latest"  .

# Build and publish the images to dockerhub.
docker-publish:
    echo "Publishing version $(./version.sh)"
    just docker-build
    docker push "lfrisken/gitea-act-dynamic:latest"
    docker push "lfrisken/gitea-act-dynamic:$(./version.sh)"

run:
   go run -ldflags="-X main.BuildVersion=$(./version.sh)" .