#!/bin/bash
set -e

# Script to build and push the Drop-Drop agent Docker image
DOCKER_REGISTRY="hanshal785"
IMAGE_NAME="drop-drop-agent"
VERSION="${1:-latest}"

echo "Building Docker image: $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION"

# Build the image
docker build -t $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION .

# Tag as latest if version is not latest
if [ "$VERSION" != "latest" ]; then
    docker tag $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION $DOCKER_REGISTRY/$IMAGE_NAME:latest
fi

echo "Built image: $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION"

# Push the image
echo "Pushing image to Docker Hub..."
docker push $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION

if [ "$VERSION" != "latest" ]; then
    docker push $DOCKER_REGISTRY/$IMAGE_NAME:latest
fi

echo "Successfully pushed $DOCKER_REGISTRY/$IMAGE_NAME:$VERSION to Docker Hub"
