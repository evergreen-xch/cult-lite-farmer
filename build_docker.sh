#!/usr/bin/env bash

docker buildx create --append --name cross_builder
docker buildx use cross_builder
docker buildx inspect --bootstrap

docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

DOCKER_BUILDKIT=1 docker buildx build \
  --platform linux/amd64 \
  --target=lite_farmer \
  -o type=docker,dest=- . > lite_farmer.tar
