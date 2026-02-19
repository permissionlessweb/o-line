#!/bin/sh

install:
    @cd plays/oline-sdl && just install

test-minio-ipfs:
    @cd plays/instant-replay &&\
    docker build -t minio-ipfs:latest . &&\
    E2E_IMAGE=minio-ipfs:latest ./e2e-test.sh