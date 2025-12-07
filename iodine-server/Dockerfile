FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y iodine && \
    apt-get install netcat-openbsd -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
