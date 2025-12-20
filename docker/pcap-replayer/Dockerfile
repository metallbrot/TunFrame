FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \ 
    tcpreplay \
    iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["tail", "-f", "/dev/null"]
