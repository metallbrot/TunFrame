FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y iodine && \
    apt-get install netcat-openbsd -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 53/udp

ENTRYPOINT ["iodined"]
CMD ["-f", "-c", "-P", "password123", "10.100.100.100", "tunnel.com"]
