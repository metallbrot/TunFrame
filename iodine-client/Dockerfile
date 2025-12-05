FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y iodine && \
    apt-get install netcat-openbsd -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["iodine"]
CMD ["-f", "-r", "-I", "1", "-O", "Base64", "-M", "100", "-P", "password123", "tunnel.com"]
