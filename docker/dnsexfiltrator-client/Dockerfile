FROM mono:latest

WORKDIR /app

RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y dnsutils
    
COPY dnsExfiltrator.cs .
RUN mcs -unsafe -r:System.IO.Compression,System.Web.Extensions -out:DNSExfiltrator.exe dnsExfiltrator.cs