FROM ubuntu:22.10
RUN apt-get update && apt-get install -y nodejs npm \
    && apt-get install -y git \
    && apt-get install -y curl \
    && curl -s https://storage.googleapis.com/golang/go1.19.3.linux-amd64.tar.gz | tar -v -C /usr/local -xz
ENV PATH $PATH:/usr/local/go/bin
# Setup folders
RUN mkdir /sshwifty
WORKDIR /sshwifty
COPY . .
RUN go get -d -v ./...
#RUN npm config set unsafe-perm true
RUN npm install
RUN npm run build

CMD SSHWIFTY_CONFIG=./sshwifty.conf.json ./sshwifty

# Run bash
#CMD /bin/sh -c bash