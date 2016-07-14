FROM golang:1.6-alpine
COPY . $GOPATH/src/github.com/cezarsa/fusis-agent
RUN go install github.com/cezarsa/fusis-agent
RUN apk add --update sudo iptables
ENTRYPOINT ["bin/fusis-agent"]
