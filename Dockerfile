# build usersync binary
FROM golang:latest as builder
COPY . /go/src/github.com/appvia/aws_usersync
WORKDIR /go/src/github.com/appvia/aws_usersync
RUN make build

# build final image
FROM alpine:latest
RUN apk add --no-cache sudo
COPY --from=builder /go/src/github.com/appvia/aws_usersync/bin/aws_usersync /usr/local/bin/
ENTRYPOINT [ "aws_usersync" ]
CMD [ "--help" ]
