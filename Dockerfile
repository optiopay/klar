FROM golang:1.8-alpine

COPY . .

RUN apk --update add git && \
  apk add --no-cache ca-certificates && \
  mv vendor/* src && \
  go build -o klar . && \
  cp klar /

ENTRYPOINT ["/klar"]
