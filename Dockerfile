FROM golang as builder

#RUN apk --update add git;
RUN go get -d github.com/optiopay/klar
RUN go build ./src/github.com/optiopay/klar

FROM debian

#RUN apk add --no-cache ca-certificates
RUN apt-get update;apt-get -y install ca-certificates;apt-get clean
COPY --from=builder /go/klar /klar

ENTRYPOINT ["/klar"]
