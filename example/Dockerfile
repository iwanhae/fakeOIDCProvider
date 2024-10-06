FROM golang:1.23 AS build

WORKDIR /go/src/example
COPY . .
RUN CGO_ENABLED=0 go build -o /go/bin/example

FROM gcr.io/distroless/static-debian12
COPY --from=build /go/bin/example /
EXPOSE 8081

ENTRYPOINT [ "/example" ]
