FROM --platform=$BUILDPLATFORM golang:1.23 AS build

WORKDIR /go/src/fake-oidc-provider
COPY . .

ENV CGO_ENABLED=0

ARG TARGETOS TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

RUN go build -o /go/bin/fake-oidc-provider

FROM gcr.io/distroless/static-debian12

COPY --from=build /go/bin/fake-oidc-provider /
COPY config.yaml /etc/oidc/config.yaml

EXPOSE 8080
ENTRYPOINT [ "/fake-oidc-provider" ]
