ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-bookworm AS builder

RUN apt-get update && apt-get install -y curl gnupg build-essential

RUN curl -fsSL https://packages.confluent.io/deb/7.6/archive.key | apt-key add - && \
    echo "deb https://packages.confluent.io/deb/7.6 stable main" > /etc/apt/sources.list.d/confluent.list

RUN apt-get update && apt-get install -y librdkafka-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
ENV GOOS=linux

RUN go build -o /app/normalizer ./cmd

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y curl gnupg && \
    curl -fsSL https://packages.confluent.io/deb/7.6/archive.key | apt-key add -

RUN echo "deb https://packages.confluent.io/deb/7.6 stable main" > /etc/apt/sources.list.d/confluent.list

RUN apt-get update && apt-get install -y librdkafka1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/normalizer /usr/local/bin/normalizer

EXPOSE 8081

ENTRYPOINT ["normalizer"]
CMD ["serve"]