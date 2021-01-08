FROM golang:1.15 AS build
WORKDIR /app
RUN git clone https://github.com/polynetwork/bsc-relayer.git  && \
    cd bsc-relayer && \
    go build -o run_bsc_relayer main.go

FROM ubuntu:18.04
WORKDIR /app
COPY ./config.json config.json
COPY --from=build /app/bsc-relayer/run_bsc_relayer run_bsc_relayer
CMD ["/bin/bash"]