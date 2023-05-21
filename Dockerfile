FROM rust:slim as builder

ARG RUN_ENV=development
WORKDIR /bench

COPY . .

RUN cargo bench --no-run

CMD [ "cargo", "bench" ] 
