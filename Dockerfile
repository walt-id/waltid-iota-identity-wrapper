FROM rust:buster as builder
WORKDIR /usr/src/waltid-iota-identity-wrapper
COPY . .
RUN cargo build --release

FROM debian:buster-slim
COPY --from=builder /usr/src/waltid-iota-identity-wrapper/target/release/libwaltid_iota_identity_wrapper.so /usr/local/lib/libwaltid_iota_identity_wrapper.so
