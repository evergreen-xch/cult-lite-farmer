FROM --platform=linux/amd64 rust:1.69-slim-bullseye AS lite_farmer_toolchain

ARG TARGETARCH

RUN if [ "$TARGETARCH" = "amd64" ] ; then \
        apt update -y \
        && apt install -y openssl libssl-dev pkg-config \
        && rm -rf /var/lib/apt/lists/* \
    ; else \
        dpkg --add-architecture arm64 \
        && apt update -y \
        && apt install -y openssl:arm64 g++-aarch64-linux-gnu libc6-dev-arm64-cross libssl-dev:arm64 pkg-config \
        && rm -rf /var/lib/apt/lists/* \
        && rustup target add aarch64-unknown-linux-gnu \
    ; fi

RUN echo "fn main() {}" > dummy.rs

FROM lite_farmer_toolchain as lite_farmer_sources
COPY Cargo.toml Cargo.toml
COPY dg_xch_utils/Cargo.toml dg_xch_utils/Cargo.toml
COPY dg_xch_utils/bls/Cargo.toml dg_xch_utils/bls/Cargo.toml
COPY dg_xch_utils/cli/Cargo.toml dg_xch_utils/cli/Cargo.toml
COPY dg_xch_utils/clients/Cargo.toml dg_xch_utils/clients/Cargo.toml
COPY dg_xch_utils/core/Cargo.toml dg_xch_utils/core/Cargo.toml
COPY dg_xch_utils/keys/Cargo.toml dg_xch_utils/keys/Cargo.toml
COPY dg_xch_utils/macros/Cargo.toml dg_xch_utils/macros/Cargo.toml
COPY dg_xch_utils/proof_of_space/Cargo.toml dg_xch_utils/proof_of_space/Cargo.toml
COPY dg_xch_utils/puzzles/Cargo.toml dg_xch_utils/puzzles/Cargo.toml
COPY dg_xch_utils/serialize/Cargo.toml dg_xch_utils/serialize/Cargo.toml
COPY lite-farmer/Cargo.toml lite-farmer/Cargo.toml
COPY Cargo.lock Cargo.lock

COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/bls/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/cli/src/main.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/clients/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/core/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/keys/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/macros/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/proof_of_space/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/puzzles/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs dg_xch_utils/serialize/src/lib.rs
COPY --from=lite_farmer_toolchain dummy.rs lite-farmer/src/main.rs

# Build the project
RUN if [ "$TARGETARCH" = "amd64" ] ; then \
        cargo fetch \
    ; else \
        PKG_CONFIG_DIR= \
        PKG_CONFIG_LIBDIR=/usr/lib/pkgconfig:/usr/share/pkgconfig \
        PKG_CONFIG_SYSROOT_DIR=/ \
        PKG_CONFIG_ALLOW_CROSS=1 \
        PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo fetch --target=aarch64-unknown-linux-gnu \
    ; fi

FROM lite_farmer_sources as lite_farmer_build

COPY dg_xch_utils/ dg_xch_utils/
COPY lite-farmer/ lite-farmer/

RUN mkdir /build

# Build the project
RUN if [ "$TARGETARCH" = "amd64" ] ; then \
        cargo build --release \
        && mv /target/release/* /build \
    ; else \
        PKG_CONFIG_DIR= \
        PKG_CONFIG_LIBDIR=/usr/lib/pkgconfig:/usr/share/pkgconfig \
        PKG_CONFIG_SYSROOT_DIR=/ \
        PKG_CONFIG_ALLOW_CROSS=1 \
        PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo build --release --target=aarch64-unknown-linux-gnu \
        && mv /target/aarch64-unknown-linux-gnu/release/* /build \
    ; fi

FROM debian:bullseye-slim AS lite_farmer
RUN apt update -y \
    && apt install -y ntfs-3g ca-certificates \
    && mkdir /mnt/plots \
    && apt autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=lite_farmer_build /build/lite-farmer .
CMD ["./lite-farmer"]