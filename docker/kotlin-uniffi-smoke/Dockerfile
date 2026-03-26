FROM rust:1.85-bookworm

ARG KOTLIN_VERSION=1.9.24

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    clang \
    cmake \
    curl \
    default-libmysqlclient-dev \
    libjna-java \
    openjdk-17-jdk \
    pkg-config \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/kotlin-compiler.zip "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
    && unzip -q /tmp/kotlin-compiler.zip -d /opt \
    && ln -s /opt/kotlinc/bin/kotlinc /usr/local/bin/kotlinc \
    && rm -f /tmp/kotlin-compiler.zip

WORKDIR /work

CMD ["bash", "-lc", "./scripts/kotlin_uniffi_smoke.sh"]
