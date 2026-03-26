FROM rust:1.85-bookworm

ARG CMDLINE_TOOLS_ZIP=commandlinetools-linux-11076708_latest.zip
ARG NDK_VERSION=26.3.11579264
ARG BUILD_TOOLS_VERSION=34.0.0

ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_NDK_HOME=/opt/android-sdk/ndk/${NDK_VERSION}
ENV PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/usr/local/cargo/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    git \
    ninja-build \
    openjdk-17-jdk \
    pkg-config \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools" \
    && curl -fsSL "https://dl.google.com/android/repository/${CMDLINE_TOOLS_ZIP}" -o /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /tmp \
    && mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools/latest" \
    && mv /tmp/cmdline-tools/* "${ANDROID_SDK_ROOT}/cmdline-tools/latest/" \
    && rm -rf /tmp/cmdline-tools /tmp/cmdline-tools.zip

RUN yes | sdkmanager --licenses \
    && sdkmanager \
      "platform-tools" \
      "build-tools;${BUILD_TOOLS_VERSION}" \
      "ndk;${NDK_VERSION}"

# rust:1.85 image cannot install latest cargo-ndk (requires rustc >=1.86),
# so pin to a compatible release.
RUN cargo install cargo-ndk --version 3.5.4 --locked
RUN cargo install bindgen-cli --version 0.71.1 --locked

WORKDIR /work

CMD ["bash", "-lc", "source /usr/local/cargo/env && ./scripts/kotlin_android_manual_test.sh"]
