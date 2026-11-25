# --- build stage ---
FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY CMakeLists.txt ./
COPY include include
COPY src src
COPY tests tests
COPY blocklists blocklists
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j \
 && ctest --test-dir build --output-on-failure

# --- runtime stage ---
FROM debian:bookworm-slim
RUN useradd --system --no-create-home dns
WORKDIR /app
COPY --from=build /app/build/dns /app/dns
COPY --from=build /app/blocklists /app/blocklists
USER dns
EXPOSE 53/udp

ENTRYPOINT ["/app/dns", "-b", "0.0.0.0"]
