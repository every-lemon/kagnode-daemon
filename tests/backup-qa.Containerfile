ARG BASE
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends openssl libstdc++6 ca-certificates && rm -rf /var/lib/apt/lists/*
USER 1001:1001
ENV TMPDIR=/work/tmp
WORKDIR /work
