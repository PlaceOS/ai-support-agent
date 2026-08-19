ARG CRYSTAL_VERSION=latest

FROM placeos/crystal:$CRYSTAL_VERSION AS build
WORKDIR /app

# Set the commit through a build arg
ARG PLACE_COMMIT="DEV"
# Set the platform version via a build arg
ARG PLACE_VERSION="DEV"

# Create a non-privileged user, defaults are appuser:10001
ARG IMAGE_UID="10001"
ENV UID=$IMAGE_UID
ENV USER=appuser

# See https://stackoverflow.com/a/55757473/12429735
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# Install shards for caching
COPY shard.yml .
COPY shard.override.yml .
COPY shard.lock .

RUN shards install --production --ignore-crystal-version --skip-postinstall --skip-executables

# Add src
COPY ./src src

# Playbooks and report templates are discovered at runtime relative to the
# compiled source path (app/playbooks, app/templates/reports)
COPY playbooks playbooks
COPY templates templates

# Build App
RUN PLACE_COMMIT=$PLACE_COMMIT \
    shards build --production --error-trace --static

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN mkdir deps

# Extract binary dependencies
RUN for binary in /app/bin/*; do \
        ldd "$binary" | \
        tr -s '[:blank:]' '\n' | \
        grep '^/' | \
        xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'; \
    done

# Build a minimal docker image
FROM scratch
WORKDIR /
ENV PATH=$PATH:/

# Copy the user information over
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# These are required for communicating with external services
COPY --from=build /etc/hosts /etc/hosts

# These provide certificate chain validation where communicating with external services over TLS
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# This is required for Timezone support
COPY --from=build /usr/share/zoneinfo/ /usr/share/zoneinfo/

# Copy the app into place
COPY --from=build /app/deps /
COPY --from=build /app/bin /
COPY --from=build /app/playbooks /app/playbooks
COPY --from=build /app/templates /app/templates

# Use an unprivileged user.
USER appuser:appuser

# Run the app binding on port 3015
EXPOSE 3015
ENTRYPOINT ["/ai-support-agent"]
HEALTHCHECK CMD ["/ai-support-agent", "-c", "http://127.0.0.1:3015/api/ai-support/v1/"]
CMD ["/ai-support-agent", "-b", "0.0.0.0", "-p", "3015"]