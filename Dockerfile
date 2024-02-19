ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH peepdf.peepdf.PeePDF

USER root

RUN apt-get update && apt-get install -y cython3 swig libx86emu-dev libnspr4-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Copy PeePDF service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
