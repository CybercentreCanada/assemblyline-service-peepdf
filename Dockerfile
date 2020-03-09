FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH peepdf.peepdf.PeePDF

USER root

RUN apt-get update && apt-get install -y python-pyrex swig libemu-dev libnspr4-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Copy PeePDF service code
WORKDIR /opt/al_service
COPY . .