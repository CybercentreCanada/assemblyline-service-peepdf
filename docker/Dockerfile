FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH peepdf_al.PeePDF

# Switch to assemblyline user
USER assemblyline

# Copy PeePDF service code
WORKDIR /opt/al_service
COPY . .