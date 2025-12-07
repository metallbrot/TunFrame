FROM python:3.10-slim

WORKDIR /app

# Install shared dependencies
COPY detector_base/requirements.txt /app/detector_base/
RUN pip install --no-cache-dir -r /app/detector_base/requirements.txt

# Copy shared code as Python package
COPY detector_base/ /app/detector_base/
ENV PYTHONPATH="/app:${PYTHONPATH}"
