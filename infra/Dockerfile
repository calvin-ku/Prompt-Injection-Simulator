FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY attack_catalog ./attack_catalog
COPY attack_engine ./attack_engine
COPY defense_pipeline ./defense_pipeline
COPY telemetry ./telemetry
COPY run_campaign.py .
COPY run_experiment.py ./

ENTRYPOINT ["python", "run_campaign.py"]

CMD ["--help"]