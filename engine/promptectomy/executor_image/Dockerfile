FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG RUNNER_SHA256
LABEL dev.promptectomy.executor.protocol="phase1b-1"
LABEL dev.promptectomy.executor.runner.sha256=$RUNNER_SHA256

COPY runner.py /opt/promptectomy/runner.py
RUN chmod 0555 /opt/promptectomy/runner.py

ENTRYPOINT ["/usr/local/bin/python3", "-I", "-S", "/opt/promptectomy/runner.py"]
