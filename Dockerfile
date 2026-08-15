# syntax=docker/dockerfile:1
#
# Everything the project needs - Python, uv, the package, pytest, Ruff, and mypy - lives in this
# image. The host only ever needs Docker Compose.
FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /workspace

# Install from the project metadata first so that editing source or tests does not invalidate the
# dependency layer.
COPY pyproject.toml ./
COPY src ./src
RUN uv pip install --system --no-cache -e ".[dev]"

# The fictional sensitive fixture is baked into the image rather than mounted, so the demonstration
# can only ever disclose a file the image itself provides.
RUN mkdir -p /srv/netops
COPY fixtures/fleet_deploy.key /srv/netops/fleet_deploy.key

COPY tests ./tests
COPY scripts ./scripts

CMD ["bash", "scripts/verify.sh"]
