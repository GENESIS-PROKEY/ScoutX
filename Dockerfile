FROM python:3.12-slim

LABEL maintainer="LO" \
      description="ScoutX v2.0 - Elite Recon Framework" \
      version="2.0.0"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget nmap masscan whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22
RUN wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install core Go recon tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest

WORKDIR /app

# Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[full]" 2>/dev/null || pip install --no-cache-dir .

COPY . .
RUN pip install --no-cache-dir -e .

# Verify
RUN sx doctor 2>/dev/null || true

ENTRYPOINT ["sx"]
CMD ["--help"]
