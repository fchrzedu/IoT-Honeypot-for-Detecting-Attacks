# OS image
FROM ubuntu:22.04

# no prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Metadata about image
LABEL maintainer ="Containerised Honeypot"
LABEL description="Sandboxed Cowrie Honeypot within Docker for IoT malware analysis"
LABEL version="1.0"

# required system dependencies
# all of these dependencies are the ones that Cowrie requires ref: https://docs.cowrie.org/en/latest/INSTALL.html
RUN apt-get update && apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-dev \
    authbind \
    virtualenv \
    # Cleanup to reduce image size
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# create non root user with no priv
# make bash default shell!
RUN useradd -m -s /bin/bash cowrie

USER cowrie
WORKDIR /home/cowrie

# clone cowrie from git

RUN git clone https://github.com/cowrie/cowrie.git cowrie

# set dir to cowrie
WORKDIR /home/cowrie/cowrie

# create python3 venv
RUN python3 -m venv cowrie-env

# install cowrie dependenies inside venv
RUN . cowrie-env/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

# create dirs for files
RUN mkdir -p /home/cowrie/cowrie/var/log/cowrie \
                         /home/cowrie/cowrie/var/lib/cowrie \
                        /home/cowrie/cowrie/etc

# Expose SSH and TELNET ports
EXPOSE 2222 2223

# cp config file for containerised honeypot
COPY --chown=cowrie:cowrie sandboxed-honeypot.cfg /home/cowrie/cowrie/etc/cowrie.cfg

#periodic health checker to see whether cowrie and docker works
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD pgrep -f "cowrie.tac" || exit 1

# finally start cowrie
CMD ["/bin/bash", "-c", "source cowrie-env/bin/activate && bin/cowrie start && tail -f /dev/null"]

