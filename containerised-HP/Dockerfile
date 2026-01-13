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
    # Cowrie dependencies
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
    # Firejail dependencies
    firejail \
    apparmor \
    apparmor-utils \
    apparmor-profiles \
    # Additional monitoring security tools
    net-tools \
    strace \
    ltrace \
    # Cleanup to reduce image size
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create firejail runtime directories with proper permissions AS ROOT (before switching to cowrie user)
RUN mkdir -p /tmp/firejail-tmp \
             /run/firejail \
             /var/cache/firejail && \
    chmod 1777 /tmp/firejail-tmp && \
    chmod 755 /run/firejail && \
    chmod 755 /var/cache/firejail

# CURRENTLY MISSING COWRIE DIRECTORIES AND ACCESS FOR FIREJAIL


# need to add firejail as sudoer using a non-root user
# avoiding root if malware propagates
RUN chmod u+s /usr/bin/firejail

# create non root user with no priv
# make bash default shell!
RUN useradd -m -s /bin/bash cowrie

# allow cowrie to run firejail without passwd as sudoer
RUN echo "cowrie ALL=(ALL) NOPASSWD: /usr/bin/firejail, /bin/bash, /usr/bin/env" >> /etc/sudoers && \
    # Allow Firejail to work without tty requirement
    echo "Defaults:cowrie !requiretty" >> /etc/sudoers && \
    # Allow Firejail to preserve environment variables
    echo "Defaults:cowrie env_keep = \"PATH LD_LIBRARY_PATH\"" >> /etc/sudoers


USER cowrie
WORKDIR /home/cowrie

# Create firejail runtime directories with proper permissions BEFORE switching to cowrie user
RUN mkdir -p /home/cowrie/.config/firejail \
             /home/cowrie/.local/share/firejail \
             /home/cowrie/.cache/firejail && \
    chmod 700 /home/cowrie/.cache/firejail \
             /home/cowrie/.local/share/firejail

# clone cowrie from git

RUN git clone https://github.com/cowrie/cowrie.git cowrie

# set dir to cowrie
WORKDIR /home/cowrie/cowrie

RUN mkdir -p /home/cowrie/.cache/firejail \
             /home/cowrie/.local/share/firejail && \
    chmod 700 /home/cowrie/.cache/firejail \
             /home/cowrie/.local/share/firejail

# create python3 venv
RUN python3 -m venv cowrie-env

# install cowrie dependenies inside venv
RUN . cowrie-env/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

# Install cowrie packages themselves
RUN . cowrie-env/bin/activate && pip install -e .

# create directories for cowrie
RUN mkdir -p /home/cowrie/cowrie/var/log/cowrie \
             /home/cowrie/cowrie/var/lib/cowrie \
             /home/cowrie/cowrie/etc

# copy firejail profile for Cowrie
COPY --chown=cowrie:cowrie cowrie.profile /home/cowrie/.config/firejail
# cp config file for containerised honeypot
COPY --chown=cowrie:cowrie sandboxed-honeypot.cfg /home/cowrie/cowrie/etc/cowrie.cfg
# Expose SSH and TELNET ports
EXPOSE 2222 2223



#periodic health checker to see whether cowrie and docker works
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD pgrep -f "cowrie.tac" || exit 1

# finally start cowrie


CMD ["/bin/bash", "-c", "\
    source cowrie-env/bin/activate && \
    firejail \
        --noprofile \
        --profile=/home/cowrie/.config/filejail/cowrie.profile \
        --quiet \
        --shell=none \
        --keep-dev-log \
        bash -c 'cd /home/cowrie/cowrie && twistd --nodaemon --pidfile= cowrie' \
    "]
