#  1️⃣ Use the official Ubuntu 24.04 base image
FROM ubuntu:24.04

# 2️⃣ Avoid interactive prompts during package installs
ENV DEBIAN_FRONTEND=noninteractive

# 3️⃣ Install system dependencies
# - python3, venv, pip, dev headers for building Python packages
# - libssl-dev, libffi-dev, build-essential needed for Cowrie dependencies
# - git, net-tools, iproute2 for debugging and networking
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    git \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# 4️⃣ Create a dedicated cowrie user (non-root for security)
RUN useradd -m -r -d /home/cowrie cowrie

# 5️⃣ Set working directory inside cowrie home
WORKDIR /home/cowrie

# 6️⃣ Copy the Cowrie source code into the container
COPY cowrie /home/cowrie/cowrie

# 7️⃣ Fix ownership so cowrie user can write files
RUN chown -R cowrie:cowrie /home/cowrie/cowrie

# 8️⃣ Switch to cowrie user for security
USER cowrie

# 9️⃣ Create a virtual environment for Cowrie inside the cowrie directory
RUN python3 -m venv cowrie/cowrie-env

# 1️⃣0️⃣ Upgrade pip and install Python dependencies inside the venv
RUN cowrie/cowrie-env/bin/pip install --upgrade pip && \
    cowrie/cowrie-env/bin/pip install -r cowrie/requirements.txt && \
    cowrie/cowrie-env/bin/pip install -e cowrie

# 1️⃣1️⃣ Ensure the venv's bin directory is in PATH
ENV PATH="/home/cowrie/cowrie/cowrie-env/bin:$PATH"

# 1️⃣2️⃣ Expose the default Cowrie SSH/Telnet ports
EXPOSE 2222 2223

# 1️⃣3️⃣ Use the Cowrie binary from the virtual environment to start
# This ensures it uses the correct twistd inside the venv
CMD ["cowrie", "start"]
