This Git Repo is for version control of my dissertation based on IoT IP devices and honeypots
OS running is Lubuntu 23.04.3
Python version 3.12.3
Docker version 29.0.1, build eedd969

ENSURE YOU USE PYTHON 3.12.3 IF ON DEBIAN, DO NOT USE DEV

NOTE:
All cowrie files reside as a submodule within this repo, to allow configurations to be accessible
	cowrie @ XXXXXXXX itself is just a pointer to https://github.com/cowrie/cowrie/


containerised-HP\	(docker + cowrie honeypot)
	- data\ (files for containerised honeypot)
	- Dockerfile:	builds docker image
	- docker-compose.yml: defines containers from Dockerfile
	- monitor.sh:	custom $bash script for Dockerfile 
	- sandboxed-honeypot.cfg:	config for sandboxed honeypot

documents\:	all docs and papers

cowrie-configs\:	copies of configs from containerised-HP & cowrie/
		
cowrie\:	submodule of https://github.com/cowrie/cowrie/


Run vanilla honeypot:
source cowrie\cowrie-env\bin {activate|deactivate}

Run sandboxed honeypot (containerised-HP):
./monitor.sh build:	Builds Docker image using Docker-Compose
./monitor.sh start:	Starts Docker image with a unique internet bridge
./monitor.sh --help: 	various commands (processing & exporting not yet supported)



