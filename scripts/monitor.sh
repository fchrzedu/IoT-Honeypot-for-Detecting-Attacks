
set -e # exit on errors

# Color codes for output
RED='\033[1;196m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'


print_all_info(){
	echo -e "${GREEN}[INFO]${NC} $1"
}

print_a_warning(){
	echo -e "${BLUE}[WARNING]${NC} $1"
}

print_an_error(){
	echo -e "${RED}[ERROR]${NC} $1"
}

# check whether docker is running!
check_docker_status(){
	if ! docker info > /dev/null 2>&1; then
	print_an_error "Docker is not running. Start docker from systemctl!"
	exit 1
	fi

}

build_container(){
	print_all_info "Building Docker & Honeypot image...."
	docker compose build
	print_all_info "Build complete."
}

start_honeypot(){
	check_docker_status
	print_all_info "Starting containerised Cowrie & Docker sandbox..."
	docker compose up -d
	print_all_info "Honeypot started. Awaiting initialization..."
	sleep 5
	docker compose ps
	print_all_info "SSH accessible on 2222"
	print_all_info "Telnet accessible on 2223"
}

stop_honeypot(){
	print_all_info "Stopping containerised Honeypot..."
	docker compose down
	print_all_info "Honeypot stopped."
}

restart_honeypot(){
	print_all_info "Restarting containerised Honeypot..."
	stop_honeypot
	sleep 1
	start_honeypot
}

logging(){
	print_all_info "Showing logs (CTRL+C EXIT)..."
	docker compose logs -f sandboxed-cowrie
}

show_status(){
	check_docker
	print_all_info "Status:"
	docker compose ps
	echo ""
	print_all_info "Resource usage:"
	docker stats --no-stream sandboxed-cowrie-honeypot
}

shell_cont(){
	print_all_info "Opening shell within Docker container..."
	docker compose exec sandboxed-cowrie /bin/bash
}

reset_honeypot(){
	print_a_warning "<><> This will delete all data and reset the honeypot <><>"
	read -p "Proceed? (y/n)"
	if [ "$confirm" = "y" ]; then
		print_all_info "Terminating..."
		docker compose down -v
		print_all_info "Removing directories..."
		rm -rf data/logs/* data/downloads/* data/pcap/* data/tty/*
		print_all_info "Reset complete!"
	else
		print_all_info "Cancelled."
	fi
}

create_a_backup(){
	BACKUP_DIR="backups/$(date + %Y%m%d_%H%M%S)"
	print_all_info "Backup being stored in $BACKUP_DIR"
	mkdir -p "$BACKUP_DIR"
	cp -r data/* "$BACKUP_DIR"
	sleep 5
	print_all_info "Backup Complete. Check: $BACKUP_DIR"

}


export_data() {
    EXPORT_DIR="exports/$(date +%Y%m%d_%H%M%S)"
    print_all_info "Exporting data for analysis to $EXPORT_DIR..."
    mkdir -p "$EXPORT_DIR"
    
    # Copy logs
    cp data/logs/*.json "$EXPORT_DIR/" 2>/dev/null || true
    cp data/logs/*.log "$EXPORT_DIR/" 2>/dev/null || true
    
    # Copy packet captures
    cp data/pcap/*.pcap "$EXPORT_DIR/" 2>/dev/null || true
    
    # Create summary
    echo "Export created: $(date)" > "$EXPORT_DIR/README.txt"
    echo "Total log files: $(ls data/logs/ 2>/dev/null | wc -l)" >> "$EXPORT_DIR/README.txt"
    echo "Total downloads: $(ls data/downloads/ 2>/dev/null | wc -l)" >> "$EXPORT_DIR/README.txt"
    
    print_all_info "Export complete: $EXPORT_DIR"
}



# Main script logic
case "${1:-}" in
    build)
        build_container
        ;;
    start)
        start_honeypot
        ;;
    stop)
        stop_honeypot
        ;;
    restart)
        restart_honeypot
        ;;
    logs)
        logging
        ;;
    status)
        show_status
        ;;
    shell)
        shell_cont
        ;;
    reset)
        reset_honeypot
        ;;
    backup)
        create_a_backup
        ;;
    *)
        print_an_error "Unknown command: ${1:-}"
        echo ""
        exit 1
        ;;
esac
