# ContainerGuard

ContainerGuard is a robust vulnerability scanning platform that provides a unified web interface for analyzing Docker container images using both Grype and Trivy scanners. It offers comprehensive security assessments and detailed vulnerability reports to help ensure the safety of your container deployments.

## Maintainer

This project is maintained by Rakan Bakir.

## Features

- Web-based interface for scanning Docker images
- Support for both Grype and Trivy scanners
- Automatic PDF report generation
- Real-time report listing and viewing
- Separate scanning options for each tool

## Prerequisites

- Docker
- Docker Compose

## Quick Start

1. Clone this repository
2. Start the services:
```bash
docker-compose up --build
```
3. Access the web interface at http://localhost:8080

## Usage

1. Enter a Docker image name in the format `image:tag` (e.g., `nginx:latest`)
2. Choose your preferred scanning tool:
   - Click "Scan with Grype" to use Grype scanner
   - Click "Scan with Trivy" to use Trivy scanner
3. Wait for the scan to complete
4. View the generated PDF reports in the respective sections

## Project Structure

```
.
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile           # API service Dockerfile
├── nginx.conf          # Nginx web server configuration
├── scan_api.py         # Flask API for vulnerability scanning
├── index.html         # Web interface
├── grype/             # Grype scanner files and reports
└── trivy/            # Trivy scanner files and reports
```

## Architecture

- **Nginx**: Serves the web interface and handles routing
- **Flask API**: Manages scan requests and report generation
- **Grype**: Vulnerability scanner by Anchore
- **Trivy**: Vulnerability scanner by Aqua Security

## API Endpoints

- `POST /api/scan/grype`
  - Scans an image using Grype
  - Request body: `{"image": "image:tag"}`

- `POST /api/scan/trivy`
  - Scans an image using Trivy
  - Request body: `{"image": "image:tag"}`

## Configuration

### Nginx Timeouts

The default timeout for scanning operations is set to 600 seconds (10 minutes). You can adjust this in `nginx.conf`:

```nginx
proxy_read_timeout 600s;
proxy_connect_timeout 600s;
proxy_send_timeout 600s;
```

### Report Directories

Reports are stored in:
- Grype reports: `./grype/`
- Trivy reports: `./trivy/`

## Troubleshooting

1. **504 Gateway Timeout**
   - This can happen for large images
   - Current timeout is set to 10 minutes
   - Adjust timeout values in nginx.conf if needed

2. **PDF Generation Issues**
   - Check the API logs: `docker-compose logs api`
   - Ensure proper permissions on report directories

3. **Scanner Failures**
   - Verify image name format
   - Check scanner-specific logs in API output
   - Ensure image is accessible from scanner

## Note

For production use, consider:
- Adding authentication
- Implementing rate limiting
- Setting up HTTPS
- Configuring proper log rotation
- Adding scan result persistence
