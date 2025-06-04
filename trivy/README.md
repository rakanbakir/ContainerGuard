# Trivy Vulnerability Scan Report Generator

This tool converts Trivy vulnerability scan JSON output into a comprehensive PDF report with detailed vulnerability information.

## Overview

The `trivy-json-to-pdf.py` script processes JSON output from the Trivy vulnerability scanner and generates a professional PDF report that includes:

- Executive summary with vulnerability statistics
- Distribution of vulnerabilities by severity
- Detailed findings organized by severity level
- Complete vulnerability descriptions and metadata
- Visual charts for quick assessment (when dependencies are installed)

## Requirements

- Python 3.7+
- ReportLab library (`pip install reportlab`)
- Pandas library (`pip install pandas`)

For chart visualization support:
- PyCairo (`pip install pycairo`) - preferred for better quality charts
- or Pillow (`pip install pillow`) - alternative option

### Installing Dependencies

A `requirements.txt` file is included for easy installation of all dependencies:

```bash
# Install all required packages
pip install -r requirements.txt

# To enable better chart quality, edit requirements.txt to uncomment pycairo
# and then run the above command again
```

## Generating Trivy JSON Files

Before using this tool, you need to generate a JSON output file from the Trivy vulnerability scanner:

1. **Install Trivy** (if not already installed):
   ```bash
   # Install using Homebrew on macOS
   brew install aquasecurity/trivy/trivy
   
   # Or install using curl and apt (on Ubuntu/Debian)
   sudo apt-get install wget apt-transport-https gnupg lsb-release
   wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
   echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
   sudo apt-get update
   sudo apt-get install trivy
   ```

2. **Scan a container image or project**:
   ```bash
   # Scan a Docker image and output JSON
   trivy image --format json -o trivy-result.json image-name:tag
   
   # Scan with output for all vulnerabilities (including non-fixed)
   trivy image --format json --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN -o trivy-result.json image-name:tag
   
   # Scan a filesystem/project directory
   trivy fs --format json -o trivy-result.json /path/to/project
   ```

3. **Generate reports from different scan types**:
   ```bash
   # Scan container images
   trivy image --format json -o trivy-result.json alpine:latest
   
   # Scan local filesystem
   trivy fs --format json -o trivy-result.json ./
   
   # Scan git repositories
   trivy repo --format json -o trivy-result.json https://github.com/org/repo
   
   # Scan kubernetes clusters
   trivy k8s --format json -o trivy-result.json all -n default
   ```

For more Trivy options, run `trivy --help` or visit the [Trivy documentation](https://aquasecurity.github.io/trivy/).

## Usage

```bash
python trivy-json-to-pdf.py [json_file] [options]
```

### Arguments

- `json_file`: Path to the Trivy JSON report file

### Options

- `-o, --output`: Output PDF file path (default: input filename with "_vulnerability_report.pdf" suffix)
- `--max-vulns`: Maximum vulnerabilities per page (default: 25)
- `--no-charts`: Disable chart generation

### Examples

```bash
# Basic usage with required JSON file
python trivy-json-to-pdf.py trivy-result.json

# Specify output file
python trivy-json-to-pdf.py path/to/trivy-scan.json -o path/to/output.pdf

# Customize vulnerability display and disable charts
python trivy-json-to-pdf.py trivy-result.json --max-vulns 15 --no-charts
```

## Features

1. **Complete Vulnerability Information**
   - No text truncation in tables or descriptions
   - Full display of CVEs, package names, versions, and CVSS scores
   - Complete vulnerability information with proper text wrapping

2. **Well-Organized Report Structure**
   - Title page with scan metadata and timestamp
   - Executive summary with statistics
   - Detailed findings categorized by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
   - Tables optimized for readability

3. **Visual Representations**
   - Pie chart showing vulnerability distribution by severity
   - Text-based chart fallback when graphical libraries aren't available

4. **Empty Scan Handling**
   - Properly handles cases where no vulnerabilities are found
   - Displays appropriate messaging in the report
   - Generates valid summary statistics even with zero findings

## Troubleshooting

### Chart Visualization Issues

If you see the message "Chart visualization is disabled due to missing dependencies":

1. Install PyCairo for best results:
   ```bash
   pip install pycairo
   ```

2. Or install Pillow as an alternative:
   ```bash
   pip install pillow
   ```

3. If you still have issues, use the `--no-charts` option to disable chart generation entirely.

### PDF Format Issues

If tables are split across pages or have excessive spacing:
- Try reducing the `--max-vulns` value to limit vulnerabilities per table
- The default of 25 vulnerabilities per page works well for most reports

## Difference Between Trivy and Grype Reports

The Trivy report generator is specifically designed to handle the JSON output format from Trivy scanner, which differs from Grype in several ways:

- Different JSON structure with "Results" section (vs. "matches" in Grype)
- CVSS scores are structured differently with vendor-specific entries
- Severity levels use uppercase naming (CRITICAL vs Critical)
- Different metadata fields are available

## Output Example

The generated PDF report includes:

- Scan metadata (target, timestamp, scanner version)
- Executive summary with total vulnerability count
- Severity distribution table with counts and percentages
- Visual chart of severity distribution
- Detailed tables for each severity level
- Complete vulnerability descriptions with CVSS vectors and references

## License

[MIT License](LICENSE)
