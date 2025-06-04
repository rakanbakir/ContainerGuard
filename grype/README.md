# Grype Vulnerability Scan Report Generator

This tool converts Grype vulnerability scan JSON output into a comprehensive PDF report with detailed vulnerability information.

## Overview

The `grype-json-to-pdf.py` script processes JSON output from the Grype vulnerability scanner and generates a professional PDF report that includes:

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

## Generating Grype JSON Files

Before using this tool, you need to generate a JSON output file from the Grype vulnerability scanner:

1. **Install Grype** (if not already installed):
   ```bash
   # Install using Homebrew on macOS
   brew install anchore/grype/grype
   
   # Or install using curl
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
   ```

2. **Scan a container image or directory**:
   ```bash
   # Scan a Docker image and output JSON
   grype docker:image-name:tag -o json > grype-result.json
   
   # Scan a specific directory
   grype dir:/path/to/directory -o json > grype-result.json
   
   # Scan with additional options
   grype --scope all-layers -o json docker:ubuntu:latest > grype-result.json
   ```

3. **Generate reports from different scan targets**:
   ```bash
   # Scan an OCI image (from Docker)
   grype registry:docker.io/library/alpine:latest -o json > grype-result.json
   
   # Scan a container by ID
   grype container:containerID -o json > grype-result.json
   
   # Scan a file system directory
   grype dir:/path/to/dir -o json > grype-result.json
   ```

For more Grype options, run `grype --help` or visit the [Grype documentation](https://github.com/anchore/grype).

## Usage

```bash
python grype-json-to-pdf.py [json_file] [options]
```

### Arguments

- `json_file`: Path to the Grype JSON report file (default: "grype-result.json")

### Options

- `-o, --output`: Output PDF file path (default: input filename with "_vulnerability_report.pdf" suffix)
- `--max-vulns`: Maximum vulnerabilities per page (default: 10)
- `--no-charts`: Disable chart generation

### Examples

```bash
# Basic usage - uses grype-result.json by default
python grype-json-to-pdf.py

# Specify input and output files
python grype-json-to-pdf.py path/to/grype-scan.json -o path/to/output.pdf

# Customize vulnerability display and disable charts
python grype-json-to-pdf.py grype-result.json --max-vulns 15 --no-charts
```

## Features

1. **Complete Vulnerability Information**
   - No text truncation in tables or descriptions
   - Full display of CVEs, package names, versions, and other metadata

2. **Well-Organized Report Structure**
   - Title page with scan metadata and timestamp
   - Executive summary with statistics 
   - Detailed findings categorized by severity
   - Tables optimized for readability

3. **Visual Representations**
   - Pie chart showing vulnerability distribution by severity
   - Text-based chart fallback when graphical libraries aren't available

4. **Customization Options**
   - Adjust vulnerabilities per page
   - Enable/disable chart visualization

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
- This will create more but smaller tables that fit better on pages

## Output Example

The generated PDF report includes:

- Scan metadata (target, timestamp, scanner version)
- Executive summary with total vulnerability count
- Severity distribution table with counts and percentages
- Visual chart of severity distribution
- Detailed tables for each severity level 
- Complete vulnerability descriptions and remediation information

## License

[MIT License](LICENSE)
