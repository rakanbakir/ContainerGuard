from flask import Flask, request, jsonify
import subprocess
import os
import re

app = Flask(__name__)

def sanitize_image_name(image):
    # Remove special characters and replace with dash, then clean up multiple dashes
    sanitized = re.sub(r'[^a-zA-Z0-9.-]', '-', image)
    # Replace multiple dashes with single dash
    sanitized = re.sub(r'-+', '-', sanitized)
    # Remove any trailing special characters
    sanitized = sanitized.rstrip('.-')
    return sanitized

@app.route('/scan/grype', methods=['POST'])
def scan_grype():
    data = request.get_json()
    
    if not data or 'image' not in data:
        return jsonify({'error': 'No image provided'}), 400
    
    image = data['image']
    safe_image = sanitize_image_name(image)
    
    try:
        # Run Grype scan directly on the image reference
        grype_json = f'grype/grype-result-{safe_image}.json'
        grype_pdf = f'grype/grype-result-{safe_image}_vulnerability_report.pdf'
        subprocess.run([
            'grype', f'registry:{image}', '-o', 'json', '--file', grype_json
        ], check=True)
        subprocess.run([
            'python3', 'grype/grype-json-to-pdf.py',
            grype_json,
            '-o', grype_pdf
        ], check=True)
        
        return jsonify({
            'message': 'Grype scan completed successfully',
            'report': grype_pdf
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Grype scan failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error in Grype scan: {str(e)}'}), 500

@app.route('/scan/trivy', methods=['POST'])
def scan_trivy():
    data = request.get_json()
    
    if not data or 'image' not in data:
        return jsonify({'error': 'No image provided'}), 400
    
    image = data['image']
    safe_image = sanitize_image_name(image)
    
    try:
        # Run Trivy scan directly on the image reference
        trivy_json = f'trivy/trivy-result-{safe_image}.json'
        trivy_pdf = f'trivy/trivy-result-{safe_image}_vulnerability_report.pdf'
        subprocess.run([
            'trivy', 'image', '--no-progress', '-f', 'json', '-o', trivy_json, 
            '--timeout', '5m', image
        ], check=True)
        subprocess.run([
            'python3', 'trivy/trivy-json-to-pdf.py',
            trivy_json,
            '-o', trivy_pdf
        ], check=True)
        
        return jsonify({
            'message': 'Trivy scan completed successfully',
            'report': trivy_pdf
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Trivy scan failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error in Trivy scan: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)