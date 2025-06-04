#!/usr/bin/env python3
import json
import os
import sys
import argparse
from datetime import datetime
from collections import Counter
import pandas as pd

# Import ReportLab libraries for PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, portrait
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Try to import chart libraries with fallbacks
CHART_SUPPORT = True
try:
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPM
except ImportError:
    CHART_SUPPORT = False
    print("Warning: Chart libraries not available. Charts will be disabled.")
    print("To enable charts, install required dependencies:")
    print("  pip install reportlab pillow")
    print("  or")
    print("  pip install reportlab pycairo")

# Severity levels and their colors
SEVERITY_COLORS = {
    "Critical": colors.Color(0.8, 0.1, 0.1),  # Darker red
    "High": colors.red,
    "Medium": colors.orange,
    "Low": colors.yellow,
    "Unknown": colors.grey
}

def format_vulnerabilities_to_html(data):
    """Legacy HTML formatter, kept for reference"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Assessment Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                color: #333;
                line-height: 1.5;
            }
            h1, h2, h3 {
                color: #2c3e50;
            }
            .header {
                margin-bottom: 30px;
            }
            .severity-Critical, .severity-High {
                color: #e74c3c;
                font-weight: bold;
            }
            .severity-Medium {
                color: #f39c12;
                font-weight: bold;
            }
            .severity-Low {
                color: #3498db;
            }
            .vulnerability {
                margin-bottom: 20px;
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            .metadata {
                margin-top: 30px;
                font-size: 0.9em;
                color: #7f8c8d;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 20px;
            }
            th, td {
                text-align: left;
                padding: 8px;
                border: 1px solid #ddd;
            }
            th {
                background-color: #f2f2f2;
                font-weight: bold;
            }
            tr:nth-child(even) {
                background-color: #f9f9f9;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Vulnerability Assessment Report</h1>
            <p>Generated on: """ + datetime.now().strftime("%B %d, %Y at %H:%M:%S") + """</p>
        </div>
    """

    # Extract source information 
    if "source" in data:
        html += """
        <h2>Source Information</h2>
        <table>
            <tr><th>Type</th><td>""" + data["source"]["type"] + """</td></tr>
        """
        
        if "target" in data["source"]:
            target = data["source"]["target"]
            if "userInput" in target:
                html += "<tr><th>Image</th><td>" + target["userInput"] + "</td></tr>"
            if "imageID" in target:
                html += "<tr><th>Image ID</th><td>" + target["imageID"] + "</td></tr>"
            if "tags" in target and target["tags"]:
                html += "<tr><th>Tags</th><td>" + ", ".join(target["tags"]) + "</td></tr>"
        
        html += "</table>"

    # Extract distribution information
    if "distro" in data:
        distro = data["distro"]
        html += """
        <h2>Distribution Information</h2>
        <table>
            <tr><th>Name</th><td>""" + distro["name"] + """</td></tr>
            <tr><th>Version</th><td>""" + distro["version"] + """</td></tr>
        </table>
        """
    
    return html

def extract_vulnerabilities(grype_data):
    """
    Extract vulnerability information from Grype JSON data
    """
    vulnerabilities = []
    
    # Check if this is a Grype JSON report
    if "matches" not in grype_data:
        raise ValueError("This doesn't appear to be a Grype vulnerability report")
    
    for match in grype_data.get("matches", []):
        if "vulnerability" in match and "artifact" in match:
            vuln = match["vulnerability"]
            artifact = match["artifact"]
            
            # Create a combined vulnerability entry with data from both sections
            vuln_entry = {
                "VulnerabilityID": vuln.get("id", "Unknown"),
                "PkgName": artifact.get("name", "Unknown"),
                "InstalledVersion": artifact.get("version", "Unknown"),
                "Severity": vuln.get("severity", "Unknown"),
                "Title": vuln.get("title", "No title available"),
                "Description": vuln.get("description", "No description available"),
                "FixedVersion": match.get("fixedVersion", ""),
                "PublishedDate": vuln.get("publishedDate", ""),
                "Target": artifact.get("path", "Unknown"),
                "PrimaryURL": vuln.get("primaryURL", ""),
                "References": vuln.get("urls", []),
                "CVSS": None,
                "CVSSVector": None
            }
            
            # Extract CVSS score if available
            if "cvss" in vuln and vuln["cvss"]:
                for cvss_entry in vuln["cvss"]:
                    if "metrics" in cvss_entry and "baseScore" in cvss_entry["metrics"]:
                        vuln_entry["CVSS"] = cvss_entry["metrics"]["baseScore"]
                        if "vector" in cvss_entry:
                            vuln_entry["CVSSVector"] = cvss_entry["vector"]
                        break
            
            vulnerabilities.append(vuln_entry)
    
    return vulnerabilities

def create_vulnerability_dataframe(vulnerabilities):
    """
    Convert vulnerability list into a pandas DataFrame with needed columns
    """
    if not vulnerabilities:
        return pd.DataFrame()
    
    # Create DataFrame from vulnerabilities list
    df = pd.DataFrame(vulnerabilities)
    
    # Convert dates if available
    if "PublishedDate" in df.columns:
        df["PublishedDate"] = pd.to_datetime(df["PublishedDate"], errors='coerce')
    
    # Sort by severity and CVSS score
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    df["SeverityOrder"] = df["Severity"].map(lambda s: severity_order.get(s, 99))
    df = df.sort_values(by=["SeverityOrder", "CVSS"], ascending=[True, False])
    df = df.drop("SeverityOrder", axis=1)
    
    return df

def create_summary_chart(vulnerabilities_df, output_path):
    """
    Create a summary chart of vulnerabilities by severity
    Returns None, None if chart creation fails
    """
    # Count vulnerabilities by severity
    severity_counts = Counter(vulnerabilities_df["Severity"])
    severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
    ordered_counts = {severity: severity_counts.get(severity, 0) for severity in severity_order}
    
    # If chart support is globally disabled, return counts for text representation
    if not CHART_SUPPORT:
        return ordered_counts, None
    
    # Create a drawing
    drawing = Drawing(400, 200)
    
    # Create a pie chart
    pie = Pie()
    pie.x = 150
    pie.y = 50
    pie.width = 120
    pie.height = 120
    pie.data = [ordered_counts[severity] for severity in severity_order]
    pie.labels = [f"{severity} ({ordered_counts[severity]})" for severity in severity_order]
    
    # Set colors
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = SEVERITY_COLORS["Critical"]
    pie.slices[1].fillColor = SEVERITY_COLORS["High"]
    pie.slices[2].fillColor = SEVERITY_COLORS["Medium"]
    pie.slices[3].fillColor = SEVERITY_COLORS["Low"]
    pie.slices[4].fillColor = SEVERITY_COLORS["Unknown"]
    
    drawing.add(pie)
    
    # Create PNG output
    png_path = os.path.join(output_path, "vulnerability_summary.png")
    
    # Try direct PNG rendering
    try:
        drawing.save(formats=['png'], outDir=output_path, fnRoot='vulnerability_summary')
        if os.path.exists(png_path):
            print("Successfully created PNG chart")
            return drawing, png_path
        else:
            raise Exception("PNG file was not created")
    except Exception as e:
        print(f"Warning: Unable to create chart: {e}")
        print("Continuing without chart visualization...")
        return ordered_counts, None

def create_vulnerability_report(grype_json_file, output_file=None, max_vulns_per_page=25, no_charts=False):
    """
    Create a vulnerability assessment report from Grype JSON output
    """
    global CHART_SUPPORT
    if no_charts:
        CHART_SUPPORT = False
    
    # If output file not specified, use the same name as the JSON file with PDF extension
    if not output_file:
        output_file = os.path.splitext(grype_json_file)[0] + '_vulnerability_report.pdf'
    
    output_dir = os.path.dirname(output_file) or "."
    
    print(f"Loading Grype scan results from: {grype_json_file}")
    try:
        # Load JSON data
        with open(grype_json_file, 'r') as f:
            grype_data = json.load(f)
        
        # Extract artifact details
        artifact_name = "Unknown"
        artifact_type = "Unknown"
        # Try to get timestamp from multiple possible locations in Grype JSON
        timestamp = grype_data.get("timestamp", "")
        if not timestamp and "descriptor" in grype_data and "timestamp" in grype_data["descriptor"]:
            timestamp = grype_data["descriptor"]["timestamp"]
        scan_date = "Unknown"
        
        # Try to get artifact information from source/target if available
        if "source" in grype_data and "target" in grype_data["source"]:
            if "userInput" in grype_data["source"]["target"]:
                artifact_name = grype_data["source"]["target"]["userInput"]
            artifact_type = grype_data["source"].get("type", "Unknown")
        
        # Format timestamp if available
        if timestamp:
            try:
                # Handle multiple timestamp formats used by Grype
                # Handle microseconds and timezone
                if '.' in timestamp:
                    # Truncate microseconds to 6 digits
                    base, fraction = timestamp.split('.')
                    fraction = fraction.replace('Z', '').replace('+00:00', '')[:6]
                    timestamp = f"{base}.{fraction}+00:00"
                elif 'Z' in timestamp:
                    timestamp = timestamp.replace('Z', '+00:00')
                
                # Parse the datetime and format it in a readable way
                scan_date = datetime.fromisoformat(timestamp).strftime("%B %d, %Y %H:%M:%S")
            except Exception as e:
                print(f"Warning: Could not parse timestamp '{timestamp}': {e}")
                scan_date = timestamp
                
        # Extract vulnerability information
        print("Extracting vulnerability information...")
        vulnerabilities = extract_vulnerabilities(grype_data)
        
        # Convert to DataFrame
        vuln_df = create_vulnerability_dataframe(vulnerabilities)
        
        # Create summary statistics
        vuln_count = len(vuln_df)
        severity_counts = Counter(vuln_df["Severity"])
        
        # Create summary chart or get ordered counts for text display
        if not no_charts:
            chart_result, chart_path = create_summary_chart(vuln_df, output_dir)
            
            # If chart_result is a dictionary, it contains ordered counts
            if isinstance(chart_result, dict):
                ordered_severity_counts = chart_result
                chart_drawing = None
            else:
                chart_drawing = chart_result  # This is the actual drawing object
                ordered_severity_counts = None
        else:
            chart_drawing = None
            chart_path = None
            ordered_severity_counts = {sev: severity_counts.get(sev, 0) for sev in ["Critical", "High", "Medium", "Low", "Unknown"]}
        
        print(f"Creating vulnerability report with {vuln_count} vulnerabilities...")
        # Create PDF document with improved page break handling
        doc = SimpleDocTemplate(
            output_file,
            pagesize=portrait(letter),
            allowSplitting=1,  # Allow controlled splitting where necessary
            topMargin=30,      # Reduced margins to fit more content
            bottomMargin=30,
            leftMargin=30, 
            rightMargin=30
        )
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'TitleWithMore',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=12
        )
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=10
        )
        subheading_style = ParagraphStyle(
            'SubHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=8
        )
        normal_style = styles['Normal']
        
        # Elements for the PDF
        elements = []
        
        # Add title page
        elements.append(Paragraph(f"Grype Vulnerability Assessment Report", title_style))
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(f"Target: {artifact_name}", styles['Heading1']))
        elements.append(Paragraph(f"Type: {artifact_type}", styles['Heading2']))
        elements.append(Paragraph(f"Scanner: Grype", styles['Heading2']))
        elements.append(Paragraph(f"Scan Date: {scan_date}", styles['Heading2']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Add summary section
        elements.append(Paragraph("Executive Summary", heading_style))
        
        # Add source and distribution information if available
        if "source" in grype_data:
            elements.append(Paragraph("Source Information", subheading_style))
            
            source_data = [["Property", "Value"]]
            source_data.append(["Type", grype_data["source"].get("type", "Unknown")])
            
            if "target" in grype_data["source"]:
                target = grype_data["source"]["target"]
                if "userInput" in target:
                    source_data.append(["Image", target["userInput"]])
                if "imageID" in target:
                    source_data.append(["Image ID", target["imageID"]])
                if "tags" in target and target["tags"]:
                    source_data.append(["Tags", ", ".join(target["tags"])])
            
            # Convert all text fields to Paragraph for proper text wrapping in the source table
            for i in range(len(source_data)):
                for j in range(len(source_data[i])):
                    if isinstance(source_data[i][j], str):
                        # Use a smaller font for values to fit more text
                        if j == 1 and i > 0:  # This is a value cell, not a header
                            source_data[i][j] = Paragraph(source_data[i][j], ParagraphStyle(
                                'ValueStyle', 
                                parent=styles['Normal'],
                                wordWrap='CJK',
                                leading=12,
                                alignment=0,   # Left alignment
                                allowWidows=0, # No widows
                                allowOrphans=0 # No orphans
                            ))
                        else:
                            source_data[i][j] = Paragraph(source_data[i][j], styles["Normal"])
            
            source_table = Table(source_data, colWidths=[1.5*inch, 5*inch])
            source_table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),  # Align text to top for better readability
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),  # Add padding to all data rows
                ('TOPPADDING', (0, 1), (-1, -1), 6),     # Add padding to top of rows too
                ('LEFTPADDING', (0, 0), (-1, -1), 5),    # Add left padding for all cells
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),   # Add right padding for all cells
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True),  # Enable word wrapping
            ])
            source_table.setStyle(source_table_style)
            elements.append(source_table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Add distribution information if available
        if "distro" in grype_data:
            elements.append(Paragraph("Distribution Information", subheading_style))
            distro = grype_data["distro"]
            
            distro_data = [["Property", "Value"]]
            distro_data.append(["Name", distro.get("name", "Unknown")])
            distro_data.append(["Version", distro.get("version", "Unknown")])
            
            # Convert all text fields to Paragraph for proper text wrapping in the distro table
            for i in range(len(distro_data)):
                for j in range(len(distro_data[i])):
                    if isinstance(distro_data[i][j], str):
                        # Use a smaller font for values to fit more text
                        if j == 1 and i > 0:  # This is a value cell, not a header
                            distro_data[i][j] = Paragraph(distro_data[i][j], ParagraphStyle(
                                'ValueStyle', 
                                parent=styles['Normal'],
                                wordWrap='CJK',
                                leading=12,
                                alignment=0,   # Left alignment
                                allowWidows=0, # No widows
                                allowOrphans=0 # No orphans
                            ))
                        else:
                            distro_data[i][j] = Paragraph(distro_data[i][j], styles["Normal"])
            
            distro_table = Table(distro_data, colWidths=[1.5*inch, 5*inch])
            distro_table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),  # Align text to top for better readability
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),  # Add padding to all data rows
                ('TOPPADDING', (0, 1), (-1, -1), 6),     # Add padding to top of rows too
                ('LEFTPADDING', (0, 0), (-1, -1), 5),    # Add left padding for all cells
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),   # Add right padding for all cells
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True),  # Enable word wrapping
            ])
            distro_table.setStyle(distro_table_style)
            elements.append(distro_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Add vulnerability summary
        elements.append(Paragraph("Vulnerability Summary", subheading_style))
        
        summary_text = f"""
        This report contains the results of a vulnerability scan performed using the <b>Grype</b> security scanner.
        The scan identified a total of <b>{vuln_count}</b> vulnerabilities, categorized by severity as follows:
        """
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Add severity summary table
        summary_data = [
            ["Severity", "Count", "Percentage"],
        ]
        
        for severity in ["Critical", "High", "Medium", "Low", "Unknown"]:
            count = severity_counts.get(severity, 0)
            percentage = f"{count/vuln_count*100:.1f}%" if vuln_count else "0%"
            summary_data.append([severity, count, percentage])
        
        summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch, 1*inch])
        summary_table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ])
        
        # Apply colors to each severity row
        for i, severity in enumerate(["Critical", "High", "Medium", "Low", "Unknown"], 1):
            if severity in SEVERITY_COLORS:
                summary_table_style.add('BACKGROUND', (0, i), (0, i), SEVERITY_COLORS[severity])
                summary_table_style.add('TEXTCOLOR', (0, i), (0, i), 
                                       colors.white if severity in ["Critical", "High"] else colors.black)
        
        summary_table.setStyle(summary_table_style)
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Add Vulnerability Distribution section
        elements.append(Paragraph("Vulnerability Distribution", subheading_style))
        
        # Add chart if available
        if chart_drawing is not None and chart_path is not None:
            try:
                if os.path.exists(chart_path) and chart_path.lower().endswith('.png'):
                    elements.append(Image(chart_path, width=5*inch, height=2.5*inch))
                    elements.append(Spacer(1, 0.2*inch))
                else:
                    print("Chart is not in PNG format, using text-based representation")
                    chart_drawing = None
                    chart_path = None
                    # Force fallback to text representation
                    ordered_severity_counts = severity_counts
            except Exception as e:
                print(f"Could not add chart image: {e}")
                print("Falling back to text representation...")
                # Force fallback to text representation
                ordered_severity_counts = severity_counts
                
        # If chart was not created, provide text-based representation
        elif ordered_severity_counts is not None:
            # Create ASCII-art style bar chart using tables
            bar_data = []
            max_count = max(ordered_severity_counts.values()) if ordered_severity_counts.values() else 0
            if max_count > 0:
                for severity, count in ordered_severity_counts.items():
                    if count <= 0:
                        continue
                    # Calculate bar width proportional to count
                    bar_width = int(15 * count / max_count)
                    bar = "█" * bar_width
                    bar_data.append([severity, count, bar])
                
                if bar_data:
                    elements.append(Paragraph("Text-based distribution chart:", styles["Normal"]))
                    severity_table = Table(bar_data, colWidths=[1.2*inch, 0.8*inch, 3*inch])
                    severity_table_style = TableStyle([
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                        ('ALIGN', (2, 0), (2, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ])
                    
                    # Apply severity colors
                    for i, row in enumerate(bar_data):
                        severity = row[0]
                        if severity in SEVERITY_COLORS:
                            color = SEVERITY_COLORS[severity]
                            severity_table_style.add('TEXTCOLOR', (2, i), (2, i), color)
                            severity_table_style.add('TEXTCOLOR', (0, i), (0, i), color)
                    
                    severity_table.setStyle(severity_table_style)
                    elements.append(severity_table)
                    elements.append(Spacer(1, 0.2*inch))
                    
                    if not CHART_SUPPORT:
                        elements.append(Paragraph("Note: Chart visualization is disabled due to missing dependencies.", 
                                                styles["Italic"]))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Add findings section
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", heading_style))
        
        # Group vulnerabilities by severity
        severity_groups = ["Critical", "High", "Medium", "Low", "Unknown"]
        
        for severity in severity_groups:
            # Filter vulnerabilities by current severity
            severity_df = vuln_df[vuln_df["Severity"] == severity]
            if len(severity_df) == 0:
                continue
                
            elements.append(Paragraph(f"{severity} Severity Vulnerabilities ({len(severity_df)})", subheading_style))
            
            # Create smaller tables for each severity level to avoid page breaks
            # Use a smaller chunk size for better pagination
            chunk_size = min(max_vulns_per_page, 6)  # Limit to 6 vulnerabilities per table for better fit
            for start_idx in range(0, len(severity_df), chunk_size):
                end_idx = min(start_idx + chunk_size, len(severity_df))
                chunk = severity_df.iloc[start_idx:end_idx]
                
                # Create vulnerability table for this chunk
                vuln_table_data = [["Vulnerability ID", "Package", "Current Version", "CVSS", "Title"]]
                
                # Add data rows
                for _, vuln in chunk.iterrows():
                    cvss_text = f"{vuln['CVSS']}" if pd.notna(vuln['CVSS']) else "-"
                    
                    # Convert all text fields to Paragraph for proper text wrapping
                    vuln_id_paragraph = Paragraph(str(vuln["VulnerabilityID"]), styles["BodyText"])
                    pkg_name_paragraph = Paragraph(str(vuln["PkgName"]), styles["BodyText"]) 
                    version_paragraph = Paragraph(str(vuln["InstalledVersion"]), styles["BodyText"])
                    cvss_paragraph = Paragraph(cvss_text, styles["BodyText"])
                    title_paragraph = Paragraph(str(vuln["Title"]), styles["BodyText"])
                    
                    vuln_table_data.append([
                        vuln_id_paragraph,
                        pkg_name_paragraph,
                        version_paragraph,
                        cvss_paragraph,
                        title_paragraph
                    ])
                
                # Create custom style for table cells with smaller font to fit more text
                cell_style = ParagraphStyle(
                    'CellStyle',
                    parent=styles['BodyText'],
                    fontSize=7.5,   # Further reduced font size for better fit
                    leading=8.5,    # Reduced leading for more compact text
                    wordWrap='CJK',
                    alignment=0,    # Left alignment
                    allowWidows=0,  # No widows
                    allowOrphans=0, # No orphans
                    spaceAfter=0,   # No extra space after paragraphs
                    spaceBefore=0   # No extra space before paragraphs
                )
                
                # Replace all paragraphs with the smaller font version
                # Use custom styles for different columns to optimize display
                for i in range(1, len(vuln_table_data)):
                    for j in range(len(vuln_table_data[i])):
                        if isinstance(vuln_table_data[i][j], Paragraph):
                            text = vuln_table_data[i][j].text
                            # Use specific styles for different columns
                            if j == 4:  # Title column - needs special handling for potentially long text
                                title_style = ParagraphStyle(
                                    'TitleCellStyle',
                                    parent=cell_style,
                                    spaceAfter=0,
                                    spaceBefore=0,
                                    leading=8.5
                                )
                                vuln_table_data[i][j] = Paragraph(text, title_style)
                            else:
                                vuln_table_data[i][j] = Paragraph(text, cell_style)
                
                # Create and style the table
                # Adjusted column widths to better fit content - ensure "Title" column gets more space
                available_width = 7.5*inch  # Available width on letter page with margins
                col_widths = [1.25*inch, 1.1*inch, 1.05*inch, 0.6*inch, available_width - 4.0*inch]  # Give more space to the title column
                
                # Use dynamic row heights with a minimum for the header
                # Header row has minimum height, data rows are automatically sized based on content
                min_header_height = 0.25*inch
                row_heights = [min_header_height] + [None] * (len(vuln_table_data) - 1)
                
                # Create table with optimized settings for better pagination
                vuln_table = Table(
                    vuln_table_data, 
                    colWidths=col_widths, 
                    rowHeights=row_heights, 
                    repeatRows=1,
                    splitByRow=True  # Allow row splitting if absolutely necessary
                )
                
                vuln_table_style = TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), SEVERITY_COLORS.get(severity, colors.grey)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white if severity in ["Critical", "High"] else colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 2),   # Minimum padding
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 1),  # Minimum padding
                    ('TOPPADDING', (0, 1), (-1, -1), 1),     # Minimum padding
                    ('LEFTPADDING', (0, 0), (-1, -1), 2),    # Minimum padding
                    ('RIGHTPADDING', (0, 0), (-1, -1), 2),   # Minimum padding
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), True),    # Enable word wrapping for all cells
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),     # Align text to top for better readability
                ])
                
                # Alternating row colors
                for i in range(1, len(vuln_table_data)):
                    if i % 2 == 0:
                        vuln_table_style.add('BACKGROUND', (0, i), (-1, i), colors.whitesmoke)
                
                vuln_table.setStyle(vuln_table_style)
                # Add the table directly without wrapping in KeepTogether
                # This allows ReportLab to handle pagination naturally
                elements.append(vuln_table)
                elements.append(Spacer(1, 0.05*inch))
                
                # For each vulnerability in the chunk, add detailed information
                for idx, (_, vuln) in enumerate(chunk.iterrows()):
                    # Sanitize text to avoid XML parsing issues
                    safe_title = str(vuln['Title']).replace('<', '&lt;').replace('>', '&gt;')
                    safe_vuln_id = str(vuln['VulnerabilityID']).replace('<', '&lt;').replace('>', '&gt;')
                    safe_description = str(vuln["Description"]).replace('<', '&lt;').replace('>', '&gt;')
                    
                    # Create a heading for the vulnerability with the ID and title
                    elements.append(Paragraph(f"<b>{idx + 1 + start_idx}. {safe_vuln_id}: {safe_title}</b>", styles["Heading3"]))
                    
                    # Create a custom style for descriptions to ensure they're displayed completely
                    description_style = ParagraphStyle(
                        'DescriptionStyle',
                        parent=styles['BodyText'],
                        fontSize=9,
                        leading=11,  # Reduced line spacing for more compact display
                        firstLineIndent=0,
                        wordWrap='CJK',  # Better word wrapping for long text
                        alignment=0,   # Left alignment
                        allowWidows=0, # No widows
                        allowOrphans=0, # No orphans
                        spaceBefore=2,
                        spaceAfter=3    # Reduced space after description
                    )
                    
                    # Format description to preserve line breaks from the original text
                    formatted_description = safe_description.replace('\n', '<br/>')
                    
                    # Add description with improved formatting
                    elements.append(Paragraph("<b>Description:</b> " + formatted_description, description_style))
                    
                    # Add details as bullet points with improved formatting
                    pkg_name = str(vuln['PkgName']).replace('<', '&lt;').replace('>', '&gt;')
                    inst_ver = str(vuln['InstalledVersion']).replace('<', '&lt;').replace('>', '&gt;')
                    details = [
                        f"<b>Package:</b> {pkg_name} (version {inst_ver})",
                    ]
                    
                    if vuln["FixedVersion"]:
                        fixed_ver = str(vuln['FixedVersion']).replace('<', '&lt;').replace('>', '&gt;')
                        details.append(f"<b>Fixed in:</b> version {fixed_ver}")
                    
                    if pd.notna(vuln["CVSS"]) and pd.notna(vuln["CVSSVector"]):
                        cvss_vector = str(vuln['CVSSVector']).replace('<', '&lt;').replace('>', '&gt;')
                        details.append(f"<b>CVSS:</b> {vuln['CVSS']} ({cvss_vector})")
                    elif pd.notna(vuln["CVSS"]):
                        details.append(f"<b>CVSS:</b> {vuln['CVSS']}")
                        
                    if pd.notna(vuln["PublishedDate"]):
                        try:
                            pub_date = vuln['PublishedDate'].strftime('%Y-%m-%d')
                            details.append(f"<b>Published:</b> {pub_date}")
                        except:
                            pass
                    
                    # Handle references with better formatting
                    references = []
                    if "References" in vuln and vuln["References"] and isinstance(vuln["References"], list):
                        # Only show up to 3 references to avoid cluttering the report
                        max_refs = min(3, len(vuln["References"]))
                        for i in range(max_refs):
                            ref_str = str(vuln['References'][i]).replace('<', '&lt;').replace('>', '&gt;')
                            references.append(ref_str)
                    elif "PrimaryURL" in vuln and vuln["PrimaryURL"]:
                        safe_url = str(vuln['PrimaryURL']).replace('<', '&lt;').replace('>', '&gt;')
                        references.append(safe_url)
                    
                    if references:
                        details.append(f"<b>Reference:</b> {references[0]}")
                        # Add additional references as separate bullet points
                        for ref in references[1:]:
                            details.append(f"<b>Additional Reference:</b> {ref}")
                    
                    # Create a custom style for detail bullet points
                    detail_style = ParagraphStyle(
                        'DetailStyle',
                        parent=styles['BodyText'],
                        fontSize=9,
                        leading=12,
                        leftIndent=10,  # Indent bullets
                        firstLineIndent=0,
                        wordWrap='CJK',  # Better word wrapping for long text
                        alignment=0,     # Left alignment
                        allowWidows=0,   # No widows
                        allowOrphans=0   # No orphans
                    )
                    
                    # Special style for URLs to handle their potentially long lengths
                    url_style = ParagraphStyle(
                        'URLStyle',
                        parent=detail_style,
                        wordWrap='CJK',
                        allowWidows=0,
                        allowOrphans=0
                    )
                    
                    for i, detail in enumerate(details):
                        # Use special handling for URL references to prevent line breaking issues
                        if "Reference:" in detail:
                            # Split label and URL content
                            parts = detail.split(":", 1)
                            if len(parts) == 2:
                                label = parts[0] + ":"
                                url_text = parts[1]
                                elements.append(Paragraph(f"• {label}{url_text}", url_style))
                            else:
                                elements.append(Paragraph(f"• {detail}", detail_style))
                        else:
                            elements.append(Paragraph(f"• {detail}", detail_style))
                    
                    elements.append(Spacer(1, 0.05*inch))
                
                # Add page break between chunks
                if end_idx < len(severity_df):
                    elements.append(PageBreak())
            
            # Add page break between severity levels (except after the last one)
            if severity != severity_groups[-1]:
                elements.append(PageBreak())
        
        # Build the PDF
        doc.build(elements)
        
        print(f"Vulnerability report successfully created: {output_file}")
        return output_file
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert Grype JSON report to PDF vulnerability assessment')
    parser.add_argument('json_file', nargs='?', default="grype-result.json", help='Path to the Grype JSON report file')
    parser.add_argument('-o', '--output', help='Output PDF file path')
    parser.add_argument('--max-vulns', type=int, default=10, help='Maximum vulnerabilities per page (default: 10)')
    parser.add_argument('--no-charts', action='store_true', help='Disable chart generation')
    
    args = parser.parse_args()
    
    if args.no_charts:
        CHART_SUPPORT = False
        print("Chart generation disabled via command line option.")
    elif not CHART_SUPPORT:
        print("Chart generation is not available due to missing dependencies.")
        print("To enable charts, install required dependencies:")
        print("  pip install reportlab pillow")
        print("For better quality charts:")
        print("  pip install reportlab pycairo")
    
    # Create ReportLab-based PDF report
    create_vulnerability_report(args.json_file, args.output, args.max_vulns, args.no_charts)
