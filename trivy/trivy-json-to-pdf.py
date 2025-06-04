import json
import pandas as pd
import datetime
import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape, portrait
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak, Spacer, Image, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import sys
import os
import argparse
from collections import Counter, defaultdict

# Import charting libraries with fallbacks
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
    "CRITICAL": colors.Color(0.8, 0.1, 0.1),  # Darker red
    "HIGH": colors.red,
    "MEDIUM": colors.orange,
    "LOW": colors.yellow,
    "UNKNOWN": colors.grey
}

def extract_vulnerabilities(trivy_data):
    """
    Extract vulnerability information from Trivy JSON data
    """
    vulnerabilities = []
    
    # Check if this is a Trivy JSON report
    if "Results" not in trivy_data:
        raise ValueError("This doesn't appear to be a Trivy vulnerability report")
    
    for result in trivy_data.get("Results", []):
        target = result.get("Target", "Unknown Target")
        target_type = result.get("Type", "Unknown Type")
        
        for vuln in result.get("Vulnerabilities", []):
            vuln["Target"] = target
            vuln["TargetType"] = target_type
            vulnerabilities.append(vuln)
            
    return vulnerabilities

def create_vulnerability_dataframe(vulnerabilities):
    """
    Convert vulnerability list into a pandas DataFrame with needed columns
    """
    if not vulnerabilities:
        return pd.DataFrame()
        
    # Extract relevant fields
    data = []
    for vuln in vulnerabilities:
        severity = vuln.get("Severity", "UNKNOWN")
        
        # Extract CVSS score if available
        cvss_score = None
        cvss_vector = None
        if "CVSS" in vuln:
            # Try different sources in priority order
            for source in ["nvd", "redhat", "vendor"]:
                if source in vuln["CVSS"] and "V3Score" in vuln["CVSS"][source]:
                    cvss_score = vuln["CVSS"][source]["V3Score"]
                    if "V3Vector" in vuln["CVSS"][source]:
                        cvss_vector = vuln["CVSS"][source]["V3Vector"]
                    break
        
        # Create row for the dataframe
        row = {
            "VulnerabilityID": vuln.get("VulnerabilityID", "Unknown"),
            "PkgName": vuln.get("PkgName", "Unknown"),
            "InstalledVersion": vuln.get("InstalledVersion", "Unknown"),
            "Severity": severity,
            "Title": vuln.get("Title", "Unknown"),
            "Description": vuln.get("Description", "No description available"),
            "CVSS": cvss_score,
            "CVSSVector": cvss_vector,
            "FixedVersion": vuln.get("FixedVersion", ""),
            "PublishedDate": vuln.get("PublishedDate", ""),
            "Target": vuln.get("Target", "Unknown"),
            "PrimaryURL": vuln.get("PrimaryURL", "")
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    
    # Convert dates if available
    if "PublishedDate" in df.columns:
        df["PublishedDate"] = pd.to_datetime(df["PublishedDate"], errors='coerce')
        
    # Sort by severity and CVSS score
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    df["SeverityOrder"] = df["Severity"].map(severity_order)
    df = df.sort_values(by=["SeverityOrder", "CVSS"], ascending=[True, False])
    df = df.drop("SeverityOrder", axis=1)
    
    return df

def create_summary_chart(vulnerabilities_df, output_path):
    """
    Create a summary chart of vulnerabilities by severity
    Returns None, None if chart creation fails
    
    Can return:
    - (drawing, path) if chart creation succeeds
    - (severity_counts, None) if only text table should be used
    """
    # Count vulnerabilities by severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    
    # Handle empty dataframes or dataframes without Severity column
    if len(vulnerabilities_df) == 0 or "Severity" not in vulnerabilities_df.columns:
        ordered_counts = {severity: 0 for severity in severity_order}
    else:
        severity_counts = Counter(vulnerabilities_df["Severity"])
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
    pie.slices[0].fillColor = SEVERITY_COLORS["CRITICAL"]
    pie.slices[1].fillColor = SEVERITY_COLORS["HIGH"]
    pie.slices[2].fillColor = SEVERITY_COLORS["MEDIUM"]
    pie.slices[3].fillColor = SEVERITY_COLORS["LOW"]
    pie.slices[4].fillColor = SEVERITY_COLORS["UNKNOWN"]
    
    drawing.add(pie)
    
    # Focus only on PNG output
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

def create_vulnerability_report(trivy_json_file, output_file=None, max_vulns_per_page=25):
    """
    Create a vulnerability assessment report from Trivy JSON output
    """
    # If output file not specified, use the same name as the JSON file with PDF extension
    if not output_file:
        output_file = os.path.splitext(trivy_json_file)[0] + '_vulnerability_report.pdf'
    
    output_dir = os.path.dirname(output_file) or "."
    
    print(f"Loading Trivy scan results from: {trivy_json_file}")
    try:
        # Load JSON data
        with open(trivy_json_file, 'r') as f:
            trivy_data = json.load(f)
        
        # Extract artifact details
        artifact_name = trivy_data.get("ArtifactName", "Unknown artifact")
        artifact_type = trivy_data.get("ArtifactType", "Unknown")
        timestamp = trivy_data.get("CreatedAt", "")
        scan_date = "Unknown"
        if timestamp:
            try:
                scan_date = datetime.datetime.fromisoformat(timestamp).strftime("%B %d, %Y %H:%M:%S")
            except:
                scan_date = timestamp
                
        # Extract vulnerability information
        print("Extracting vulnerability information...")
        vulnerabilities = extract_vulnerabilities(trivy_data)
        
        # Convert to DataFrame
        vuln_df = create_vulnerability_dataframe(vulnerabilities)
        
        # Create summary statistics
        vuln_count = len(vuln_df)
        severity_counts = {}
        
        # Handle empty dataframe case
        if vuln_count > 0 and "Severity" in vuln_df.columns:
            severity_counts = vuln_df["Severity"].value_counts().to_dict()
        else:
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            
        # Create summary chart or get ordered counts for text display
        chart_result, chart_path = create_summary_chart(vuln_df, output_dir)
        
        # If chart_result is a dictionary, it contains ordered counts
        if isinstance(chart_result, dict):
            ordered_severity_counts = chart_result
            chart_drawing = None
        else:
            chart_drawing = chart_result  # This is the actual drawing object
            ordered_severity_counts = None
        
        print(f"Creating vulnerability report with {vuln_count} vulnerabilities...")
        # Create PDF document
        doc = SimpleDocTemplate(output_file, pagesize=portrait(letter))
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle('TitleWithMore',
                                   parent=styles['Title'],
                                   fontSize=24,
                                   spaceAfter=12)
        heading_style = ParagraphStyle('Heading',
                                   parent=styles['Heading1'],
                                   fontSize=18,
                                   spaceAfter=10)
        subheading_style = ParagraphStyle('SubHeading',
                               parent=styles['Heading2'],
                               fontSize=16,
                               spaceAfter=8)
        normal_style = styles['Normal']
        
        # Elements for the PDF
        elements = []
        
        # Add title page
        elements.append(Paragraph(f"Trivy Vulnerability Assessment Report", title_style))
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(f"Target: {artifact_name}", styles['Heading1']))
        elements.append(Paragraph(f"Type: {artifact_type}", styles['Heading2']))
        elements.append(Paragraph(f"Scanner: Trivy", styles['Heading2']))
        elements.append(Paragraph(f"Scan Date: {scan_date}", styles['Heading2']))
        elements.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%B %d, %Y %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Add summary section
        elements.append(Paragraph("Executive Summary", heading_style))
        
        if vuln_count > 0:
            summary_text = f"""
            This report contains the results of a vulnerability scan conducted on {artifact_name} using the <b>Trivy</b> security scanner.
            The scan identified a total of <b>{vuln_count}</b> vulnerabilities, categorized by severity as follows:
            """
        else:
            summary_text = f"""
            This report contains the results of a vulnerability scan conducted on {artifact_name} using the <b>Trivy</b> security scanner.
            <b>No vulnerabilities were found</b> during the scan. This is a good indication that the target has minimal security exposure.
            """
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Add severity summary table
        summary_data = [
            ["Severity", "Count", "Percentage"],
            ["CRITICAL", severity_counts.get("CRITICAL", 0), f"{severity_counts.get('CRITICAL', 0)/vuln_count*100:.1f}%" if vuln_count else "0%"],
            ["HIGH", severity_counts.get("HIGH", 0), f"{severity_counts.get('HIGH', 0)/vuln_count*100:.1f}%" if vuln_count else "0%"],
            ["MEDIUM", severity_counts.get("MEDIUM", 0), f"{severity_counts.get('MEDIUM', 0)/vuln_count*100:.1f}%" if vuln_count else "0%"],
            ["LOW", severity_counts.get("LOW", 0), f"{severity_counts.get('LOW', 0)/vuln_count*100:.1f}%" if vuln_count else "0%"],
            ["UNKNOWN", severity_counts.get("UNKNOWN", 0), f"{severity_counts.get('UNKNOWN', 0)/vuln_count*100:.1f}%" if vuln_count else "0%"]
        ]
        
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
        for i, severity in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], 1):
            if severity in SEVERITY_COLORS:
                summary_table_style.add('BACKGROUND', (0, i), (0, i), SEVERITY_COLORS[severity])
                summary_table_style.add('TEXTCOLOR', (0, i), (0, i), colors.white if severity in ["CRITICAL", "HIGH"] else colors.black)
        
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
                    elements.append(Paragraph("Note: Chart visualization is disabled due to missing dependencies.", 
                                            styles["Italic"]))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Add findings section
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", heading_style))
        
        # If no vulnerabilities are found, display a message
        if vuln_count == 0 or "Severity" not in vuln_df.columns:
            elements.append(Paragraph("No vulnerabilities were found during the scan.", styles["Normal"]))
            elements.append(Spacer(1, 0.2*inch))
        else:
            # Group vulnerabilities by severity
            severity_groups = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
            
            for severity in severity_groups:
                # Filter vulnerabilities by current severity
                severity_df = vuln_df[vuln_df["Severity"] == severity]
                if len(severity_df) == 0:
                    continue
                
                elements.append(Paragraph(f"{severity} Severity Vulnerabilities ({len(severity_df)})", subheading_style))
                
                # Create a table for each severity level
                for start_idx in range(0, len(severity_df), max_vulns_per_page):
                    end_idx = min(start_idx + max_vulns_per_page, len(severity_df))
                    chunk = severity_df.iloc[start_idx:end_idx]
                
                # Create vulnerability table for this chunk
                vuln_table_data = [["Vulnerability ID", "Package", "Current Version", "CVSS", "Title"]]
                
                # Add data rows
                for _, vuln in chunk.iterrows():
                    cvss_text = f"{vuln['CVSS']}" if pd.notna(vuln['CVSS']) else "-"
                    
                    # Convert all text fields to Paragraph for proper text wrapping
                    vuln_id_paragraph = Paragraph(vuln["VulnerabilityID"], styles["BodyText"])
                    pkg_name_paragraph = Paragraph(vuln["PkgName"], styles["BodyText"]) 
                    version_paragraph = Paragraph(vuln["InstalledVersion"], styles["BodyText"])
                    cvss_paragraph = Paragraph(cvss_text, styles["BodyText"])
                    title_paragraph = Paragraph(vuln["Title"], styles["BodyText"])
                    
                    vuln_table_data.append([
                        vuln_id_paragraph,
                        pkg_name_paragraph,
                        version_paragraph,
                        cvss_paragraph,
                        title_paragraph
                    ])
                
                # Create and style the table
                col_widths = [1.2*inch, 1*inch, 1*inch, 0.7*inch, 3.5*inch]  # Increased width for titles
                # Set minimum row height to accommodate wrapped text
                row_heights = [0.4*inch] + [None] * (len(vuln_table_data) - 1)
                vuln_table = Table(vuln_table_data, colWidths=col_widths, rowHeights=row_heights, repeatRows=1)
                
                vuln_table_style = TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), SEVERITY_COLORS.get(severity, colors.grey)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white if severity in ["CRITICAL", "HIGH"] else colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),  # Add padding to all data rows
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), True),
                    ('WORDWRAP', (4, 1), (4, -1), True),  # Ensure title column wraps text
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),  # Align text to top in all cells for better readability
                ])
                
                # Alternating row colors
                for i in range(1, len(vuln_table_data)):
                    if i % 2 == 0:
                        vuln_table_style.add('BACKGROUND', (0, i), (-1, i), colors.whitesmoke)
                
                vuln_table.setStyle(vuln_table_style)
                elements.append(vuln_table)
                elements.append(Spacer(1, 0.2*inch))
                
                # For each vulnerability in the chunk, add detailed information
                for idx, (_, vuln) in enumerate(chunk.iterrows()):
                    # Sanitize text to avoid XML parsing issues
                    safe_title = str(vuln['Title']).replace('<', '&lt;').replace('>', '&gt;')
                    safe_vuln_id = str(vuln['VulnerabilityID']).replace('<', '&lt;').replace('>', '&gt;')
                    safe_description = str(vuln["Description"]).replace('<', '&lt;').replace('>', '&gt;')
                    
                    elements.append(Paragraph(f"<b>{idx + 1 + start_idx}. {safe_vuln_id}: {safe_title}</b>", styles["Heading3"]))
                    
                    # Add description
                    elements.append(Paragraph("<b>Description:</b> " + safe_description, styles["BodyText"]))
                    
                    # Add details as bullet points
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
                        
                    if vuln["PrimaryURL"]:
                        safe_url = str(vuln['PrimaryURL']).replace('<', '&lt;').replace('>', '&gt;')
                        details.append(f"<b>Reference:</b> {safe_url}")
                    
                    for detail in details:
                        elements.append(Paragraph(f"• {detail}", styles["BodyText"]))
                    
                    elements.append(Spacer(1, 0.1*inch))
                    
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
    parser = argparse.ArgumentParser(description='Convert Trivy JSON report to PDF vulnerability assessment')
    parser.add_argument('json_file', help='Path to the Trivy JSON report file')
    parser.add_argument('-o', '--output', help='Output PDF file path')
    parser.add_argument('--max-vulns', type=int, default=25, help='Maximum vulnerabilities per page')
    parser.add_argument('--no-charts', action='store_true', help='Disable chart generation')
    
    args = parser.parse_args()
    
    if args.no_charts:
        CHART_SUPPORT = False
        print("Chart generation disabled via command line option.")
    elif not CHART_SUPPORT:
        print("Chart generation is not available due to missing dependencies.")
        print("To enable charts, install required dependencies:")
        print("  pip install pycairo")
        print("For more information, see the README.md troubleshooting section.")
    
    create_vulnerability_report(args.json_file, args.output, args.max_vulns)
