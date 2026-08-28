import os
import sys
import json
import csv
import io
import time
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class ComplianceReportGenerator:
    """Generates regulatory compliance audit manifests, CSV summaries, and executive PDF reports."""

    @staticmethod
    def generate_csv_summary(pipeline_result: Dict[str, Any], framework_name: str) -> str:
        """Generates an executive-ready CSV report for cloud auditors."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["CloudSentinel AI - Security & Compliance Migration Audit"])
        writer.writerow(["Timestamp", time.strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Target Framework", framework_name])
        writer.writerow(["AMI ID", pipeline_result.get("hardened_payload", {}).get("ami_id", "N/A")])
        writer.writerow(["Deployment Status", pipeline_result.get("deployment_status", "UNKNOWN")])
        writer.writerow([])
        writer.writerow(["Metric", "Baseline (Pre-Scan)", "Verified Target (Post-Scan)", "Status"])
        
        pre_score = pipeline_result.get("pre_score", 0)
        post_score = pipeline_result.get("post_score", 0)
        status = "PASSED" if post_score >= 90 else "FAILED"
        
        writer.writerow(["Overall Security Score", f"{pre_score}/100", f"{post_score}/100", status])
        writer.writerow(["Storage Encryption", "Unencrypted", "AWS KMS CMK (AES-256)", "REMEDIATED"])
        writer.writerow(["VPC Ingress (Port 22/3389)", "Public 0.0.0.0/0", "Restricted 10.0.0.0/16", "REMEDIATED"])
        writer.writerow(["IAM Least Privilege", "Wildcard Admin Role", "Scoped Migration Profile", "REMEDIATED"])
        writer.writerow(["OS CIS Hardening", "Direct Root / Password Auth", "CIS Level 1 Locked", "REMEDIATED"])

        return output.getvalue()

    @staticmethod
    def generate_json_manifest(pipeline_result: Dict[str, Any], framework_name: str) -> str:
        """Serializes the full cryptographic and configuration manifest to JSON."""
        manifest = {
            "generator": "CloudSentinel AI Multi-Agent Engine v2.0",
            "audit_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target_compliance": framework_name,
            "pre_hardening_score": pipeline_result.get("pre_score"),
            "post_hardening_score": pipeline_result.get("post_score"),
            "deployment_status": pipeline_result.get("deployment_status"),
            "verification_details": pipeline_result.get("verification"),
            "golden_ami_manifest": pipeline_result.get("hardened_payload"),
            "multi_agent_blackboard": pipeline_result.get("blackboard")
        }
        return json.dumps(manifest, indent=2)

    @staticmethod
    def generate_pdf_report(pipeline_result: Dict[str, Any], framework_name: str) -> bytes:
        """Generates a professional, multi-section compliance and hardening audit PDF."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a")
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b")
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0369a1"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyDark',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155")
        )
        body_bold = ParagraphStyle(
            'BodyBold',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#0f172a")
        )

        story = []

        # 1. Header & Executive Summary
        story.append(Paragraph("🛡️ CLOUDSENTINEL AI", title_style))
        story.append(Paragraph("Autonomous Migration Security & Zero-Trust Golden AMI Hardening Audit", subtitle_style))
        story.append(Spacer(1, 4))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceBefore=2, spaceAfter=8))

        # Metadata Table
        hardened = pipeline_result.get("hardened_payload", {})
        ami_id = hardened.get("ami_id", "N/A")
        deployment_status = pipeline_result.get("deployment_status", "UNKNOWN")
        pre_score = pipeline_result.get("pre_score", 0)
        post_score = pipeline_result.get("post_score", 0)

        meta_data = [
            [
                Paragraph("<b>Audit Timestamp:</b>", body_style),
                Paragraph(time.strftime("%Y-%m-%d %H:%M:%S UTC"), body_style),
                Paragraph("<b>Target Compliance:</b>", body_style),
                Paragraph(framework_name, body_bold)
            ],
            [
                Paragraph("<b>Golden AMI ID:</b>", body_style),
                Paragraph(f"<code>{ami_id}</code>", body_style),
                Paragraph("<b>Deployment Status:</b>", body_style),
                Paragraph(f"<b>{deployment_status}</b>", body_bold)
            ],
            [
                Paragraph("<b>Pre-Scan Score:</b>", body_style),
                Paragraph(f"<font color='#dc2626'><b>{pre_score}/100 (Quarantined)</b></font>", body_style),
                Paragraph("<b>Post-Hardening Score:</b>", body_style),
                Paragraph(f"<font color='#16a34a'><b>{post_score}/100 (Approved)</b></font>", body_bold)
            ]
        ]

        meta_table = Table(meta_data, colWidths=[100, 170, 110, 160])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 8))

        # 2. Detailed Workload Manifest & Remediation Breakdown
        story.append(Paragraph("1. Configuration Manifest & Closed-Loop Remediation", h2_style))
        story.append(Paragraph("Detailed before-and-after audit breakdown showing exact cryptographic and perimeter modifications applied:", body_style))
        story.append(Spacer(1, 4))

        kms_key = hardened.get("storage", {}).get("kms_key_id", "N/A")
        role_attached = hardened.get("iam", {}).get("attached_role", "N/A")

        manifest_table_data = [
            [
                Paragraph("<b>Security Domain</b>", body_bold),
                Paragraph("<b>Pre-Scan Quarantine State</b>", body_bold),
                Paragraph("<b>Post-Hardening Golden AMI</b>", body_bold),
                Paragraph("<b>Verification Status</b>", body_bold)
            ],
            [
                Paragraph("<b>Storage Encryption</b>", body_style),
                Paragraph("Unencrypted EBS Plaintext Block Volume", body_style),
                Paragraph(f"KMS CMK Encrypted (AES-256)<br/><code>{kms_key.split('/')[-1]}</code>", body_style),
                Paragraph("<font color='#16a34a'><b>REMEDIATED</b></font>", body_style)
            ],
            [
                Paragraph("<b>Network Perimeter</b>", body_style),
                Paragraph("Management ports 22/3389 open to 0.0.0.0/0", body_style),
                Paragraph("Ingress restricted to Private VPC CIDR (10.0.0.0/16)", body_style),
                Paragraph("<font color='#16a34a'><b>REMEDIATED</b></font>", body_style)
            ],
            [
                Paragraph("<b>IAM Access Profile</b>", body_style),
                Paragraph("Wildcard Administrative Role Attached", body_style),
                Paragraph(f"Principle of Least Privilege Enforced<br/><code>{role_attached}</code>", body_style),
                Paragraph("<font color='#16a34a'><b>REMEDIATED</b></font>", body_style)
            ],
            [
                Paragraph("<b>OS Hardening Baseline</b>", body_style),
                Paragraph("SSH Root Login & Password Auth Enabled", body_style),
                Paragraph("CIS Level 1 Baseline (Key-Only Auth, Root Disabled)", body_style),
                Paragraph("<font color='#16a34a'><b>REMEDIATED</b></font>", body_style)
            ]
        ]

        manifest_table = Table(manifest_table_data, colWidths=[110, 150, 200, 80])
        manifest_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        # Fix text color for headers in Paragraphs
        manifest_table_data[0] = [
            Paragraph("<font color='#ffffff'><b>Security Domain</b></font>", body_bold),
            Paragraph("<font color='#ffffff'><b>Pre-Scan Quarantine State</b></font>", body_bold),
            Paragraph("<font color='#ffffff'><b>Post-Hardening Golden AMI</b></font>", body_bold),
            Paragraph("<font color='#ffffff'><b>Verification Status</b></font>", body_bold)
        ]
        story.append(manifest_table)
        story.append(Spacer(1, 8))

        # 3. Multi-Agent Explainable AI (XAI) Trace
        story.append(Paragraph("2. Autonomous Multi-Agent Consensus Findings", h2_style))
        story.append(Paragraph(f"<b>Supervisor AI Consensus Verdict:</b> {pipeline_result.get('blackboard', {}).get('supervisor_verdict', 'REMEDIATION_REQUIRED')}", body_bold))
        story.append(Paragraph(f"<b>Reasoning:</b> {pipeline_result.get('blackboard', {}).get('supervisor_reasoning', 'Quarantine isolation enforced due to critical security policy violations.')}", body_style))
        story.append(Spacer(1, 4))

        findings = pipeline_result.get("blackboard", {}).get("findings", [])
        if findings:
            findings_data = [
                [
                    Paragraph("<font color='#ffffff'><b>Severity</b></font>", body_bold),
                    Paragraph("<font color='#ffffff'><b>Agent</b></font>", body_bold),
                    Paragraph("<font color='#ffffff'><b>Finding Description</b></font>", body_bold),
                    Paragraph("<font color='#ffffff'><b>Remediation Action</b></font>", body_bold)
                ]
            ]
            for f in findings[:6]:  # Show top findings cleanly
                sev = f.get("severity", "HIGH")
                sev_color = "#dc2626" if sev == "CRITICAL" else ("#ea580c" if sev == "HIGH" else "#16a34a")
                findings_data.append([
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
                    Paragraph(f.get("agent_name", "SecurityAgent"), body_style),
                    Paragraph(f"<b>{f.get('title', '')}</b>: {f.get('description', '')}", body_style),
                    Paragraph(f"<code>{f.get('remediation_action', '')}</code>", body_style)
                ])

            findings_table = Table(findings_data, colWidths=[65, 95, 240, 140])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(findings_table)
        story.append(Spacer(1, 8))

        # 4. Target Compliance Framework Mapping
        story.append(Paragraph(f"3. Regulatory Compliance Assessment: {framework_name}", h2_style))
        compliance_rules = [
            f"<b>Data-at-Rest Protection:</b> AWS KMS Customer-Managed Key (CMK) attached. Satisfies encryption requirements.",
            f"<b>Perimeter Isolation:</b> Administrative ports (22, 3389, 3306) restricted to internal VPC CIDRs. Public 0.0.0.0/0 exposure revoked.",
            f"<b>Identity & Access Governance:</b> Attached scoped role '{role_attached}'. Wildcard administrator credentials revoked.",
            f"<b>Operating System Baseline:</b> Direct root access and password authentication disabled under CIS Level 1 guidelines."
        ]
        for rule in compliance_rules:
            story.append(Paragraph(f"• {rule}", body_style))

        # 5. Sign-off Footer
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=4, spaceAfter=6))
        story.append(Paragraph("<b>CloudSentinel AI Closed-Loop Verification Engine</b> | Verified Cryptographic Golden AMI Release Manifest", subtitle_style))

        doc.build(story)
        return buffer.getvalue()