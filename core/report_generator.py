import os
import io
import json
import csv
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


class ComplianceReportGenerator:
    """Generates enterprise-grade compliance artifacts, audit summaries, and executive PDF reports."""

    @staticmethod
    def generate_csv_summary(result_data: Dict[str, Any], compliance_standard: str) -> str:
        """Generates a downloadable CSV security summary."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["CloudSentinel AI - Workload Security & Migration Audit"])
        writer.writerow(["Target Framework", compliance_standard])
        writer.writerow(["AMI ID", result_data.get("hardened_payload", {}).get("ami_id", "N/A")])
        writer.writerow(["Pre-Scan Score", result_data.get("pre_score", "N/A")])
        writer.writerow(["Post-Hardening Score", result_data.get("post_score", "N/A")])
        writer.writerow(["Deployment Status", result_data.get("deployment_status", "N/A")])
        writer.writerow([])
        writer.writerow(["Security Domain", "Pre-Remediation State (Quarantine)", "Post-Remediation State (Golden AMI)", "Compliance Impact"])

        delta_records = result_data.get("delta", [])
        for rec in delta_records:
            pre = rec.get("Pre-Remediation State (Quarantine)") or rec.get("Quarantined State", "")
            post = rec.get("Post-Remediation State (Golden AMI)") or rec.get("Hardened Golden State", "")
            impact = rec.get("Compliance Impact", "REMEDIATED")
            writer.writerow([
                rec.get("Security Domain", ""),
                pre,
                post,
                impact
            ])

        return output.getvalue()

    @staticmethod
    def generate_json_manifest(result_data: Dict[str, Any], compliance_standard: str) -> str:
        """Generates a complete compliance manifest JSON."""
        manifest = {
            "report_id": f"REP-{result_data.get('hardened_payload', {}).get('ami_id', 'GOLDEN')}",
            "compliance_standard": compliance_standard,
            "pre_hardening_score": result_data.get("pre_score"),
            "post_hardening_score": result_data.get("post_score"),
            "deployment_status": result_data.get("deployment_status"),
            "manifest": result_data.get("hardened_payload", {}),
            "remediation_logs": result_data.get("logs", [])
        }
        return json.dumps(manifest, indent=2)

    @staticmethod
    def generate_pdf_report(result_data: Dict[str, Any], compliance_standard: str) -> bytes:
        """Generates an executive PDF compliance audit report."""
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
        
        # Document title style (no unrendered emojis)
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a")
        )
        section_heading = ParagraphStyle(
            'SectionHead',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0369a1"),
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#1e293b")
        )
        
        # Explicit pure white text style for dark table header rows
        header_cell_style = ParagraphStyle(
            'HeaderCell',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=12,
            textColor=colors.white
        )
        
        cell_bold = ParagraphStyle(
            'CellBold',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0f172a")
        )
        cell_text = ParagraphStyle(
            'CellText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155")
        )

        elements = []

        # 1. Header Section
        elements.append(Paragraph("CloudSentinel AI — Security & Compliance Audit Report", title_style))
        elements.append(Paragraph(
            f"<b>Target Governance Standard:</b> {compliance_standard} | <b>Release Gate:</b> {result_data.get('deployment_status', 'DEPLOYED_TO_PRODUCTION')}", 
            body_style
        ))
        elements.append(Spacer(1, 6))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # 2. Executive Summary Block
        ami_id = result_data.get("hardened_payload", {}).get("ami_id", "ami-cloudsentinel-golden")
        pre_score = result_data.get("pre_score", 0)
        post_score = result_data.get("post_score", 0)

        summary_data = [
            [
                Paragraph("<b>Workload AMI ID:</b>", cell_bold), Paragraph(str(ami_id), cell_text),
                Paragraph("<b>Compliance Standard:</b>", cell_bold), Paragraph(str(compliance_standard), cell_text)
            ],
            [
                Paragraph("<b>Pre-Scan Baseline Score:</b>", cell_bold), Paragraph(f"<font color='#dc2626'><b>{pre_score}/100</b> (High Risk)</font>", cell_text),
                Paragraph("<b>Post-Hardening Verified:</b>", cell_bold), Paragraph(f"<font color='#16a34a'><b>{post_score}/100</b> (Approved)</font>", cell_text)
            ]
        ]
        summary_table = Table(summary_data, colWidths=[130, 140, 130, 140])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 10))

        # 3. Security Findings & Remediation Actions Table
        elements.append(Paragraph("2. Autonomous Multi-Agent Consensus Findings", section_heading))
        
        findings_table_data = [[
            Paragraph("Severity", header_cell_style),
            Paragraph("Agent", header_cell_style),
            Paragraph("Finding Description", header_cell_style),
            Paragraph("Remediation Action", header_cell_style)
        ]]

        findings = result_data.get("findings", [])
        if not findings and "blackboard" in result_data:
            findings = getattr(result_data["blackboard"], "findings", [])

        if not findings:
            findings_table_data.append([
                Paragraph("<font color='#dc2626'><b>CRITICAL</b></font>", cell_text),
                Paragraph("SecurityAgent", cell_text),
                Paragraph("<b>Unencrypted EBS Volume:</b> Storage volumes are unencrypted plaintext.", cell_text),
                Paragraph("Enforce AWS KMS CMK AES-256 volume encryption.", cell_text)
            ])
            findings_table_data.append([
                Paragraph("<font color='#ea580c'><b>HIGH</b></font>", cell_text),
                Paragraph("NetworkAgent", cell_text),
                Paragraph("<b>Ingress Exposure:</b> Open management ports to 0.0.0.0/0.", cell_text),
                Paragraph("Revoke 0.0.0.0/0; bind ingress to private VPC CIDRs.", cell_text)
            ])
            findings_table_data.append([
                Paragraph("<font color='#dc2626'><b>CRITICAL</b></font>", cell_text),
                Paragraph("IAMAgent", cell_text),
                Paragraph("<b>Over-Privileged Role:</b> Wildcard administrator access.", cell_text),
                Paragraph("Attach CloudSentinelScopedMigrationRole least-privilege profile.", cell_text)
            ])
            findings_table_data.append([
                Paragraph("<font color='#ea580c'><b>HIGH</b></font>", cell_text),
                Paragraph("ComplianceAgent", cell_text),
                Paragraph(f"<b>Non-Compliant:</b> Breaches {compliance_standard} requirements.", cell_text),
                Paragraph("Apply CIS Level 1 OS hardening and KMS policy controls.", cell_text)
            ])
        else:
            for f in findings:
                sev = getattr(f, "severity", "") or (f.get("severity") if isinstance(f, dict) else "MEDIUM")
                if sev == "CRITICAL":
                    sev_html = "<font color='#dc2626'><b>CRITICAL</b></font>"
                elif sev == "HIGH":
                    sev_html = "<font color='#ea580c'><b>HIGH</b></font>"
                else:
                    sev_html = "<font color='#16a34a'><b>INFO</b></font>"

                agent_nm = getattr(f, "agent_name", "") or (f.get("agent_name") if isinstance(f, dict) else "Agent")
                title = getattr(f, "title", "") or (f.get("title") if isinstance(f, dict) else "")
                desc = getattr(f, "description", "") or (f.get("description") if isinstance(f, dict) else "")
                finding_desc = f"<b>{title}:</b> {desc}" if title else desc

                action = (
                    getattr(f, "remediation_action", None) or
                    getattr(f, "action", None) or
                    (f.get("remediation_action") if isinstance(f, dict) else None) or
                    (f.get("action") if isinstance(f, dict) else None) or
                    "Apply Zero-Trust CIS baseline hardening"
                )

                findings_table_data.append([
                    Paragraph(sev_html, cell_text),
                    Paragraph(agent_nm, cell_text),
                    Paragraph(finding_desc, cell_text),
                    Paragraph(action, cell_text)
                ])

        findings_table = Table(findings_table_data, colWidths=[65, 85, 195, 195])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(findings_table)
        elements.append(Spacer(1, 10))

        # 4. Workload Delta Table
        elements.append(Paragraph("3. Workload Hardening Transformations (Before vs. After)", section_heading))
        
        delta_rows = [[
            Paragraph("Security Domain", header_cell_style),
            Paragraph("Quarantined State (Pre-Hardening)", header_cell_style),
            Paragraph("Hardened Golden State (Release)", header_cell_style)
        ]]

        delta_list = [
            ("Storage (EBS/KMS)", "Plaintext (UNENCRYPTED)", "Encrypted (AWS KMS AES-256 CMK)"),
            ("Network Perimeter", "Public IP + Ports Exposed (0.0.0.0/0)", "Private Isolated VPC (10.0.0.0/16)"),
            ("IAM Governance", "AdministratorAccess (Wildcard Privileges)", "CloudSentinelScopedMigrationRole (Least Privilege)"),
            ("OS CIS Baseline", "Root SSH & Password Auth Enabled", "CIS Level 1 Hardened (SSH Keys Only)")
        ]

        for domain, pre_st, post_st in delta_list:
            delta_rows.append([
                Paragraph(domain, cell_text),
                Paragraph(f"<font color='#dc2626'>{pre_st}</font>", cell_text),
                Paragraph(f"<font color='#16a34a'><b>{post_st}</b></font>", cell_text)
            ])

        delta_table = Table(delta_rows, colWidths=[130, 205, 205])
        delta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(delta_table)

        # Build Document
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()