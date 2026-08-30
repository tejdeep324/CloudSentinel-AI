import os
import sys
import json
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# Guarantee root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from agents.supervisor import SupervisorAgent
from core.scoring import calculate_risk_score
from core.compliance import evaluate_compliance, COMPLIANCE_STANDARDS
from core.hardening import HardeningEngine
from core.pipeline_orchestrator import PipelineOrchestrator
from core.database_service import AuditDatabaseService
from core.report_generator import ComplianceReportGenerator
from core.iac_generator import IaCGenerator
from core.ansible_generator import AnsiblePlaybookGenerator
from core.recovery_manager import RecoverySnapshotManager
from core.aws_live_service import AWSLiveService
from core.orchestration_service import AWSOrchestrationService
from core.packer_generator import PackerImageBuilderGenerator
from tools.cost_calculator_tool import FinOpsCostCalculatorTool
from tools.cve_scanner_tool import CVEScannerTool

# ----------------- PAGE CONFIG -----------------
st.set_page_config(
    page_title="CloudSentinel AI — Enterprise Governance",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- HIGH-CONTRAST MODERN STYLING -----------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    .agent-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 14px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    .badge-critical {
        background-color: #dc2626;
        color: #ffffff;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        display: inline-block;
    }
    
    .badge-high {
        background-color: #ea580c;
        color: #ffffff;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        display: inline-block;
    }
    
    .badge-pass {
        background-color: #16a34a;
        color: #ffffff;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        display: inline-block;
    }
    
    .stepper-container {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 14px 24px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 13px;
        font-weight: 600;
        color: #f1f5f9;
    }

    .stButton>button {
        border-radius: 8px;
        font-weight: 700;
        height: 44px;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- CACHED SERVICES -----------------
@st.cache_resource
def get_services():
    return (
        AuditDatabaseService(),
        SupervisorAgent(),
        PipelineOrchestrator(),
        AWSLiveService()
    )

db_service, supervisor, orchestrator, aws_service = get_services()

# Session State Page Routing
if "page_view" not in st.session_state:
    st.session_state.page_view = "STAGE_INGESTION"
if "pipeline_result" not in st.session_state:
    st.session_state.pipeline_result = None
if "current_payload" not in st.session_state:
    st.session_state.current_payload = None

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=56)
    st.markdown("### **CloudSentinel AI**")
    st.caption("Autonomous Workload Governance & AMI Hardening")
    st.markdown("---")

    # AWS Connectivity Status Indicator
    is_aws = aws_service.is_aws_authenticated()
    if is_aws:
        st.success("🟢 AWS Live SDK Connected")
    else:
        st.info("☁️ AWS Live Adapter (Simulated SDK)")

    st.markdown("---")
    selected_compliance = st.selectbox(
        "🎯 Target Compliance Framework",
        list(COMPLIANCE_STANDARDS.keys())
    )

    st.markdown("### 💰 FinOps & GreenOps")
    cost_data = FinOpsCostCalculatorTool.calculate_rightsizing_projection("m5.large")
    c_side1, c_side2 = st.columns(2)
    with c_side1:
        st.metric("Monthly Savings", f"${cost_data['monthly_savings']}/mo", f"-{cost_data['percentage_savings']}%")
    with c_side2:
        st.metric("CO₂ Cut", f"{cost_data['monthly_co2_reduction_kg']} kg", "Green Tier")

    st.markdown("---")
    simulate_fail = st.checkbox("🧪 Test Chaos Rollback")


# ==============================================================================
# PAGE 1: WORKLOAD INGESTION & STAGING
# ==============================================================================
if st.session_state.page_view == "STAGE_INGESTION":

    st.markdown("## 🛡️ Autonomous Migration Security Control Plane")
    
    with st.expander("ℹ️ **About CloudSentinel AI & Full AWS Stack Architecture**", expanded=False):
        st.markdown("""
        **CloudSentinel AI** covers the complete ecosystem from the specification:
        * **Infrastructure:** Amazon EC2, Golden AMI, AWS VPC, AWS IAM, Amazon S3, DynamoDB, AWS KMS, AWS WAF, Amazon CloudWatch, AWS Config.
        * **Orchestration & Integration:** AWS Step Functions, Amazon SQS, Amazon SNS, AWS Database Migration Service (DMS).
        * **AMI Building Tools:** HashiCorp Packer (`.pkr.hcl`) & AWS EC2 Image Builder Recipes.
        * **Multi-Agent Framework:** Supervisor & Sub-Agents with Gemini 2.5 Flash / local fallback tools.
        """)

    st.markdown("""
    <div class="stepper-container">
        <div><b>1. Ingestion Channel</b><br><small style="color:#38bdf8;">🔵 Ready</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>2. Multi-Agent Audit</b><br><small style="color:#94a3b8;">⚪ Pending</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>3. Golden AMI Bake</b><br><small style="color:#94a3b8;">⚪ Pending</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>4. Production Gate</b><br><small style="color:#94a3b8;">⚪ Pending</small></div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 📥 Select Workload Ingestion Channel")
    
    ingest_tab1, ingest_tab2, ingest_tab3, ingest_tab4, ingest_tab5 = st.tabs([
        "⚡ Scenario Presets",
        "☁️ Live AWS Account Ingestion (EC2 SDK)",
        "📝 Interactive Form Builder",
        "📁 JSON Webhook Upload & Extractor Guide",
        "🤖 Multi-Agent Directory & Guide"
    ])

    workload_payload = None

    # Channel 1: Presets
    with ingest_tab1:
        st.caption("Select a standard pre-configured test scenario:")
        preset_choice = st.selectbox(
            "Telemetry Profile:",
            [
                "Scenario 1: Critical Legacy Server (EBS Unencrypted + Open Ports 22/3389)",
                "Scenario 2: Unencrypted Production DB (Port 3306 Open)",
                "Scenario 3: Web App (Partially Hardened)"
            ]
        )
        if "Scenario 2" in preset_choice:
            with open("data/database_payload.json", "r") as f:
                workload_payload = json.load(f)
        elif "Scenario 3" in preset_choice:
            with open("data/webapp_payload.json", "r") as f:
                workload_payload = json.load(f)
        else:
            with open("data/sample_payload.json", "r") as f:
                workload_payload = json.load(f)

    # Channel 2: Live AWS Boto3 Discovery
    with ingest_tab2:
        st.caption("Discover live AWS EC2 instances, EBS volumes, and Security Groups via boto3 SDK:")
        aws_c1, aws_c2 = st.columns(2)
        with aws_c1:
            aws_reg = st.selectbox("AWS Target Region", ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"])
            aws_inst = st.text_input("Target AWS EC2 Instance ID", value="i-089a7f51b919e34e2")
        with aws_c2:
            st.text_input("Cross-Account IAM Role ARN", value="arn:aws:iam::123456789012:role/CloudSentinelDiscoveryRole")
            if st.button("📡 Discover & Fetch Live AWS Telemetry", use_container_width=True):
                with st.spinner("Connecting to AWS EC2 & Security Group APIs..."):
                    workload_payload = aws_service.discover_live_ec2_instance(aws_inst)
                    st.success(f"Ingested telemetry from {workload_payload.get('aws_source')}")

    # Channel 3: Form Builder
    with ingest_tab3:
        st.caption("Configure a migration workload manually:")
        form_col1, form_col2 = st.columns(2)
        with form_col1:
            form_inst_id = st.text_input("Instance ID", value="i-custom-legacy-09")
            form_inst_type = st.selectbox("Instance Type", ["m5.large", "t3.medium", "m5.2xlarge"])
            form_role = st.selectbox("IAM Role Profile", ["AdministratorAccess", "PowerUserAccess", "CloudSentinelScopedMigrationRole"])
            form_storage_enc = st.checkbox("EBS Storage Encrypted", value=False)
        with form_col2:
            form_ssh_open = st.checkbox("Expose Port 22 (SSH) to 0.0.0.0/0", value=True)
            form_rdp_open = st.checkbox("Expose Port 3389 (RDP) to 0.0.0.0/0", value=True)
            form_root_login = st.checkbox("OS SSH Root Login Enabled", value=True)
            form_pass_auth = st.checkbox("OS Password Authentication Enabled", value=True)

        if st.button("🔨 Stage Custom Workload"):
            sg_rules = []
            if form_ssh_open:
                sg_rules.append({"port": 22, "protocol": "tcp", "source": "0.0.0.0/0"})
            if form_rdp_open:
                sg_rules.append({"port": 3389, "protocol": "tcp", "source": "0.0.0.0/0"})

            workload_payload = {
                "instance_id": form_inst_id,
                "instance_type": form_inst_type,
                "storage": {"volume_id": "vol-custom-01", "encrypted": form_storage_enc, "kms_key_id": "arn:aws:kms:us-east-1:1111:key/01" if form_storage_enc else None},
                "network": {"public_ip_assigned": True, "security_group_rules": sg_rules},
                "iam": {"attached_role": form_role, "least_privilege_compliant": form_role == "CloudSentinelScopedMigrationRole"},
                "os_security": {"root_login_enabled": form_root_login, "password_auth_enabled": form_pass_auth, "cis_benchmark_compliant": False}
            }
            st.success("Custom workload staged successfully.")

    # Channel 4: JSON Upload & Extractor Guide (Method 1 & Method 2)
    with ingest_tab4:
        st.markdown("#### 📁 Upload Workload Telemetry JSON")
        uploaded = st.file_uploader("Upload pre-generated workload telemetry (.json)", type=["json"])
        if uploaded is not None:
            try:
                workload_payload = json.load(uploaded)
                st.success("JSON telemetry uploaded and staged successfully.")
            except Exception as e:
                st.error(f"Invalid JSON file: {str(e)}")

        st.markdown("---")
        st.markdown("### 🛠️ How to Generate This JSON from Your AWS Account")
        
        json_method1, json_method2 = st.tabs([
            "🐍 Method 1: Automated Python Extractor Script",
            "📋 Method 2: Manual AWS Console Mapping & Template"
        ])
        
        with json_method1:
            st.caption("Run this Python script on your local machine to automatically query AWS APIs via boto3 and export the JSON:")
            
            extractor_script = """import json
import boto3

# 1. Provide your EC2 instance ID and AWS Region
INSTANCE_ID = "i-089a7f51b919e34e2"  # <-- Replace with your Instance ID
REGION = "us-east-1"                 # <-- Replace with your AWS Region

ec2 = boto3.client("ec2", region_name=REGION)

# 2. Fetch Instance metadata
resp = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
instance = resp["Reservations"][0]["Instances"][0]

# Volume encryption check
vol_id = instance["BlockDeviceMappings"][0]["Ebs"]["VolumeId"] if instance.get("BlockDeviceMappings") else "vol-none"
vol_info = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0] if vol_id != "vol-none" else {}

# Security group ingress check
sg_id = instance["SecurityGroups"][0]["GroupId"] if instance.get("SecurityGroups") else None
sg_rules = []
if sg_id:
    sg_info = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    for perm in sg_info.get("IpPermissions", []):
        port = perm.get("FromPort", 0)
        proto = perm.get("IpProtocol", "tcp")
        for ip in perm.get("IpRanges", []):
            sg_rules.append({"port": port, "protocol": proto, "source": ip.get("CidrIp", "")})

# IAM Role check
iam_arn = instance.get("IamInstanceProfile", {}).get("Arn", "None")
role_name = iam_arn.split("/")[-1] if "arn" in iam_arn else "None"

# 3. Assemble CloudSentinel Standard Schema
telemetry = {
    "instance_id": INSTANCE_ID,
    "instance_type": instance.get("InstanceType", "t3.medium"),
    "storage": {
        "volume_id": vol_id,
        "encrypted": vol_info.get("Encrypted", False),
        "kms_key_id": vol_info.get("KmsKeyId", None)
    },
    "network": {
        "public_ip_assigned": bool(instance.get("PublicIpAddress")),
        "security_group_rules": sg_rules
    },
    "iam": {
        "attached_role": role_name,
        "least_privilege_compliant": "admin" not in role_name.lower() and role_name != "None"
    },
    "os_security": {
        "root_login_enabled": True,
        "password_auth_enabled": True,
        "cis_benchmark_compliant": False
    },
    "packages": [
        {"name": "openssh-server", "version": "8.2p1"},
        {"name": "libssl1.1", "version": "1.1.1f"}
    ]
}

# 4. Save to JSON
with open("workload_telemetry.json", "w") as f:
    json.dump(telemetry, f, indent=2)

print("Generated workload_telemetry.json successfully!")
"""
            st.code(extractor_script, language="python")
            st.download_button(
                "📥 Download extract_telemetry.py",
                data=extractor_script,
                file_name="extract_telemetry.py",
                mime="text/x-python",
                type="primary"
            )

        with json_method2:
            st.caption("Copy this template into a text editor (e.g., Notepad / VS Code) and populate the values directly from your AWS Console:")
            
            sample_json_template = {
                "instance_id": "i-0a8f9214b7e1234a5",
                "instance_type": "m5.large",
                "storage": {
                    "volume_id": "vol-0192837465abcde12",
                    "encrypted": False,
                    "kms_key_id": None
                },
                "network": {
                    "public_ip_assigned": True,
                    "security_group_rules": [
                        {"port": 22, "protocol": "tcp", "source": "0.0.0.0/0"},
                        {"port": 3389, "protocol": "tcp", "source": "0.0.0.0/0"}
                    ]
                },
                "iam": {
                    "attached_role": "AdministratorAccess",
                    "least_privilege_compliant": False
                },
                "os_security": {
                    "root_login_enabled": True,
                    "password_auth_enabled": True,
                    "cis_benchmark_compliant": False
                }
            }
            
            st.code(json.dumps(sample_json_template, indent=2), language="json")
            st.download_button(
                "📥 Download workload_template.json",
                data=json.dumps(sample_json_template, indent=2),
                file_name="workload_template.json",
                mime="application/json"
            )

            with st.expander("🔍 AWS Console Navigation Guide (Where to Find Each Field)"):
                st.markdown("""
                * **`instance_id` & `instance_type`:** Open **EC2 Console** $\\rightarrow$ Click **Instances** $\\rightarrow$ Select your instance $\\rightarrow$ Copy from the **Details** tab.
                * **`storage` (Volume & Encryption):** In instance details, open the **Storage** tab $\\rightarrow$ Click the **Volume ID** $\\rightarrow$ Check whether **Encryption** states *Encrypted* or *Not Encrypted*.
                * **`network` & `security_group_rules`:** In instance details, open the **Security** tab $\\rightarrow$ Click the **Security Group ID** $\\rightarrow$ Check the **Inbound Rules** table for exposed ports (`22`, `3389`, `3306`) and source CIDRs (`0.0.0.0/0`).
                * **`iam`:** In instance details, open the **Security** tab $\\rightarrow$ Check the **IAM Role** name.
                """)

    # Channel 5: Multi-Agent Directory Tab
    with ingest_tab5:
        st.markdown("### 🤖 CloudSentinel Multi-Agent Architecture Directory")
        st.write("Overview of the specialized AI agents operating inside the governance blackboard:")
        
        agent_cols = st.columns(2)
        with agent_cols[0]:
            st.markdown("""
            <div class="agent-card">
                <h4 style="color:#0284c7; margin:0 0 6px 0;">🧠 SupervisorAgent (Orchestration & Consensus)</h4>
                <b>Target Problem:</b> Multi-domain conflict resolution and trade-off planning.<br>
                <b>AWS Stack:</b> Coordinates Step Functions, dispatches SQS queues, and structures AMI baking.
            </div>
            <div class="agent-card">
                <h4 style="color:#dc2626; margin:0 0 6px 0;">🔒 SecurityAgent (Storage & OS Hardening)</h4>
                <b>Target Problem:</b> Plaintext disk storage and insecure OS configurations.<br>
                <b>AWS Stack:</b> Interacts with <b>AWS KMS</b> for CMK encryption and Packer recipes.
            </div>
            <div class="agent-card">
                <h4 style="color:#ea580c; margin:0 0 6px 0;">🌐 NetworkAgent (Perimeter & Ingress)</h4>
                <b>Target Problem:</b> Public internet exposure of sensitive management & DB ports.<br>
                <b>AWS Stack:</b> Secures <b>AWS VPC Security Groups</b> and configures <b>AWS WAF</b> rulesets.
            </div>
            """, unsafe_allow_html=True)
            
        with agent_cols[1]:
            st.markdown("""
            <div class="agent-card">
                <h4 style="color:#7c3aed; margin:0 0 6px 0;">🔑 IAMAgent (Access Governance & Least Privilege)</h4>
                <b>Target Problem:</b> Over-privileged wildcard administrator roles on compute instances.<br>
                <b>AWS Stack:</b> Evaluates <b>AWS IAM</b> instance profiles and enforces Least Privilege.
            </div>
            <div class="agent-card">
                <h4 style="color:#16a34a; margin:0 0 6px 0;">📋 ComplianceAgent (Regulatory Framework Mapping)</h4>
                <b>Target Problem:</b> Regulatory compliance failure under standard cloud frameworks.<br>
                <b>AWS Stack:</b> Maps violations directly to <b>AWS Config Rules</b>, PCI-DSS, HIPAA, and SOC 2.
            </div>
            <div class="agent-card">
                <h4 style="color:#0f766e; margin:0 0 6px 0;">🔍 CVEScannerTool (Package Vulnerability Hunter)</h4>
                <b>Target Problem:</b> Unpatched OS vulnerabilities and known software exploits.<br>
                <b>AWS Stack:</b> Correlates CVEs and triggers Packer provisioning patches.
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    if workload_payload is not None:
        st.session_state.current_payload = workload_payload

    st.json(st.session_state.current_payload, expanded=False)
    
    if st.button("🚀 Ingest Workload to Quarantine & Launch Autonomous Multi-Agent Scan", type="primary", use_container_width=True):
        st.session_state.page_view = "MULTI_AGENT_AUDIT"
        st.rerun()


# ==============================================================================
# PAGE 2: MULTI-AGENT AUDIT & PRE-SCAN ASSESSMENT
# ==============================================================================
elif st.session_state.page_view == "MULTI_AGENT_AUDIT":
    payload = st.session_state.current_payload or {}

    st.markdown("""
    <div class="stepper-container">
        <div><b>1. Ingestion Channel</b><br><small style="color:#38bdf8;">🟢 Complete</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>2. Multi-Agent Audit</b><br><small style="color:#38bdf8;">🟡 Active Review</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>3. Golden AMI Bake</b><br><small style="color:#94a3b8;">⚪ Pending Execution</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>4. Production Gate</b><br><small style="color:#94a3b8;">⚪ Pending</small></div>
    </div>
    """, unsafe_allow_html=True)

    c_nav1, c_nav2 = st.columns([8, 2])
    with c_nav1:
        st.markdown("## 🤖 Multi-Agent Security Audit & Strategy Selection")
    with c_nav2:
        if st.button("⬅️ Change Workload", use_container_width=True):
            st.session_state.page_view = "STAGE_INGESTION"
            st.rerun()

    col1, col2 = st.columns([1, 1], gap="large")

    # Left Column: Pre-Scan Score & CVEs
    with col1:
        st.markdown("### 📥 Quarantined Workload Telemetry")
        pre_eval = calculate_risk_score(payload)
        pre_score = pre_eval["total_score"]

        gauge_pre_color = "#dc2626" if pre_score < 60 else "#d97706"
        fig_pre = go.Figure(go.Indicator(
            mode="gauge+number",
            value=pre_score,
            title={'text': "<b>Pre-Scan Baseline Risk Score</b>", 'font': {'size': 18, 'color': '#0f172a'}},
            number={'font': {'size': 48, 'color': '#0f172a', 'family': 'Inter, sans-serif'}},
            gauge={
                'axis': {'range': [0, 100], 'tickcolor': "#475569", 'tickfont': {'size': 12, 'color': '#334155'}},
                'bar': {'color': gauge_pre_color, 'thickness': 0.28},
                'bgcolor': "#e2e8f0",
                'bordercolor': "#cbd5e1",
                'steps': [
                    {'range': [0, 50], 'color': "#fee2e2"},
                    {'range': [50, 80], 'color': "#fef3c7"},
                    {'range': [80, 100], 'color': "#dcfce7"}
                ]
            }
        ))
        fig_pre.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=260,
            margin=dict(l=20, r=20, t=55, b=20)
        )
        st.plotly_chart(fig_pre, use_container_width=True)

        with st.expander("📄 Quarantined Telemetry JSON", expanded=False):
            st.json(payload)

        st.markdown("#### 🔍 Package CVE Vulnerabilities")
        cve_findings = CVEScannerTool.scan_workload_packages(payload)
        if cve_findings:
            for cve in cve_findings:
                st.markdown(f"""
                <div style="background:#ffffff; border-left: 4px solid #dc2626; border: 1px solid #e2e8f0; padding: 10px 14px; border-radius: 6px; margin-bottom: 8px;">
                    <span class="badge-critical">{cve['cve_id']}</span> <strong style="color:#0f172a;">{cve['package']}</strong> <span style="color:#64748b; font-size:12px;">(CVSS {cve['cvss_score']})</span>
                    <div style="font-size: 12px; color: #334155; margin-top: 4px;">{cve['description']}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("<span class='badge-pass'>✓ No Package CVEs Detected</span>", unsafe_allow_html=True)

    # Right Column: Multi-Agent Consensus & Remediation Selector
    with col2:
        st.markdown("### 🤖 Autonomous Multi-Agent Consensus")
        blackboard = supervisor.coordinate_assessment(payload, target_compliance=selected_compliance)

        if blackboard.supervisor_verdict == "REMEDIATION_REQUIRED":
            st.markdown(f"""
            <div style="background: #fef2f2; border: 1.5px solid #f87171; border-radius: 8px; padding: 14px; margin-bottom: 14px;">
                <strong style="color: #991b1b; font-size: 15px;">⚠️ Supervisor AI Verdict: REMEDIATION REQUIRED</strong>
                <div style="font-size: 13px; color: #7f1d1d; margin-top: 6px; font-weight: 500;">{blackboard.supervisor_reasoning}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background: #f0fdf4; border: 1.5px solid #4ade80; border-radius: 8px; padding: 14px; margin-bottom: 14px;">
                <strong style="color: #166534; font-size: 15px;">✅ Supervisor AI Verdict: APPROVED FOR MIGRATION</strong>
                <div style="font-size: 13px; color: #14532d; margin-top: 6px; font-weight: 500;">{blackboard.supervisor_reasoning}</div>
            </div>
            """, unsafe_allow_html=True)

        with st.expander(f"📋 Sub-Agent XAI Findings Trace ({len(blackboard.findings)} Identified)", expanded=True):
            for f in blackboard.findings:
                badge_class = "badge-critical" if f.severity == "CRITICAL" else ("badge-high" if f.severity == "HIGH" else "badge-pass")
                st.markdown(f"""
                <div style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;">
                    <span class="{badge_class}">{f.severity}</span> <strong style="color:#0f172a;">[{f.agent_name}]</strong> <span style="color:#1e293b; font-weight:600;">{f.title}</span>
                    <div style="font-size: 12.5px; color: #475569; margin-top: 4px;">{f.description}</div>
                    <div style="font-size: 11.5px; color: #0284c7; margin-top: 3px; font-weight:500;">Action: <code>{f.remediation_action}</code></div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("#### ⚙️ Remediation Strategy Execution")
        selected_plan = st.selectbox("Select Execution Strategy:", list(blackboard.remediation_plans.keys()))
        plan_obj = blackboard.remediation_plans[selected_plan]
        st.caption(f"⚡ **Details:** {plan_obj.description}")

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔧 Execute Hardening & Build Golden AMI", type="primary", use_container_width=True):
            with st.spinner("Invoking AWS KMS, SQS queues, and baking Golden AMI..."):
                res = orchestrator.run_full_pipeline(payload, selected_plan, force_failure=simulate_fail)
                res["selected_plan_name"] = selected_plan
                
                # AWS Live Service + SNS Integration
                aws_exec_res = aws_service.execute_live_hardening(payload, selected_plan)
                res["logs"].extend(aws_exec_res["logs"])
                
                sns_res = AWSOrchestrationService.publish_sns_security_alert(
                    "arn:aws:sns:us-east-1:123456789012:CloudSentinelMigrationApprovals",
                    payload.get("instance_id", "i-workload-node"),
                    res["deployment_status"],
                    res["post_score"]
                )
                res["logs"].append(f"[Amazon SNS] Published security event notification: {sns_res['message_id']}")

                st.session_state.pipeline_result = res
                
                db_service.record_migration_event(
                    instance_id=payload.get("instance_id", "i-workload-node"),
                    pre_score=res["pre_score"],
                    post_score=res["post_score"],
                    compliance=selected_compliance,
                    status=res["deployment_status"],
                    manifest=res["hardened_payload"]
                )
                st.session_state.page_view = "REMEDIATION_RESULTS"
                st.rerun()


# ==============================================================================
# PAGE 3: DEDICATED AUDIT RESULTS & VERIFICATION CONSOLE
# ==============================================================================
elif st.session_state.page_view == "REMEDIATION_RESULTS":
    res = st.session_state.pipeline_result
    payload = st.session_state.current_payload or {}

    st.markdown("""
    <div class="stepper-container">
        <div><b>1. Ingestion Channel</b><br><small style="color:#38bdf8;">🟢 Complete</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>2. Multi-Agent Audit</b><br><small style="color:#38bdf8;">🟢 Verified</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>3. Golden AMI Bake</b><br><small style="color:#38bdf8;">🟢 Baked</small></div>
        <div style="color:#64748b;">➜</div>
        <div><b>4. Production Gate</b><br><small style="color:#38bdf8;">🟢 Deployed</small></div>
    </div>
    """, unsafe_allow_html=True)

    # Top Navigation Row
    top_c1, top_c2 = st.columns([8, 2])
    with top_c1:
        st.markdown("## 🎯 Post-Hardening Verification & Production Gate")
    with top_c2:
        if st.button("⬅️ Back to Main Dashboard", type="primary", use_container_width=True):
            st.session_state.page_view = "STAGE_INGESTION"
            st.session_state.pipeline_result = None
            st.rerun()

    tab_res1, tab_res2, tab_res3, tab_res4, tab_res5, tab_res6 = st.tabs([
        "🛡️ Posture Verification",
        "🏗️ Terraform IaC (10 AWS Services)",
        "📦 HashiCorp Packer & Image Builder",
        "⚙️ Step Functions & DMS",
        "📋 Regulatory Compliance & FinOps",
        "🗄️ Audit Logs"
    ])

    with tab_res1:
        r1, r2, r3 = st.columns([1, 1, 1], gap="medium")
        with r1:
            is_prod = res["deployment_status"] == "DEPLOYED_TO_PRODUCTION"
            card_bg = "#f0fdf4" if is_prod else "#fef2f2"
            card_border = "#86efac" if is_prod else "#fca5a5"
            status_color = "#166534" if is_prod else "#991b1b"
            
            st.markdown(f"""
            <div style="background:{card_bg}; border: 1.5px solid {card_border}; border-radius:10px; padding:16px;">
                <h4 style="color: {status_color}; margin: 0 0 10px 0;">{res['verification']['status']}</h4>
                <div style="font-size: 13.5px; margin-bottom: 5px; color:#0f172a;"><b>Deployment State:</b> <code>{res['deployment_status']}</code></div>
                <div style="font-size: 13.5px; margin-bottom: 5px; color:#0f172a;"><b>Baked Golden AMI:</b> <code>{res['hardened_payload'].get('ami_id')}</code></div>
                <div style="font-size: 13.5px; color:#0f172a;"><b>Score Delta:</b> <span style="color: #16a34a; font-weight:700;">{res['verification']['score_delta']}</span></div>
            </div>
            """, unsafe_allow_html=True)

        with r2:
            fig_post = go.Figure(go.Indicator(
                mode="gauge+number",
                value=res["post_score"],
                title={'text': "<b>Post-Hardening Verified Score</b>", 'font': {'size': 18, 'color': '#0f172a'}},
                number={'font': {'size': 48, 'color': '#0f172a', 'family': 'Inter, sans-serif'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickcolor': "#475569", 'tickfont': {'size': 12, 'color': '#334155'}},
                    'bar': {'color': "#16a34a" if res["post_score"] >= 90 else "#dc2626", 'thickness': 0.28},
                    'bgcolor': "#e2e8f0",
                    'bordercolor': "#cbd5e1",
                    'steps': [
                        {'range': [0, 50], 'color': "#fee2e2"},
                        {'range': [50, 80], 'color': "#fef3c7"},
                        {'range': [80, 100], 'color': "#dcfce7"}
                    ]
                }
            ))
            fig_post.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=260,
                margin=dict(l=20, r=20, t=55, b=20)
            )
            st.plotly_chart(fig_post, use_container_width=True)

        with r3:
            with st.expander("📦 Baked Golden AMI JSON Manifest", expanded=True):
                st.json(res["hardened_payload"])

        st.markdown("#### 🔍 Workload Hardening Delta (Before vs. After)")
        delta_data = HardeningEngine.compute_delta(payload, res["hardened_payload"])
        st.dataframe(pd.DataFrame(delta_data), use_container_width=True, hide_index=True)

        with st.expander("🖥️ Real-Time AWS SDK & Autonomous Execution Logs", expanded=False):
            st.code("\n".join(res["logs"]), language="bash")

        st.markdown("#### 📥 Compliance & Security Audit Downloads")
        d1, d2, d3 = st.columns(3)
        csv_rep = ComplianceReportGenerator.generate_csv_summary(res, selected_compliance)
        json_man = ComplianceReportGenerator.generate_json_manifest(res, selected_compliance)
        pdf_rep = ComplianceReportGenerator.generate_pdf_report(res, selected_compliance)

        with d1:
            st.download_button(
                "📄 Security Audit Summary (.CSV)",
                data=csv_rep,
                file_name=f"Audit_{res['hardened_payload'].get('ami_id')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        with d2:
            st.download_button(
                "📦 Full Compliance Manifest (.JSON)",
                data=json_man,
                file_name=f"Manifest_{res['hardened_payload'].get('ami_id')}.json",
                mime="application/json",
                use_container_width=True
            )
        with d3:
            st.download_button(
                "📑 Download Audit Report (.PDF)",
                data=pdf_rep,
                file_name=f"CloudSentinel_Report_{res['hardened_payload'].get('ami_id')}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )

    with tab_res2:
        st.markdown("### 🏗️ Auto-Generated Terraform IaC (10 AWS Services)")
        tf_code = IaCGenerator.generate_terraform(res["hardened_payload"], selected_compliance)
        st.code(tf_code, language="hcl")
        st.download_button("📥 Download main.tf", data=tf_code, file_name="main.tf", mime="text/plain", type="primary")

    with tab_res3:
        st.markdown("### 📦 HashiCorp Packer & AWS EC2 Image Builder Recipes")
        packer_code = PackerImageBuilderGenerator.generate_packer_hcl(res["hardened_payload"], selected_compliance)
        st.code(packer_code, language="hcl")
        st.download_button("📥 Download packer.pkr.hcl", data=packer_code, file_name="packer.pkr.hcl", mime="text/plain", type="primary")

    with tab_res4:
        st.markdown("### ⚙️ AWS Step Functions ASL & AWS DMS Configuration")
        sfn_code = AWSOrchestrationService.generate_step_functions_asl()
        dms_code = AWSOrchestrationService.generate_dms_migration_task()
        
        st.markdown("#### 🔄 AWS Step Functions State Machine (ASL JSON)")
        st.code(sfn_code, language="json")
        
        st.markdown("#### 🗄️ AWS Database Migration Service (DMS) Task Definition")
        st.code(dms_code, language="json")

    with tab_res5:
        st.markdown(f"### 📋 Regulatory Compliance Analysis: **{selected_compliance}**")
        comp_res = evaluate_compliance(payload, selected_compliance)
        
        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("#### 🔴 Quarantined Workload Violations")
            for f in comp_res["failed"]:
                st.error(f)
        with c_right:
            st.markdown("#### 🟢 Remediated Compliance Guarantees")
            for p in comp_res["passed"]:
                st.success(p)

        st.markdown("---")
        st.markdown("### 💡 FinOps Right-Sizing & GreenOps Carbon Impact")
        f1, f2, f3 = st.columns(3)
        with f1:
            st.metric("Current Profile", cost_data['current_instance'], f"${cost_data['current_monthly_cost']}/mo")
        with f2:
            st.metric("Recommended Profile", cost_data['recommended_instance'], f"${cost_data['optimized_monthly_cost']}/mo")
        with f3:
            st.metric("Monthly Savings", f"${cost_data['monthly_savings']}/mo", f"-{cost_data['percentage_savings']}%")

        # Snapshot & DR Runbook
        st.markdown("---")
        st.markdown("### 🔄 Point-in-Time Rollback & Safety Snapshot Runbook")
        dr_info = RecoverySnapshotManager.generate_dr_runbook(payload)
        with st.expander("🛠️ View Point-in-Time Disaster Recovery Runbook (.sh)", expanded=False):
            st.code(dr_info["rollback_script"], language="bash")

    with tab_res6:
        st.markdown("### 🗄️ Immutable Migration Audit Log (SQLite)")
        history = db_service.get_historical_logs()
        if len(history) > 0:
            st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
        else:
            st.info("No migration events recorded yet.")