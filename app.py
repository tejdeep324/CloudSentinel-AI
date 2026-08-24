import streamlit as st
import json
import plotly.graph_objects as go
from agents.supervisor import SupervisorAgent
from core.scoring import calculate_risk_score
from core.compliance import evaluate_compliance, calculate_cost_optimization, COMPLIANCE_STANDARDS
from core.pipeline_orchestrator import PipelineOrchestrator

st.set_page_config(page_title="CloudSentinel AI", page_icon="🛡️", layout="wide")

# Initialize Session State
if "scan_started" not in st.session_state:
    st.session_state.scan_started = False
if "hardened" not in st.session_state:
    st.session_state.hardened = False

st.title("🛡️ CloudSentinel AI")
st.caption("Autonomous Workload Security & Zero-Trust AMI Hardening Platform")
st.markdown("---")

# Sidebar Controls
st.sidebar.header("⚙️ Governance & Settings")
selected_compliance = st.sidebar.selectbox("Target Compliance Framework:", list(COMPLIANCE_STANDARDS.keys()))

scenario = st.sidebar.selectbox(
    "Workload Source:",
    ["Simulated Migration Payload (Default)", "Custom JSON Upload"]
)

if scenario == "Custom JSON Upload":
    uploaded_file = st.sidebar.file_uploader("Upload Server Telemetry JSON", type=["json"])
    if uploaded_file is not None:
        payload = json.load(uploaded_file)
    else:
        with open("data/sample_payload.json", "r") as f:
            payload = json.load(f)
else:
    with open("data/sample_payload.json", "r") as f:
        payload = json.load(f)

simulate_fail = st.sidebar.checkbox("Simulate Hardening Failure (Test Rollback)")

# Initial State: Waiting for user to start scan
if not st.session_state.scan_started:
    st.info("👋 System Ready. Inbound server migration detected in Quarantine VPC Subnet.")
    st.json(payload)
    
    if st.button("🚀 Start Ingestion & Autonomous Scan", type="primary"):
        st.session_state.scan_started = True
        st.rerun()

# Step 1: Scan Started -> Show Assessment and Options
else:
    tab1, tab2 = st.tabs(["🚀 Real-Time Pipeline Interception", "📋 Compliance & Audit Reports"])

    with tab1:
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("📥 Inbound Workload Payload (Quarantined)")
            st.json(payload)
            
            pre_eval = calculate_risk_score(payload)
            pre_score = pre_eval["total_score"]
            
            fig_pre = go.Figure(go.Indicator(
                mode="gauge+number",
                value=pre_score,
                title={'text': "Pre-Scan Risk Score (Critical Risk)"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#EF4444"},
                    'steps': [
                        {'range': [0, 50], 'color': "#FEE2E2"},
                        {'range': [50, 80], 'color': "#FEF3C7"},
                        {'range': [80, 100], 'color': "#D1FAE5"}
                    ]
                }
            ))
            fig_pre.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_pre, use_container_width=True)

        with col2:
            st.subheader("🤖 Autonomous Agent Assessment")
            supervisor = SupervisorAgent()
            assessment = supervisor.coordinate_assessment(payload)
            
            st.error(f"⚠️ **Verdict:** {assessment['supervisor_verdict']} (Confidence: {assessment['confidence_score']})")
            st.write(f"**Agent Reasoning:** {assessment['reasoning']}")
            
            with st.expander("🔍 Detailed Agent Findings"):
                for report in assessment["agent_reports"]:
                    st.markdown(f"**{report['agent']}** — *Status: {report['status']}*")
                    for item in report["findings"]:
                        st.write(f"• {item}")
                    st.caption(f"Remediation Action: {report['recommended_action']}")
                    st.divider()

            st.subheader("⚙️ Select Remediation Strategy")
            plan_options = list(assessment["remediation_plans"].keys())
            selected_plan = st.selectbox("Execution Strategy:", plan_options)
            st.info(f"**Strategy Details:** {assessment['remediation_plans'][selected_plan]['description']}")
            
            c_btn1, c_btn2 = st.columns([2, 1])
            with c_btn1:
                execute_btn = st.button("🔧 Execute Hardening & Golden AMI Build", type="primary")
            with c_btn2:
                if st.button("🔄 Reset Scan"):
                    st.session_state.scan_started = False
                    st.session_state.hardened = False
                    st.rerun()

        # Step 2: Hardening Execution
        if execute_btn:
            st.session_state.hardened = True
            st.markdown("---")
            st.subheader("🔄 Automated Remediation & Verification Scanner")
            
            orchestrator = PipelineOrchestrator()
            with st.spinner("Executing zero-trust hardening, generating KMS keys, and building Golden AMI..."):
                result = orchestrator.run_full_pipeline(payload, selected_plan, force_failure=simulate_fail)
            
            v_col1, v_col2, v_col3 = st.columns([1, 1, 1])
            
            with v_col1:
                if result["deployment_status"] == "DEPLOYED_TO_PRODUCTION":
                    st.success(f"Status: {result['verification']['status']}")
                else:
                    st.error(f"Status: {result['verification']['status']}")
                    
                st.metric(
                    label="Verified Post-Scan Score", 
                    value=f"{result['post_score']}/100", 
                    delta=result['verification']['score_delta']
                )
                st.write(f"**Hardened AMI ID:** `{result['hardened_payload']['ami_id']}`")
                st.write(f"**Deployment State:** `{result['deployment_status']}`")

            with v_col2:
                gauge_color = "#10B981" if result["post_score"] >= 90 else "#EF4444"
                fig_post = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=result["post_score"],
                    title={'text': "Post-Hardening Score"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': gauge_color},
                        'steps': [
                            {'range': [0, 50], 'color': "#FEE2E2"},
                            {'range': [50, 80], 'color': "#FEF3C7"},
                            {'range': [80, 100], 'color': "#D1FAE5"}
                        ]
                    }
                ))
                fig_post.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig_post, use_container_width=True)

            with v_col3:
                st.subheader("📋 Golden AMI Manifest")
                st.json(result["hardened_payload"])

            st.markdown("### 🖥️ Event-Driven Orchestration Console")
            st.code("\n".join(result["logs"]), language="bash")

    with tab2:
        st.subheader(f"📊 Compliance Audit: {selected_compliance}")
        comp_pre = evaluate_compliance(payload, selected_compliance)
        
        c_col1, c_col2 = st.columns(2)
        with c_col1:
            st.markdown("### 🔴 Pre-Hardening Audit Results")
            st.write(f"**Audit Status:** `{comp_pre['status']}`")
            st.markdown("**Violations Detected:**")
            for f in comp_pre["failed"]:
                st.error(f)
        
        with c_col2:
            st.markdown("### 🟢 Post-Hardening Audit Target")
            for p in comp_pre["passed"]:
                st.success(p)