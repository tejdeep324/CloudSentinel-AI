import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go

from agents.supervisor import SupervisorAgent
from core.scoring import calculate_risk_score
from core.compliance import evaluate_compliance, COMPLIANCE_STANDARDS
from core.pipeline_orchestrator import PipelineOrchestrator
from core.database_service import AuditDatabaseService
from core.report_generator import ComplianceReportGenerator
from tools.cost_calculator_tool import FinOpsCostCalculatorTool

st.set_page_config(page_title="CloudSentinel AI", page_icon="🛡️", layout="wide")

# Persistent singletons
db_service = AuditDatabaseService()
supervisor = SupervisorAgent()
orchestrator = PipelineOrchestrator()

# Session State Initialization
if "scan_started" not in st.session_state:
    st.session_state.scan_started = False
if "pipeline_result" not in st.session_state:
    st.session_state.pipeline_result = None

st.title("🛡️ CloudSentinel AI")
st.caption("Enterprise Autonomous Multi-Agent Workload Security & Zero-Trust AMI Hardening Platform")
st.markdown("---")

# Sidebar Controls
st.sidebar.header("⚙️ Governance & Settings")
selected_compliance = st.sidebar.selectbox("Target Compliance Framework:", list(COMPLIANCE_STANDARDS.keys()))

scenario = st.sidebar.selectbox(
    "Workload Telemetry Ingestion:",
    [
        "Scenario 1: Critical Legacy Server (Default)",
        "Scenario 2: Unencrypted Production Database",
        "Scenario 3: Web App (Partially Hardened)",
        "Scenario 4: Custom JSON Upload"
    ]
)

# Multi-Scenario Payload Ingestion
payload = None
if scenario == "Scenario 4: Custom JSON Upload":
    uploaded_file = st.sidebar.file_uploader("Upload Telemetry JSON", type=["json"])
    if uploaded_file is not None:
        try:
            payload = json.load(uploaded_file)
        except Exception:
            st.sidebar.error("Invalid JSON file uploaded. Falling back to default.")
            with open("data/sample_payload.json", "r") as f:
                payload = json.load(f)
    else:
        with open("data/sample_payload.json", "r") as f:
            payload = json.load(f)
elif scenario == "Scenario 2: Unencrypted Production Database":
    with open("data/database_payload.json", "r") as f:
        payload = json.load(f)
elif scenario == "Scenario 3: Web App (Partially Hardened)":
    with open("data/webapp_payload.json", "r") as f:
        payload = json.load(f)
else:
    with open("data/sample_payload.json", "r") as f:
        payload = json.load(f)

st.sidebar.markdown("---")
st.sidebar.subheader("💰 Resource Cost Optimization")
cost_data = FinOpsCostCalculatorTool.calculate_rightsizing_projection("m5.large")
st.sidebar.metric(
    label="Projected Monthly Savings", 
    value=f"${cost_data['monthly_savings']}/mo", 
    delta=f"-{cost_data['percentage_savings']}% Compute Cost"
)

st.sidebar.markdown("---")
simulate_fail = st.sidebar.checkbox("Simulate Hardening Failure (Test Rollback)")

# ----------------- VIEW 1: PRE-INGESTION SCREEN -----------------
if not st.session_state.scan_started:
    st.info("Workload detected in isolated Migration Quarantine VPC Subnet. Ready for autonomous multi-agent assessment.")
    st.json(payload)
    
    if st.button("🚀 Start Ingestion & Autonomous Scan", type="primary"):
        st.session_state.scan_started = True
        st.rerun()

# ----------------- VIEW 2: ACTIVE DASHBOARD -----------------
else:
    tab1, tab2, tab3 = st.tabs([
        "🚀 Real-Time Multi-Agent Pipeline", 
        "📋 Compliance & Cost Analysis",
        "🗄️ Historical Audit Logs"
    ])

    with tab1:
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("📥 Quarantined Workload Telemetry")
            st.json(payload)
            
            pre_eval = calculate_risk_score(payload)
            pre_score = pre_eval["total_score"]
            
            gauge_pre_color = "#EF4444" if pre_score < 70 else "#F59E0B"
            fig_pre = go.Figure(go.Indicator(
                mode="gauge+number",
                value=pre_score,
                title={'text': "Pre-Scan Risk Score"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': gauge_pre_color},
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
            st.subheader("🤖 Autonomous Multi-Agent Blackboard")
            blackboard = supervisor.coordinate_assessment(payload, target_compliance=selected_compliance)
            
            if blackboard.supervisor_verdict == "REMEDIATION_REQUIRED":
                st.error(f"⚠️ **Supervisor AI Verdict:** {blackboard.supervisor_verdict}")
            else:
                st.success(f"✅ **Supervisor AI Verdict:** {blackboard.supervisor_verdict}")
                
            st.write(f"**Consensus Reasoning:** {blackboard.supervisor_reasoning}")
            
            with st.expander("🔍 Sub-Agent Specific Findings (XAI Trace)", expanded=True):
                for f in blackboard.findings:
                    badge_color = "🔴" if f.severity == "CRITICAL" else ("🟠" if f.severity == "HIGH" else "🟡")
                    st.markdown(f"{badge_color} **[{f.agent_name}]** `{f.title}` — *Severity: {f.severity}*")
                    st.write(f"• {f.description}")
                    st.caption(f"Action: `{f.remediation_action}` | Domain: {f.domain}")
                    st.divider()

            st.subheader("⚙️ Select Remediation Strategy")
            plan_options = list(blackboard.remediation_plans.keys())
            selected_plan = st.selectbox("Execution Strategy:", plan_options)
            chosen_plan = blackboard.remediation_plans[selected_plan]
            
            st.info(f"**Description:** {chosen_plan.description}\n\n**Trade-off Note:** {chosen_plan.trade_off_notes}")
            
            c_btn1, c_btn2 = st.columns([2, 1])
            with c_btn1:
                if st.button("🔧 Execute Hardening & Golden AMI Build", type="primary"):
                    with st.spinner("Executing zero-trust hardening, generating KMS keys, and building Golden AMI..."):
                        res = orchestrator.run_full_pipeline(payload, selected_plan, force_failure=simulate_fail)
                        st.session_state.pipeline_result = res
                        
                        # Persist to persistent SQLite DB
                        db_service.record_migration_event(
                            instance_id=payload.get("instance_id", "i-workload-node"),
                            pre_score=res["pre_score"],
                            post_score=res["post_score"],
                            compliance=selected_compliance,
                            status=res["deployment_status"],
                            manifest=res["hardened_payload"]
                        )
                        st.rerun()

            with c_btn2:
                if st.button("🔄 Reset Scan"):
                    st.session_state.scan_started = False
                    st.session_state.pipeline_result = None
                    st.rerun()

        # Hardening Results Section
        if st.session_state.pipeline_result is not None:
            res = st.session_state.pipeline_result
            st.markdown("---")
            st.subheader("🔄 Automated Remediation & Verification Scanner")
            
            v_col1, v_col2, v_col3 = st.columns([1, 1, 1])
            
            with v_col1:
                if res["deployment_status"] == "DEPLOYED_TO_PRODUCTION":
                    st.success(f"Status: {res['verification']['status']}")
                else:
                    st.error(f"Status: {res['verification']['status']}")
                    
                st.metric(
                    label="Verified Post-Scan Score", 
                    value=f"{res['post_score']}/100", 
                    delta=res['verification']['score_delta']
                )
                st.write(f"**Hardened AMI ID:** `{res['hardened_payload']['ami_id']}`")
                st.write(f"**Deployment State:** `{res['deployment_status']}`")

            with v_col2:
                gauge_color = "#10B981" if res["post_score"] >= 90 else "#EF4444"
                fig_post = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=res["post_score"],
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
                st.json(res["hardened_payload"])

            st.markdown("### 🖥️ Real-Time Agent Execution Console")
            combined_logs = blackboard.execution_trace + ["--- HARDENING EXECUTION ---"] + res["logs"]
            st.code("\n".join(combined_logs), language="bash")

            # Downloadable Audit Reports
            st.markdown("### 📥 Compliance Audit Export")
            exp_col1, exp_col2 = st.columns(2)

            csv_report = ComplianceReportGenerator.generate_csv_summary(res, selected_compliance)
            json_manifest = ComplianceReportGenerator.generate_json_manifest(res, selected_compliance)

            with exp_col1:
                st.download_button(
                    label="📄 Download Security Audit Summary (.CSV)",
                    data=csv_report,
                    file_name=f"CloudSentinel_Audit_{res['hardened_payload']['ami_id']}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

            with exp_col2:
                st.download_button(
                    label="📦 Download Full Compliance Manifest (.JSON)",
                    data=json_manifest,
                    file_name=f"CloudSentinel_Manifest_{res['hardened_payload']['ami_id']}.json",
                    mime="application/json",
                    use_container_width=True
                )

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
                
        st.markdown("---")
        st.subheader("💡 Compute Right-Sizing Analysis")
        st.write(f"Telemetry detected that the instance is provisioned with an idle compute profile (`{cost_data['current_instance']}`).")
        st.info(f"**Recommendation:** Right-size to `{cost_data['recommended_instance']}` during deployment to save **${cost_data['monthly_savings']}/month** (~{cost_data['percentage_savings']}% cost reduction).")

    with tab3:
        st.subheader("🗄️ Migration Audit History & Governance Logs")
        history = db_service.get_historical_logs()
        if len(history) > 0:
            df = pd.DataFrame(history)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No historical events recorded yet. Run a hardening pipeline to populate logs.")