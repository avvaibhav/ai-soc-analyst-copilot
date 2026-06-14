import os
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

st.set_page_config(page_title="AI SOC Analyst Copilot", layout="wide")

st.title("AI-Powered SOC Analyst Copilot")
st.write(
    "Upload SIEM alerts, analyze suspicious activity, map events to MITRE ATT&CK, "
    "and generate AI-assisted incident investigation reports using a free Groq-hosted LLM."
)

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    api_key = st.sidebar.text_input("Enter Groq API Key", type="password")

client = Groq(api_key=api_key) if api_key else None

uploaded_file = st.file_uploader("Upload SIEM Alert CSV", type=["csv"])

def map_mitre(event_type):
    mitre_map = {
        "Failed Login": "T1110 - Brute Force",
        "PowerShell Execution": "T1059.001 - PowerShell",
        "Privilege Escalation": "T1068 - Exploitation for Privilege Escalation",
        "Suspicious Process": "T1204 - User Execution",
        "New Admin User": "T1098 - Account Manipulation",
        "Encoded Command": "T1027 - Obfuscated Files or Information",
        "Malware Alert": "T1204 - User Execution",
        "Ransomware Activity": "T1486 - Data Encrypted for Impact"
    }
    return mitre_map.get(event_type, "Unknown - Needs Analyst Review")

def generate_ai_report(alert_data):
    prompt = f"""
You are a senior SOC analyst and incident responder.

Analyze the following SIEM alert data and produce a professional incident investigation report.

Include:
1. Executive Summary
2. Incident Overview
3. Key Suspicious Activities
4. MITRE ATT&CK Mapping
5. Severity Assessment
6. Possible Attack Chain
7. Containment Recommendations
8. Remediation Recommendations
9. Analyst Notes
10. Final Conclusion

SIEM Alert Data:
{alert_data}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "You are an expert SOC analyst specializing in SIEM alert triage, threat hunting, incident response, and MITRE ATT&CK mapping."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3
    )

    return response.choices[0].message.content

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    required_columns = [
        "timestamp", "source_ip", "user", "host",
        "event_type", "severity", "description"
    ]

    missing_columns = [column for column in required_columns if column not in df.columns]

    if missing_columns:
        st.error(f"Missing required columns: {', '.join(missing_columns)}")
    else:
        df["MITRE Technique"] = df["event_type"].apply(map_mitre)

        st.subheader("Uploaded SIEM Alerts")
        st.dataframe(df)

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Alerts", len(df))
        col2.metric("High/Critical Alerts", len(df[df["severity"].isin(["High", "Critical"])]))
        col3.metric("Unique Hosts", df["host"].nunique())
        col4.metric("Unique Users", df["user"].nunique())

        st.subheader("Severity Distribution")
        st.bar_chart(df["severity"].value_counts())

        st.subheader("MITRE ATT&CK Mapping")
        st.dataframe(
            df[
                [
                    "timestamp",
                    "host",
                    "user",
                    "event_type",
                    "severity",
                    "MITRE Technique"
                ]
            ]
        )

        st.subheader("AI Incident Investigation")

        if st.button("Generate AI Incident Report"):
            if not client:
                st.error("Groq API key is missing.")
            else:
                with st.spinner("Generating AI incident report..."):
                    alert_text = df.to_string(index=False)
                    report = generate_ai_report(alert_text)

                st.success("AI incident report generated successfully.")
                st.markdown(report)

                st.download_button(
                    label="Download Incident Report",
                    data=report,
                    file_name="ai_incident_report.txt",
                    mime="text/plain"
                )
else:
    st.info("Upload a SIEM alert CSV file to begin investigation.")