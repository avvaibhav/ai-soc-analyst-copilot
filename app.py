import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="AI SOC Analyst Copilot",
    layout="wide"
)

st.title("🛡️ AI-Powered SOC Analyst Copilot")

uploaded_file = st.file_uploader(
    "Upload SIEM Alert CSV",
    type=["csv"]
)

def map_mitre(event_type):
    mitre_map = {
        "Failed Login": "T1110 - Brute Force",
        "PowerShell Execution": "T1059.001 - PowerShell",
        "Privilege Escalation": "T1068 - Privilege Escalation",
        "Suspicious Process": "T1204 - User Execution"
    }

    return mitre_map.get(
        event_type,
        "Unknown Technique"
    )

if uploaded_file:

    df = pd.read_csv(uploaded_file)

    df["MITRE Technique"] = df["event_type"].apply(map_mitre)

    st.subheader("Alert Data")

    st.dataframe(df)

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Alerts",
        len(df)
    )

    col2.metric(
        "High/Critical Alerts",
        len(
            df[
                df["severity"].isin(
                    ["High", "Critical"]
                )
            ]
        )
    )

    col3.metric(
        "Unique Hosts",
        df["host"].nunique()
    )

    st.subheader("Severity Distribution")

    st.bar_chart(
        df["severity"].value_counts()
    )

    st.subheader("MITRE ATT&CK Mapping")

    st.dataframe(
        df[
            [
                "host",
                "event_type",
                "severity",
                "MITRE Technique"
            ]
        ]
    )

else:
    st.info(
        "Upload sample_alerts.csv to begin analysis."
    )