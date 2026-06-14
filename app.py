import os
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

st.set_page_config(page_title="AI SOC Analyst Copilot", layout="wide")

st.title("AI-Powered SOC Analyst Copilot")
st.write(
    "Upload any CSV file. The app will detect security-relevant fields, normalize alerts where possible, "
    "map events to MITRE ATT&CK, and generate an AI-assisted SOC investigation report."
)

def get_groq_api_key():
    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        try:
            api_key = st.secrets["GROQ_API_KEY"]
        except Exception:
            api_key = None

    return api_key

api_key = get_groq_api_key()
client = Groq(api_key=api_key) if api_key else None

uploaded_file = st.file_uploader("Upload Any CSV File", type=["csv"])

def find_column(df, possible_names):
    columns_lower = {col.lower(): col for col in df.columns}

    for name in possible_names:
        if name.lower() in columns_lower:
            return columns_lower[name.lower()]

    return None

def map_mitre(event_type):
    event_type = str(event_type).lower()

    if "failed" in event_type or "brute" in event_type or "login" in event_type:
        return "T1110 - Brute Force"

    if "powershell" in event_type:
        return "T1059.001 - PowerShell"

    if "privilege" in event_type or "admin" in event_type:
        return "T1068 - Exploitation for Privilege Escalation"

    if "rundll32" in event_type or "suspicious process" in event_type:
        return "T1204 - User Execution"

    if "ransomware" in event_type or "encryption" in event_type:
        return "T1486 - Data Encrypted for Impact"

    if "malware" in event_type:
        return "T1204 - User Execution"

    if "encoded" in event_type or "obfuscated" in event_type:
        return "T1027 - Obfuscated Files or Information"

    return "Unknown - Needs Analyst Review"

def normalize_csv(df):
    timestamp_col = find_column(
        df,
        ["timestamp", "time", "TimeGenerated", "TimeCreated", "_time", "date"]
    )

    source_ip_col = find_column(
        df,
        ["source_ip", "src_ip", "SourceIP", "ClientIP", "IpAddress", "ip"]
    )

    user_col = find_column(
        df,
        ["user", "username", "Account", "AccountName", "UserName", "SubjectUserName"]
    )

    host_col = find_column(
        df,
        ["host", "hostname", "Computer", "ComputerName", "DeviceName", "machine"]
    )

    event_col = find_column(
        df,
        ["event_type", "AlertName", "EventType", "EventID", "ProcessName", "Activity", "Operation"]
    )

    severity_col = find_column(
        df,
        ["severity", "Severity", "level", "risk", "priority"]
    )

    description_col = find_column(
        df,
        ["description", "Message", "event", "CommandLine", "Details", "AlertDescription"]
    )

    normalized_df = pd.DataFrame()

    normalized_df["timestamp"] = df[timestamp_col] if timestamp_col else "Unknown"
    normalized_df["source_ip"] = df[source_ip_col] if source_ip_col else "Unknown"
    normalized_df["user"] = df[user_col] if user_col else "Unknown"
    normalized_df["host"] = df[host_col] if host_col else "Unknown"
    normalized_df["event_type"] = df[event_col] if event_col else "Unknown Event"
    normalized_df["severity"] = df[severity_col] if severity_col else "Medium"
    normalized_df["description"] = df[description_col] if description_col else df.astype(str).agg(" | ".join, axis=1)

    normalized_df["MITRE Technique"] = normalized_df["event_type"].apply(map_mitre)

    return normalized_df

def generate_ai_report(original_data, normalized_data):
    prompt = f"""
You are a senior SOC analyst and incident responder.

Analyze the following CSV security/log data. The data may come from SIEM, Splunk, Microsoft Sentinel, Sysmon, Windows Event Logs, EDR alerts, firewall logs, IAM logs, or a generic CSV export.

Your task is to produce a professional SOC investigation report.

Include:
1. Executive Summary
2. Data Source Understanding
3. Key Suspicious Activities
4. High-Risk Events
5. MITRE ATT&CK Mapping
6. Severity Assessment
7. Possible Attack Chain
8. Threat Hunting Observations
9. Containment Recommendations
10. Remediation Recommendations
11. Analyst Notes
12. Final Conclusion

Original CSV Data Preview:
{original_data}

Normalized SOC View:
{normalized_data}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "You are an expert SOC analyst specializing in SIEM alert triage, threat hunting, incident response, MITRE ATT&CK mapping, and security log analysis.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content

if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Could not read CSV file: {e}")
        st.stop()

    st.subheader("Original Uploaded CSV")
    st.dataframe(df)

    if df.empty:
        st.error("Uploaded CSV is empty.")
        st.stop()

    normalized_df = normalize_csv(df)

    st.subheader("Normalized SOC Alert View")
    st.dataframe(normalized_df)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Rows", len(df))
    col2.metric("Detected Hosts", normalized_df["host"].nunique())
    col3.metric("Detected Users", normalized_df["user"].nunique())
    col4.metric(
        "High/Critical Events",
        len(normalized_df[normalized_df["severity"].astype(str).isin(["High", "Critical"])]),
    )

    st.subheader("Severity Distribution")
    st.bar_chart(normalized_df["severity"].astype(str).value_counts())

    st.subheader("MITRE ATT&CK Mapping")
    st.dataframe(
        normalized_df[
            [
                "timestamp",
                "host",
                "user",
                "event_type",
                "severity",
                "MITRE Technique",
            ]
        ]
    )

    st.subheader("AI Incident Investigation")

    if st.button("Generate AI Incident Report"):
        if not client:
            st.error("Groq API key is missing. Add it in .env locally or Streamlit Secrets online.")
        else:
            with st.spinner("Generating AI incident report..."):
                original_preview = df.head(25).to_string(index=False)
                normalized_preview = normalized_df.head(25).to_string(index=False)
                report = generate_ai_report(original_preview, normalized_preview)

            st.success("AI incident report generated successfully.")
            st.markdown(report)

            st.download_button(
                label="Download Incident Report",
                data=report,
                file_name="ai_incident_report.txt",
                mime="text/plain",
            )
else:
    st.info("Upload any CSV file to begin investigation.")