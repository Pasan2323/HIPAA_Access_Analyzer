import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI


# =========================
# PAGE CONFIGURATION
# =========================

st.set_page_config(
    page_title="AI HIPAA Access Violation Analyzer",
    page_icon="🏥",
    layout="wide"
)

st.title("🏥 AI HIPAA Access Violation Analyzer")

st.write(
    "Upload healthcare access logs to detect possible HIPAA access violations."
)


# =========================
# ENVIRONMENT SETUP
# =========================

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

client = None

if api_key:
    client = OpenAI(api_key=api_key)


# =========================
# REQUIRED COLUMNS
# =========================

REQUIRED_COLUMNS = [
    "timestamp",
    "user",
    "patient_id",
    "action",
    "location",
    "department",
    "patient_department",
    "status",
]


# =========================
# CSV VALIDATION
# =========================

def validate_columns(df):

    missing = []

    for column in REQUIRED_COLUMNS:
        if column not in df.columns:
            missing.append(column)

    return missing


# =========================
# DETECT VIOLATIONS
# =========================

def detect_violations(df):

    alerts = []

    try:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

        df["hour"] = df["timestamp"].dt.hour

        # ---------------------
        # After hours access
        # ---------------------

        after_hours = df[
            (df["hour"] < 6)
            | (df["hour"] > 20)
        ]

        for _, row in after_hours.iterrows():

            alerts.append({
                "user": row["user"],
                "patient_id": row["patient_id"],
                "issue": "After-hours PHI access",
                "severity": "High",
                "evidence": (
                    f"{row['user']} accessed "
                    f"patient {row['patient_id']} "
                    f"at {row['timestamp']}"
                )
            })

        # ---------------------
        # Export / Download
        # ---------------------

        export_actions = df[
            df["action"].isin(
                ["EXPORT", "DOWNLOAD"]
            )
        ]

        for _, row in export_actions.iterrows():

            alerts.append({
                "user": row["user"],
                "patient_id": row["patient_id"],
                "issue": "PHI export/download activity",
                "severity": "Critical",
                "evidence": (
                    f"{row['user']} performed "
                    f"{row['action']} on "
                    f"{row['patient_id']}"
                )
            })

        # ---------------------
        # Unknown location
        # ---------------------

        unknown_locations = df[
            df["location"] == "Unknown"
        ]

        for _, row in unknown_locations.iterrows():

            alerts.append({
                "user": row["user"],
                "patient_id": row["patient_id"],
                "issue": "Access from unknown location",
                "severity": "High",
                "evidence": (
                    f"{row['user']} accessed "
                    f"from an unknown location"
                )
            })

        # ---------------------
        # Cross department
        # ---------------------

        cross_department = df[
            df["department"]
            != df["patient_department"]
        ]

        for _, row in cross_department.iterrows():

            alerts.append({
                "user": row["user"],
                "patient_id": row["patient_id"],
                "issue": "Cross-department access",
                "severity": "Medium",
                "evidence": (
                    f"{row['user']} from "
                    f"{row['department']} "
                    f"accessed "
                    f"{row['patient_department']} "
                    f"records"
                )
            })

        # ---------------------
        # Failed logins
        # ---------------------

        failed = (
            df[df["status"] == "FAILED"]
            .groupby("user")
            .size()
            .reset_index(
                name="failed_count"
            )
        )

        for _, row in failed.iterrows():

            if row["failed_count"] >= 3:

                alerts.append({
                    "user": row["user"],
                    "patient_id": "N/A",
                    "issue": "Multiple failed logins",
                    "severity": "Medium",
                    "evidence": (
                        f"{row['user']} had "
                        f"{row['failed_count']} "
                        f"failed attempts"
                    )
                })

        # ---------------------
        # Mass viewing
        # ---------------------

        views = (
            df[df["action"] == "VIEW"]
            .groupby("user")["patient_id"]
            .nunique()
            .reset_index()
        )

        views.columns = [
            "user",
            "unique_patients"
        ]

        for _, row in views.iterrows():

            if row["unique_patients"] >= 5:

                alerts.append({
                    "user": row["user"],
                    "patient_id": "Multiple",
                    "issue": "Mass patient viewing",
                    "severity": "High",
                    "evidence": (
                        f"{row['user']} viewed "
                        f"{row['unique_patients']} "
                        f"patients"
                    )
                })

        return pd.DataFrame(alerts)

    except Exception as e:

        st.error(
            f"Analysis error: {e}"
        )

        return pd.DataFrame()


# =========================
# AI REPORT
# =========================

def generate_ai_report(alert):

    if client is None:

        return """
OpenAI API key not found.

Create a .env file.

OPENAI_API_KEY=your_key_here
"""

    prompt = f"""
Generate a professional HIPAA incident report.

User: {alert['user']}

Issue: {alert['issue']}

Severity: {alert['severity']}

Patient: {alert['patient_id']}

Evidence:
{alert['evidence']}

Provide:

1. Incident Summary

2. Why This Is Risky

3. Possible Cause

4. Recommended Response

5. Escalation Priority
"""

    try:

        response = client.chat.completions.create(

            model="gpt-4o-mini",

            messages=[

                {
                    "role": "system",
                    "content": (
                        "You are a healthcare "
                        "cybersecurity analyst."
                    )
                },

                {
                    "role": "user",
                    "content": prompt
                }
            ],

            temperature=0.3
        )

        return response.choices[0].message.content

    except Exception as e:

        return f"AI Error: {e}"


# =========================
# SIDEBAR
# =========================

st.sidebar.header("Upload Data")

uploaded_file = st.sidebar.file_uploader(
    "Upload CSV",
    type=["csv"]
)


# =========================
# MAIN APPLICATION
# =========================

if uploaded_file:

    try:

        df = pd.read_csv(uploaded_file)

    except Exception as e:

        st.error(f"Cannot read file: {e}")

        st.stop()

    missing = validate_columns(df)

    if missing:

        st.error(
            f"Missing columns: {missing}"
        )

        st.stop()

    st.subheader("Uploaded Logs")

    st.dataframe(df)

    alerts_df = detect_violations(df)

    st.subheader("Dashboard")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Logs",
        len(df)
    )

    col2.metric(
        "Alerts",
        len(alerts_df)
    )

    critical = 0

    if not alerts_df.empty:

        critical = len(
            alerts_df[
                alerts_df["severity"]
                == "Critical"
            ]
        )

    col3.metric(
        "Critical",
        critical
    )

    st.subheader(
        "Detected Alerts"
    )

    if alerts_df.empty:

        st.success(
            "No suspicious activity detected."
        )

    else:

        severity = st.selectbox(

            "Filter severity",

            [
                "All",
                "Critical",
                "High",
                "Medium"
            ]
        )

        filtered = alerts_df

        if severity != "All":

            filtered = alerts_df[
                alerts_df["severity"]
                == severity
            ]

        st.dataframe(filtered)

        selected = st.selectbox(

            "Generate AI report",

            filtered.index
        )

        alert = filtered.loc[selected]

        if st.button(
            "Generate Report"
        ):

            with st.spinner(
                "Generating..."
            ):

                report = generate_ai_report(
                    alert
                )

            st.text_area(

                "Incident Report",

                report,

                height=400
            )

            st.download_button(

                "Download Report",

                report,

                file_name="hipaa_report.txt",

                mime="text/plain"
            )

else:

    st.info(
        "Upload a CSV file to begin."
    )