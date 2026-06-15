# AI HIPAA Access Violation Analyzer
A cybersecurity portfolio project that detects suspicious healthcare access activity and generates AI-assisted incident reports.

## Features
- Upload healthcare access log CSV
- Detect after-hours access
- Detect PHI export/download activity
- Detect unknown location access
- Detect cross-department access
- Detect repeated failed logins
- Detect mass patient record viewing
- Generate AI-assisted incident reports
- Download reports as TXT

## Tech Stack
- Python
- Streamlit
- Pandas
- OpenAI API

## To run
```
streamlit run app.py
```
Upload the csv file using the **upload** button.

## To generate an AI report
### First create a **.env** file and put
```
OPENAI_API_KEY=your_api_key_here
```
### and put your OpenAI key in the *your_api_key_here* section.

After this step the AI report will be automatically generated when uploading a CSV.

## Disclaimer
This project uses simulated data only. It does not process real patient records or real PHI.
