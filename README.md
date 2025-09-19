Description:
LogRisk Analyzer is a command-line tool designed for Security Governance, Risk Management, and Compliance (GRC) purposes. It enables IT administrators, security analysts, and compliance teams to automatically scan and analyze log files from Linux and Windows systems to identify potential security and operational risks.

The tool supports:

Linux log analysis: Monitors authentication events, sudo commands, cron jobs, kernel messages, and system errors.

Windows log analysis: Supports Application, System, and Security logs to detect crashes, hangs, failed updates, unauthorized changes, and security alerts.

Key Features:

Customizable risk rules stored in JSON files for each log type.

Automatic risk assessment, assigning severity levels based on detected events.

Detailed mitigation suggestions for each detected risk.

Organized output: Results are saved in separate folders for Linux, Windows Application, Windows System, and Windows Security logs.

Command-line interface for quick scanning using intuitive commands like:

Linux: --linux

Windows Security: --w-security

Windows System: --w-system

Windows Application: --w-application

Benefits:

Streamlines risk detection and reporting from log data.

Helps maintain compliance standards by monitoring critical system events.

Provides actionable recommendations to reduce operational and security risks.
