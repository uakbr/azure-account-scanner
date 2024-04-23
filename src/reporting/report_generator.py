import json
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.report = {
            "timestamp": "",
            "summary": {
                "total_resources": 0,
                "total_security_findings": 0,
                "total_vulnerabilities": 0,
                "high_severity_findings": 0,
                "medium_severity_findings": 0,
                "low_severity_findings": 0,
                "high_severity_vulnerabilities": 0,
                "medium_severity_vulnerabilities": 0,
                "low_severity_vulnerabilities": 0
            },
            "aggregated_data": {},
            "security_findings": {},
            "vulnerabilities": []
        }

    def generate_report(self, aggregated_data, security_findings, vulnerabilities):
        self.report["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report["aggregated_data"] = aggregated_data
        self.report["security_findings"] = security_findings
        self.report["vulnerabilities"] = vulnerabilities

        self.generate_summary()
        self.generate_json_report()
        self.generate_html_report()

    def generate_summary(self):
        total_resources = sum(len(resources) for resources in self.report["aggregated_data"].values())
        total_security_findings = sum(len(findings) for findings in self.report["security_findings"].values() if isinstance(findings, list))
        total_security_findings += sum(len(sub_findings) for findings in self.report["security_findings"].values() if isinstance(findings, dict) for sub_findings in findings.values())
        total_vulnerabilities = len(self.report["vulnerabilities"])

        high_severity_findings = sum(1 for findings in self.report["security_findings"].values() if isinstance(findings, list) for finding in findings if finding["severity"] == "High")
        high_severity_findings += sum(1 for findings in self.report["security_findings"].values() if isinstance(findings, dict) for sub_findings in findings.values() for finding in sub_findings if finding["severity"] == "High")
        medium_severity_findings = sum(1 for findings in self.report["security_findings"].values() if isinstance(findings, list) for finding in findings if finding["severity"] == "Medium")
        medium_severity_findings += sum(1 for findings in self.report["security_findings"].values() if isinstance(findings, dict) for sub_findings in findings.values() for finding in sub_findings if finding["severity"] == "Medium")
        low_severity_findings = sum(1 for findings in self.report["security_findings"].values() if isinstance(findings, list) for finding in findings if finding["severity"] == "Low")
        low_severity_findings += sum(1 for findings in self.report["security_findings"].values() if isinstance(findings, dict) for sub_findings in findings.values() for finding in sub_findings if finding["severity"] == "Low")

        high_severity_vulnerabilities = sum(1 for vulnerability in self.report["vulnerabilities"] if vulnerability["severity"] == "High")
        medium_severity_vulnerabilities = sum(1 for vulnerability in self.report["vulnerabilities"] if vulnerability["severity"] == "Medium")
        low_severity_vulnerabilities = sum(1 for vulnerability in self.report["vulnerabilities"] if vulnerability["severity"] == "Low")

        self.report["summary"]["total_resources"] = total_resources
        self.report["summary"]["total_security_findings"] = total_security_findings
        self.report["summary"]["total_vulnerabilities"] = total_vulnerabilities
        self.report["summary"]["high_severity_findings"] = high_severity_findings
        self.report["summary"]["medium_severity_findings"] = medium_severity_findings
        self.report["summary"]["low_severity_findings"] = low_severity_findings
        self.report["summary"]["high_severity_vulnerabilities"] = high_severity_vulnerabilities
        self.report["summary"]["medium_severity_vulnerabilities"] = medium_severity_vulnerabilities
        self.report["summary"]["low_severity_vulnerabilities"] = low_severity_vulnerabilities

    def generate_json_report(self):
        json_report = json.dumps(self.report, indent=4)
        with open("azure_security_report.json", "w") as file:
            file.write(json_report)
        print("JSON report generated: azure_security_report.json")

    def generate_html_report(self):
        html_report = """
        <html>
        <head>
            <title>Azure Security Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }
                h1 {
                    color: #333;
                }
                h2 {
                    color: #666;
                    margin-top: 30px;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                }
                .severity-high {
                    color: #ff0000;
                    font-weight: bold;
                }
                .severity-medium {
                    color: #ff9900;
                    font-weight: bold;
                }
                .severity-low {
                    color: #ffcc00;
                    font-weight: bold;
                }
                .summary {
                    margin-top: 20px;
                    padding: 10px;
                    background-color: #f9f9f9;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
                .summary p {
                    margin: 5px 0;
                }
            </style>
        </head>
        <body>
            <h1>Azure Security Report</h1>
            <p>Generated on: {timestamp}</p>

            <div class="summary">
                <h2>Summary</h2>
                <p>Total Resources: {total_resources}</p>
                <p>Total Security Findings: {total_security_findings}</p>
                <p>Total Vulnerabilities: {total_vulnerabilities}</p>
                <p>High Severity Findings: {high_severity_findings}</p>
                <p>Medium Severity Findings: {medium_severity_findings}</p>
                <p>Low Severity Findings: {low_severity_findings}</p>
                <p>High Severity Vulnerabilities: {high_severity_vulnerabilities}</p>
                <p>Medium Severity Vulnerabilities: {medium_severity_vulnerabilities}</p>
                <p>Low Severity Vulnerabilities: {low_severity_vulnerabilities}</p>
            </div>

            <h2>Aggregated Data</h2>
            <pre>{aggregated_data}</pre>

            <h2>Security Findings</h2>
            {security_findings_table}

            <h2>Vulnerabilities</h2>
            {vulnerabilities_table}

        </body>
        </html>
        """

        security_findings_rows = ""
        for resource_type, findings in self.report["security_findings"].items():
            if isinstance(findings, dict):
                for sub_resource_type, sub_findings in findings.items():
                    for finding in sub_findings:
                        security_findings_rows += f"""
                        <tr>
                            <td>{resource_type.capitalize().replace("_", " ")}</td>
                            <td>{sub_resource_type.capitalize().replace("_", " ")}</td>
                            <td>{finding.get("resource_name", "")}</td>
                            <td>{finding["issue"]}</td>
                            <td class="severity-{finding['severity'].lower()}">{finding["severity"]}</td>
                        </tr>
                        """
            else:
                for finding in findings:
                    security_findings_rows += f"""
                    <tr>
                        <td>{resource_type.capitalize().replace("_", " ")}</td>
                        <td></td>
                        <td>{finding.get("resource_name", "")}</td>
                        <td>{finding["issue"]}</td>
                        <td class="severity-{finding['severity'].lower()}">{finding["severity"]}</td>
                    </tr>
                    """

        vulnerabilities_rows = ""
        for vulnerability in self.report["vulnerabilities"]:
            vulnerabilities_rows += f"""
            <tr>
                <td>{vulnerability["resource_type"]}</td>
                <td>{vulnerability.get("resource_name", "")}</td>
                <td>{vulnerability["name"]}</td>
                <td>{vulnerability["description"]}</td>
                <td class="severity-{vulnerability['severity'].lower()}">{vulnerability["severity"]}</td>
            </tr>
            """

        security_findings_table = f"""
        <table>
            <tr>
                <th>Resource Type</th>
                <th>Sub-Resource Type</th>
                <th>Resource Name</th>
                <th>Issue</th>
                <th>Severity</th>
            </tr>
            {security_findings_rows}
        </table>
        """

        vulnerabilities_table = f"""
        <table>
            <tr>
                <th>Resource Type</th>
                <th>Resource Name</th>
                <th>Vulnerability</th>
                <th>Description</th>
                <th>Severity</th>
            </tr>
            {vulnerabilities_rows}
        </table>
        """

        html_report = html_report.format(
            timestamp=self.report["timestamp"],
            total_resources=self.report["summary"]["total_resources"],
            total_security_findings=self.report["summary"]["total_security_findings"],
            total_vulnerabilities=self.report["summary"]["total_vulnerabilities"],
            high_severity_findings=self.report["summary"]["high_severity_findings"],
            medium_severity_findings=self.report["summary"]["medium_severity_findings"],
            low_severity_findings=self.report["summary"]["low_severity_findings"],
            high_severity_vulnerabilities=self.report["summary"]["high_severity_vulnerabilities"],
            medium_severity_vulnerabilities=self.report["summary"]["medium_severity_vulnerabilities"],
            low_severity_vulnerabilities=self.report["summary"]["low_severity_vulnerabilities"],
            aggregated_data=json.dumps(self.report["aggregated_data"], indent=4),
            security_findings_table=security_findings_table,
            vulnerabilities_table=vulnerabilities_table
        )

        with open("azure_security_report.html", "w") as file:
            file.write(html_report)
        print("HTML report generated: azure_security_report.html")