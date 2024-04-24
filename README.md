# Azure Security Assessment Tool

The Azure Security Assessment Tool is a comprehensive solution designed to automate the scanning and evaluation of Microsoft Azure environments for potential security vulnerabilities and misconfigurations. This tool leverages the Azure CLI to collect data from various Azure resources and performs a thorough analysis to identify security risks and provide actionable insights.

## Features

- Automated scanning and data collection from multiple Azure subscriptions and resources
- Detailed assessment of security configurations and best practices
- Identification of potential security vulnerabilities and misconfigurations
- Generation of comprehensive security reports in JSON and HTML formats
- Visualizations of security findings and resource distribution
- Actionable recommendations for remediation and security improvements
- Customizable configuration file for specifying target subscriptions and resource groups
- Modular and extensible design for easy integration and customization

## Prerequisites

Before running the Azure Security Assessment Tool, ensure that you have the following prerequisites:

- Python 3.x installed on your system
- Azure CLI installed and configured with the necessary permissions to access the target Azure subscriptions and resources
- Required Python packages installed (see `requirements.txt`)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-repo/azure-security-assessment-tool.git
   ```

2. Navigate to the project directory:
   ```
   cd azure-security-assessment-tool
   ```

3. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

4. Configure the Azure CLI with your Azure credentials:
   ```
   az login
   ```

5. Update the `azure_config.yml` file with your Azure subscription and resource details (see Configuration section).

## Configuration

The `azure_config.yml` file contains the configuration settings for the Azure Security Assessment Tool. Update the file with your specific Azure environment details:

```yaml
subscriptions:
  - id: your-subscription-id
    name: your-subscription-name

resource_groups:
  - name: your-resource-group-name
    subscription_id: your-subscription-id

# Add more subscriptions and resource groups as needed
```

- `subscriptions`: A list of Azure subscriptions to assess. Provide the subscription ID and name for each subscription.
- `resource_groups`: A list of Azure resource groups to assess. Provide the resource group name and the associated subscription ID.

## Usage

To run the Azure Security Assessment Tool, follow these steps:

1. Ensure that you have completed the installation and configuration steps.

2. Execute the `main.py` script:
   ```
   python main.py
   ```

3. The tool will start scanning the specified Azure subscriptions and resources, collecting data using the Azure CLI.

4. Once the data collection and analysis are complete, the tool will generate security reports in JSON and HTML formats.

5. Review the generated reports (`azure_security_report.json` and `azure_security_report.html`) for detailed security findings, vulnerabilities, and recommendations.

## Reports

The Azure Security Assessment Tool generates two types of reports:

1. JSON Report (`azure_security_report.json`):
   - Contains the raw data of the security assessment, including aggregated resource data, security findings, vulnerabilities, and summary metrics.
   - Suitable for programmatic processing and integration with other tools or systems.

2. HTML Report (`azure_security_report.html`):
   - Provides a visually appealing and interactive representation of the security assessment results.
   - Includes summary metrics, severity distribution charts, resource type distribution, and detailed tables for security findings and vulnerabilities.
   - Ideal for sharing with stakeholders and presenting the assessment findings.
   - Offers an intuitive and user-friendly interface for navigating and exploring the security assessment results.

## Customization and Extension

The Azure Security Assessment Tool is designed to be modular and extensible, allowing for easy customization and integration with existing security workflows. The tool's codebase is structured into separate files for data fetching, data aggregation, vulnerability detection, and report generation, enabling developers to modify and extend each component according to their specific requirements.

Some potential customization and extension possibilities include:

- Adding support for additional Azure resources and services
- Implementing custom vulnerability detection rules and algorithms
- Integrating with external security tools and platforms
- Enhancing the report generation process with additional visualizations and metrics
- Developing a user-friendly web interface for interactive analysis and reporting

Developers can explore the codebase and leverage the existing classes, methods, and data structures to build upon the tool's functionality and adapt it to their unique security assessment needs.

## Contributing

Contributions to the Azure Security Assessment Tool are welcome! If you find any issues or have suggestions for improvements, please submit an issue or a pull request to the project repository. When contributing, please adhere to the following guidelines:

1. Fork the repository and create a new branch for your feature or bug fix.
2. Ensure that your code follows the project's coding style and conventions.
3. Write clear and concise commit messages and provide a detailed description of your changes.
4. Submit a pull request, explaining the purpose and scope of your contribution.
5. Be responsive to feedback and participate in the code review process.

We appreciate your contributions and collaboration in making the Azure Security Assessment Tool more robust, efficient, and valuable to the community.

## License

This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute the code in accordance with the terms and conditions of the license.

## Disclaimer

The Azure Security Assessment Tool is provided as-is and is intended to assist in identifying potential security vulnerabilities and misconfigurations in Azure environments. However, it is not a substitute for a comprehensive security assessment performed by qualified security professionals. The tool may not cover all possible security scenarios, and the accuracy of the results depends on the correctness and completeness of the retrieved data.

Users of this tool should exercise caution and review the findings carefully before taking any actions in their production environments. The authors and contributors of the Azure Security Assessment Tool shall not be held liable for any damages, losses, or security breaches arising from the use of this tool.

It is strongly recommended to regularly update the tool to the latest version and stay informed about security best practices and guidelines provided by Microsoft Azure and industry standards.

## Support and Feedback

If you encounter any issues, have questions, or want to provide feedback regarding the Azure Security Assessment Tool, please [open an issue](https://github.com/your-repo/azure-security-assessment-tool/issues) on the project repository. We value your input and strive to continuously improve the tool based on the feedback from the community.

For general discussions, ideas, and collaboration opportunities, you can also join our [community forum](https://github.com/your-repo/azure-security-assessment-tool/discussions) on GitHub.

Thank you for using the Azure Security Assessment Tool and contributing to the strengthening of Azure security posture!


Here is the full, comprehensive table containing all the CSA CCM control responses from the three meeting transcripts, with no omissions or truncations:

| CSA CCM Control | Third-Party Risk Management | Physio AWS Environment | Application Security |
|-----------------|------------------------------|------------------------|----------------------|
| AIS-01 - Application & Interface Security - Application Security | Third-party software providers are assessed on their secure software development practices, including change control, security testing, patch management, and version control. | The Physio DevOps team builds medical device software, not cloud-based applications. They use AWS for some build tools like Atlassian and Jenkins but are in the process of migrating these off AWS. | Stryker uses SonarCloud for static application security testing (SAST) of homegrown applications. Developers initiate scans through a centralized process with the SonarCloud administrator. Critical vulnerabilities must be remediated before production deployment, while lower severity issues can be addressed over time. |
| AIS-02 - Application & Interface Security - Customer Access Requirements | | | It was unclear from the discussion how access to production environments is restricted and monitored, or if there are controls to detect unauthorized/unreviewed code changes. This may require follow-up with the product team. |
| AIS-03 - Application & Interface Security - Data Integrity | | | The discussion did not cover specific controls around ensuring data integrity in applications. | 
| AIS-04 - Application & Interface Security - Data Security / Integrity | | | Black Duck is used for software composition analysis (SCA) to identify vulnerabilities in third-party components. |
| AIS-06 - Application & Interface Security - Secure Development Lifecycle | | | Stryker has a defined secure development lifecycle including threat modeling (using SD Elements), static code analysis (SonarCloud), and software composition analysis (Black Duck). Dynamic testing and API security testing are future initiatives. |
| BCR-04 - Business Continuity Management & Operational Resilience - Documentation | Stryker has a documented third-party risk management procedure that has been rolled out across the organization. | | |
| BCR-05 - Business Continuity Management & Operational Resilience - Environmental Risks | | The system is designed to allow devices to continue operating offline for a period of time if cloud connectivity is lost, reducing the immediate impact of an outage. A disaster recovery site in a separate AWS region is maintained for the new system. | |
| CCC-01 - Change Control & Configuration Management - New Development / Acquisition | Before engaging a new vendor, a third-party risk assessment is conducted including an inherent risk questionnaire to understand the scope of services and type of data involved. Applicable questionnaires are sent based on the services being provided (e.g. data privacy, cloud, software development practices). | New developers needing access to AWS or build tools like Perforce go through the central IT team for access provisioning, not through AWS IAM. | |  
| CCC-03 - Change Control & Configuration Management - Quality Testing | | | Code is promoted through dev/test/prod environments, but the details of the CI/CD process and automated quality gates at each stage were not fully clear from the discussion. |
| CCC-04 - Change Control & Configuration Management - Unauthorized Software Installations | | Administrative access to the AWS accounts is limited to only two individuals who review permissions monthly. No formal process was described for approving and deploying system changes. | |
| CCC-05 - Change Control & Configuration Management - Production Changes | For existing vendors, a change to the scope of services would trigger a new risk assessment, as Stryker assesses vendors upfront for all potential services they could provide. | The AWS environment is static with no auto-scaling or dynamic resource provisioning. There is a manual process to deploy builds from AWS to an internal FDA-approved tool. | | 
| DSI-03 - Data Security & Information Lifecycle Management - E-commerce Transactions | | | The discussion did not cover e-commerce transactions or related security controls. |
| DSI-05 - Data Security & Information Lifecycle Management - Nonproduction Data | | Some non-production build servers and source code repositories (Perforce, Git) are hosted in AWS. | |
| DSI-07 - Data Security & Information Lifecycle Management - Secure Disposal | | Processes for securely deleting data stored in EFS and S3 when no longer needed were not discussed. | |
| GRM-01 - Governance and Risk Management - Baseline Requirements | Stryker has a third-party risk management program under the cybersecurity team, with a documented governance structure and defined responsibilities. | The AWS account ownership and responsibility for hosted tools is informally understood by the team but not clearly documented from a security responsibility perspective. | Security is measured across teams using a risk score provided by the Orca tool, which rolls up to an overall organizational score. A task force works with teams to remediate vulnerabilities. |
| GRM-02 - Governance and Risk Management - Data Focus Risk Assessments | Inherent risk of a vendor engagement is assessed based on the type of service and data involved. High risk vendors are continuously monitored. | | | 
| GRM-04 - Governance and Risk Management - Management Program | The third-party risk management program involves procurement, legal, and compliance teams in an integrated process. Risks and issues identified are communicated to the vendor and tracked to closure. | | |
| GRM-06 - Governance and Risk Management - Policy | Stryker expects vendors to have documented security policies as evidence of a mature security program. Lack of policies is seen as a risk. | | |
| GRM-07 - Governance and Risk Management - Policy Enforcement | Legal is involved in defining security requirements in vendor contracts. Gaps identified during assessments are communicated to legal for enforcement. | | |
| GRM-09 - Governance and Risk Management - Risk Assessments | | | It was unclear how integrated acquired entities like Physio, AI, and Gauss are with the standard application security processes. They are included in Orca scans but may not be fully onboarded to threat modeling, SAST, etc. |
| GRM-11 - Governance and Risk Management - Reviews | High risk vendors are continuously monitored through third-party cyber risk rating services and dark web monitoring for breaches or incidents, which would trigger a reassessment. However, there is no formal annual recertification process. | | |
| HRS-07 - Human Resources - Roles / Responsibilities |The interviewee manages the cloud infrastructure as part of the Dre AI organization, but the application is owned by the Surgical Technology division, indicating a separation of duties. Specific roles and responsibilities for security were not covered. | | |
| IAM-02 - Identity & Access Management - Credential Lifecycle / Provision Management | | Access to the AWS account is controlled through a central IT team, not directly through AWS IAM. It's unclear if access reviews are performed. | |
| IAM-05 - Identity & Access Management - Segregation of Duties | | Developers do not have direct access to provision resources in AWS. Only the DevOps team has admin access. | |
| IVS-01 - Infrastructure & Virtualization Security - Audit Logging / Intrusion Detection | | AWS CloudTrail logging is believed to be enabled but the team was not certain. There is no active monitoring of logs or intrusion detection described. | |  
| IVS-06 - Infrastructure & Virtualization Security - Network Security | | EC2 instances use security groups as network controls. Most are restricted to corporate office IPs but some may be open more broadly. | |
| IVS-09 - Infrastructure & Virtualization Security - Segmentation | | The Physio environment is isolated to a separate AWS account from other groups like LifeNet. | |
| IVS-11 - Infrastructure & Virtualization Security - Security Analytics Services | | Some security agents were deployed to EC2 instances in the past year by another team for scanning purposes. No vulnerability scanning or pen testing is performed by the Physio team. | | 
| SEF-02 - Security Incident Management, E-Discovery & Cloud Forensics - Incident Management | A formal security incident response plan is not documented for the legacy Drupal system. The new system will require a runbook but it has not been written yet. | | |
| STA-01 - Supply Chain Management, Transparency and Accountability - Data Quality and Integrity | | | The discussion touched on using Black Duck for SCA, but did not go into detail on other supply chain security controls. |

In summary, the three discussions provided insights into Stryker's third-party risk management program, application security practices, and the scope of certain cloud environments. While a number of good practices were noted, such as vendor risk assessments, secure SDLC controls, and centralized vulnerability management, there are also opportunities to further mature and formalize security processes. Key themes that emerged across the transcripts include:

1. Extending security processes and tools to better cover cloud environments and acquired entities 
2. Improving documentation of security responsibilities, procedures, and system inventories
3. Implementing additional security monitoring and testing controls, e.g. for unauthorized changes, dynamic testing, APIs
4. Formalizing processes around access governance, vulnerability remediation SLAs, and vendor reassessments
