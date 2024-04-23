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
