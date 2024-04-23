class DataAggregator:
    def __init__(self):
        self.aggregated_data = {
            "virtual_machines": [],
            "storage_accounts": [],
            "network_interfaces": [],
            "network_security_groups": [],
            "public_ip_addresses": [],
            "virtual_networks": [],
            "network_watchers": [],
            "load_balancers": [],
            "application_gateways": [],
            "azure_firewalls": [],
            "azure_active_directory": {
                "users": [],
                "groups": [],
                "role_assignments": [],
                "service_principals": [],
                "app_registrations": [],
                "conditional_access_policies": [],
                "identity_providers": [],
                "user_settings": [],
                "audit_logs": [],
                "sign_in_logs": []
            },
            "azure_resource_graph": [],
            "azure_security_center": {
                "security_policies": [],
                "security_recommendations": [],
                "security_alerts": [],
                "compliance_results": [],
                "regulatory_compliance_standards": [],
                "secure_scores": [],
                "automation_settings": []
            },
            "azure_monitor": {
                "metrics": [],
                "diagnostic_settings": [],
                "log_profiles": [],
                "action_groups": [],
                "autoscale_settings": [],
                "alert_rules": [],
                "app_insights_components": [],
                "log_analytics_workspaces": []
            }
        }
        self.security_findings = {
            "virtual_machines": [],
            "storage_accounts": [],
            "network_interfaces": [],
            "network_security_groups": [],
            "public_ip_addresses": [],
            "virtual_networks": [],
            "network_watchers": [],
            "load_balancers": [],
            "application_gateways": [],
            "azure_firewalls": [],
            "azure_active_directory": {
                "users": [],
                "groups": [],
                "role_assignments": [],
                "service_principals": [],
                "app_registrations": [],
                "conditional_access_policies": [],
                "identity_providers": [],
                "user_settings": [],
                "audit_logs": [],
                "sign_in_logs": []
            },
            "azure_resource_graph": [],
            "azure_security_center": {
                "security_policies": [],
                "security_recommendations": [],
                "security_alerts": [],
                "compliance_results": [],
                "regulatory_compliance_standards": [],
                "secure_scores": [],
                "automation_settings": []
            },
            "azure_monitor": {
                "metrics": [],
                "diagnostic_settings": [],
                "log_profiles": [],
                "action_groups": [],
                "autoscale_settings": [],
                "alert_rules": [],
                "app_insights_components": [],
                "log_analytics_workspaces": []
            }
        }

    def assess_virtual_machine_security(self, vm_data):
        security_findings = []

        # Check for public IP addresses
        for ip_config in vm_data.get("ipAddresses", []):
            if ip_config.get("publicIpAddress"):
                finding = {
                    "resource_type": "Virtual Machine",
                    "resource_name": vm_data["name"],
                    "issue": "Virtual machine has a public IP address",
                    "severity": "High"
                }
                security_findings.append(finding)

        # Check for open management ports
        for ip_config in vm_data.get("ipAddresses", []):
            if ip_config.get("publicIpAddress"):
                # Check for open RDP port (3389)
                if any(rule for rule in vm_data.get("networkSecurityGroup", {}).get("securityRules", [])
                       if rule.get("destinationPortRange") == "3389" and rule.get("access") == "Allow"):
                    finding = {
                        "resource_type": "Virtual Machine",
                        "resource_name": vm_data["name"],
                        "issue": "Virtual machine has RDP port (3389) open to the public",
                        "severity": "High"
                    }
                    security_findings.append(finding)
                # Check for open SSH port (22)
                if any(rule for rule in vm_data.get("networkSecurityGroup", {}).get("securityRules", [])
                       if rule.get("destinationPortRange") == "22" and rule.get("access") == "Allow"):
                    finding = {
                        "resource_type": "Virtual Machine",
                        "resource_name": vm_data["name"],
                        "issue": "Virtual machine has SSH port (22) open to the public",
                        "severity": "High"
                    }
                    security_findings.append(finding)

        # Check for missing disk encryption
        if not vm_data.get("disks", []) or not all(disk.get("encryptionSettings") for disk in vm_data["disks"]):
            finding = {
                "resource_type": "Virtual Machine",
                "resource_name": vm_data["name"],
                "issue": "Virtual machine disks are not encrypted",
                "severity": "Medium"
            }
            security_findings.append(finding)

        # Check for missing endpoint protection
        if not vm_data.get("extensions", []) or not any(ext.get("type") == "MicrosoftMonitoringAgent" for ext in vm_data["extensions"]):
            finding = {
                "resource_type": "Virtual Machine",
                "resource_name": vm_data["name"],
                "issue": "Virtual machine is missing endpoint protection",
                "severity": "Medium"
            }
            security_findings.append(finding)

        return security_findings

    def assess_storage_account_security(self, storage_account_data):
        security_findings = []

        # Check for public blob containers
        if storage_account_data.get("allowBlobPublicAccess"):
            finding = {
                "resource_type": "Storage Account",
                "resource_name": storage_account_data["name"],
                "issue": "Storage account allows public access to blob containers",
                "severity": "High"
            }
            security_findings.append(finding)

        # Check for missing HTTPS traffic enforcement
        if storage_account_data.get("supportsHttpsTrafficOnly") is False:
            finding = {
                "resource_type": "Storage Account",
                "resource_name": storage_account_data["name"],
                "issue": "Storage account does not enforce HTTPS traffic",
                "severity": "Medium"
            }
            security_findings.append(finding)

        # Check for missing encryption for data at rest
        if storage_account_data.get("encryption", {}).get("keySource") != "Microsoft.Keyvault":
            finding = {
                "resource_type": "Storage Account",
                "resource_name": storage_account_data["name"],
                "issue": "Storage account is not encrypted with customer-managed keys",
                "severity": "Low"
            }
            security_findings.append(finding)

        return security_findings

    def assess_network_security_group_security(self, nsg_data):
        security_findings = []

        # Check for overly permissive inbound rules
        for rule in nsg_data.get("securityRules", []):
            if rule.get("access") == "Allow" and rule.get("direction") == "Inbound" and (
                    rule.get("sourceAddressPrefix") == "*" or rule.get("sourceAddressPrefix") == "Internet"):
                finding = {
                    "resource_type": "Network Security Group",
                    "resource_name": nsg_data["name"],
                    "issue": f"Network security group has an overly permissive inbound rule: {rule['name']}",
                    "severity": "High"
                }
                security_findings.append(finding)

        # Check for unrestricted outbound rules
        for rule in nsg_data.get("securityRules", []):
            if rule.get("access") == "Allow" and rule.get("direction") == "Outbound" and (
                    rule.get("destinationAddressPrefix") == "*" or rule.get("destinationAddressPrefix") == "Internet"):
                finding = {
                    "resource_type": "Network Security Group",
                    "resource_name": nsg_data["name"],
                    "issue": f"Network security group has an unrestricted outbound rule: {rule['name']}",
                    "severity": "Medium"
                }
                security_findings.append(finding)

        return security_findings

    def assess_public_ip_address_security(self, public_ip_data):
        security_findings = []

        # Check for public IP addresses not associated with a network security group
        if not public_ip_data.get("networkSecurityGroup"):
            finding = {
                "resource_type": "Public IP Address",
                "resource_name": public_ip_data["name"],
                "issue": "Public IP address is not associated with a network security group",
                "severity": "High"
            }
            security_findings.append(finding)

        return security_findings

    def assess_virtual_network_security(self, vnet_data):
        security_findings = []

        # Check for virtual networks with broad address spaces
        for address_prefix in vnet_data.get("addressSpace", {}).get("addressPrefixes", []):
            if address_prefix.startswith("10.0.0.0") or address_prefix.startswith("172.16.0.0") or address_prefix.startswith("192.168.0.0"):
                finding = {
                    "resource_type": "Virtual Network",
                    "resource_name": vnet_data["name"],
                    "issue": f"Virtual network has a broad address space: {address_prefix}",
                    "severity": "Low"
                }
                security_findings.append(finding)

        # Check for virtual networks with unrestricted peering
        for peering in vnet_data.get("virtualNetworkPeerings", []):
            if peering.get("allowVirtualNetworkAccess") and peering.get("allowForwardedTraffic") and peering.get("allowGatewayTransit"):
                finding = {
                    "resource_type": "Virtual Network",
                    "resource_name": vnet_data["name"],
                    "issue": f"Virtual network has unrestricted peering: {peering['name']}",
                    "severity": "Medium"
                }
                security_findings.append(finding)

        return security_findings

    def assess_azure_active_directory_security(self, aad_data):
        security_findings = {
            "users": [],
            "groups": [],
            "role_assignments": [],
            "service_principals": [],
            "app_registrations": [],
            "conditional_access_policies": [],
            "identity_providers": [],
            "user_settings": [],
            "audit_logs": [],
            "sign_in_logs": []
        }

        # Assess user security
        for user in aad_data["users"]:
            if not user.get("accountEnabled"):
                finding = {
                    "resource_type": "Azure Active Directory User",
                    "resource_name": user["userPrincipalName"],
                    "issue": "User account is disabled",
                    "severity": "Low"
                }
                security_findings["users"].append(finding)

            if user.get("userType") == "Guest":
                finding = {
                    "resource_type": "Azure Active Directory User",
                    "resource_name": user["userPrincipalName"],
                    "issue": "User is a guest account",
                    "severity": "Medium"
                }
                security_findings["users"].append(finding)

        # Assess group security
        for group in aad_data["groups"]:
            if group.get("securityEnabled") is False:
                finding = {
                    "resource_type": "Azure Active Directory Group",
                    "resource_name": group["displayName"],
                    "issue": "Group is not security-enabled",
                    "severity": "Low"
                }
                security_findings["groups"].append(finding)

        # Assess role assignment security
        for assignment in aad_data["role_assignments"]:
            if assignment["roleDefinitionName"] == "Owner":
                finding = {
                    "resource_type": "Azure Active Directory Role Assignment",
                    "resource_name": assignment["principalName"],
                    "issue": "User or group has Owner role assignment",
                    "severity": "High"
                }
                security_findings["role_assignments"].append(finding)

        # Assess service principal security
        for sp in aad_data["service_principals"]:
            if sp.get("accountEnabled") is False:
                finding = {
                    "resource_type": "Azure Active Directory Service Principal",
                    "resource_name": sp["displayName"],
                    "issue": "Service principal is disabled",
                    "severity": "Low"
                }
                security_findings["service_principals"].append(finding)

        # Assess app registration security
        for app in aad_data["app_registrations"]:
            if app.get("publisherDomain") != "microsoft.com":
                finding = {
                    "resource_type": "Azure Active Directory App Registration",
                    "resource_name": app["displayName"],
                    "issue": "App registration is not published by Microsoft",
                    "severity": "Medium"
                }
                security_findings["app_registrations"].append(finding)

        # Assess conditional access policy security
        for policy in aad_data["conditional_access_policies"]:
            if policy.get("state") != "enabled":
                finding = {
                    "resource_type": "Azure Active Directory Conditional Access Policy",
                    "resource_name": policy["displayName"],
                    "issue": "Conditional access policy is not enabled",
                    "severity": "Medium"
                }
                security_findings["conditional_access_policies"].append(finding)

        return security_findings

    def assess_azure_security_center_security(self, asc_data):
        security_findings = {
            "security_policies": [],
            "security_recommendations": [],
            "security_alerts": [],
            "compliance_results": [],
            "regulatory_compliance_standards": [],
            "secure_scores": [],
            "automation_settings": []
        }

        # Assess security policy security
        for policy in asc_data["security_policies"]:
            if policy.get("state") != "Enabled":
                finding = {
                    "resource_type": "Azure Security Center Security Policy",
                    "resource_name": policy["name"],
                    "issue": "Security policy is not enabled",
                    "severity": "High"
                }
                security_findings["security_policies"].append(finding)

        # Assess security recommendation security
        for recommendation in asc_data["security_recommendations"]:
            if recommendation.get("status") != "Healthy":
                finding = {
                    "resource_type": "Azure Security Center Security Recommendation",
                    "resource_name": recommendation["name"],
                    "issue": f"Security recommendation is not healthy: {recommendation['status']}",
                    "severity": "Medium"
                }
                security_findings["security_recommendations"].append(finding)

        # Assess security alert security
        for alert in asc_data["security_alerts"]:
            if alert.get("status") != "Resolved":
                finding = {
                    "resource_type": "Azure Security Center Security Alert",
                    "resource_name": alert["name"],
                    "issue": f"Security alert is not resolved: {alert['status']}",
                    "severity": "High"
                }
                security_findings["security_alerts"].append(finding)

        # Assess compliance result security
        for result in asc_data["compliance_results"]:
            if result.get("resourceStatus") != "Healthy":
                finding = {
                    "resource_type": "Azure Security Center Compliance Result",
                    "resource_name": result["name"],
                    "issue": f"Compliance result is not healthy: {result['resourceStatus']}",
                    "severity": "Medium"
                }
                security_findings["compliance_results"].append(finding)

# Assess regulatory compliance standard security
    for standard in asc_data["regulatory_compliance_standards"]:
        if standard.get("state") != "Passed":
            finding = {
                "resource_type": "Azure Security Center Regulatory Compliance Standard",
                "resource_name": standard["name"],
                "issue": f"Regulatory compliance standard is not passed: {standard['state']}",
                "severity": "High"
            }
            security_findings["regulatory_compliance_standards"].append(finding)

    # Assess secure score security
    for score in asc_data["secure_scores"]:
        if score.get("score", {}).get("current") < score.get("score", {}).get("max"):
            finding = {
                "resource_type": "Azure Security Center Secure Score",
                "resource_name": score["name"],
                "issue": f"Secure score is not at maximum: {score['score']['current']} out of {score['score']['max']}",
                "severity": "Low"
            }
            security_findings["secure_scores"].append(finding)

    # Assess automation setting security
    for setting in asc_data["automation_settings"]:
        if setting.get("enabled") is False:
            finding = {
                "resource_type": "Azure Security Center Automation Setting",
                "resource_name": setting["name"],
                "issue": "Automation setting is not enabled",
                "severity": "Medium"
            }
            security_findings["automation_settings"].append(finding)


    def assess_azure_monitor_security(self, monitor_data):
        security_findings = {
            "metrics": [],
            "diagnostic_settings": [],
            "log_profiles": [],
            "action_groups": [],
            "autoscale_settings": [],
            "alert_rules": [],
            "app_insights_components": [],
            "log_analytics_workspaces": []
        }

        # Assess metric security
        for metric in monitor_data["metrics"]:
            if not metric.get("enabled"):
                finding = {
                    "resource_type": "Azure Monitor Metric",
                    "resource_name": metric["name"],
                    "issue": "Metric is not enabled",
                    "severity": "Low"
                }
                security_findings["metrics"].append(finding)

        # Assess diagnostic setting security
        for setting in monitor_data["diagnostic_settings"]:
            if not setting.get("storageAccountId") and not setting.get("workspaceId"):
                finding = {
                    "resource_type": "Azure Monitor Diagnostic Setting",
                    "resource_name": setting["name"],
                    "issue": "Diagnostic setting does not have a storage account or workspace configured",
                    "severity": "Medium"
                }
                security_findings["diagnostic_settings"].append(finding)

        # Assess log profile security
        for profile in monitor_data["log_profiles"]:
            if not profile.get("retentionPolicy", {}).get("enabled"):
                finding = {
                    "resource_type": "Azure Monitor Log Profile",
                    "resource_name": profile["name"],
                    "issue": "Log profile does not have retention policy enabled",
                    "severity": "Medium"
                }
                security_findings["log_profiles"].append(finding)

        # Assess action group security
        for group in monitor_data["action_groups"]:
            if not group.get("enabled"):
                finding = {
                    "resource_type": "Azure Monitor Action Group",
                    "resource_name": group["name"],
                    "issue": "Action group is not enabled",
                    "severity": "Medium"
                }
                security_findings["action_groups"].append(finding)

        # Assess autoscale setting security
        for setting in monitor_data["autoscale_settings"]:
            if not setting.get("enabled"):
                finding = {
                    "resource_type": "Azure Monitor Autoscale Setting",
                    "resource_name": setting["name"],
                    "issue": "Autoscale setting is not enabled",
                    "severity": "Low"
                }
                security_findings["autoscale_settings"].append(finding)

        # Assess alert rule security
        for rule in monitor_data["alert_rules"]:
            if rule.get("enabled") is False:
                finding = {
                    "resource_type": "Azure Monitor Alert Rule",
                    "resource_name": rule["name"],
                    "issue": "Alert rule is not enabled",
                    "severity": "High"
                }
                security_findings["alert_rules"].append(finding)

        # Assess Application Insights component security
        for component in monitor_data["app_insights_components"]:
            if component.get("publicNetworkAccessForIngestion") != "Disabled" or component.get("publicNetworkAccessForQuery") != "Disabled":
                finding = {
                    "resource_type": "Azure Monitor Application Insights Component",
                    "resource_name": component["name"],
                    "issue": "Application Insights component has public network access enabled",
                    "severity": "Medium"
                }
                security_findings["app_insights_components"].append(finding)

        # Assess Log Analytics workspace security
        for workspace in monitor_data["log_analytics_workspaces"]:
            if workspace.get("retentionInDays") < 30:
                finding = {
                    "resource_type": "Azure Monitor Log Analytics Workspace",
                    "resource_name": workspace["name"],
                    "issue": "Log Analytics workspace has retention period less than 30 days",
                    "severity": "Medium"
                }
                security_findings["log_analytics_workspaces"].append(finding)

        return security_findings

def aggregate_virtual_machine_data(self, fetched_data):
    self.aggregated_data["virtual_machines"].extend(fetched_data)
    for vm_data in fetched_data:
        vm_findings = self.assess_virtual_machine_security(vm_data)
        self.security_findings["virtual_machines"].extend(vm_findings)

def aggregate_storage_account_data(self, fetched_data):
    self.aggregated_data["storage_accounts"].extend(fetched_data)
    for storage_account_data in fetched_data:
        storage_account_findings = self.assess_storage_account_security(storage_account_data)
        self.security_findings["storage_accounts"].extend(storage_account_findings)

def aggregate_network_interface_data(self, fetched_data):
    self.aggregated_data["network_interfaces"].extend(fetched_data)

def aggregate_network_security_group_data(self, fetched_data):
    self.aggregated_data["network_security_groups"].extend(fetched_data)
    for nsg_data in fetched_data:
        nsg_findings = self.assess_network_security_group_security(nsg_data)
        self.security_findings["network_security_groups"].extend(nsg_findings)

def aggregate_public_ip_address_data(self, fetched_data):
    self.aggregated_data["public_ip_addresses"].extend(fetched_data)
    for public_ip_data in fetched_data:
        public_ip_findings = self.assess_public_ip_address_security(public_ip_data)
        self.security_findings["public_ip_addresses"].extend(public_ip_findings)

def aggregate_virtual_network_data(self, fetched_data):
    self.aggregated_data["virtual_networks"].extend(fetched_data)
    for vnet_data in fetched_data:
        vnet_findings = self.assess_virtual_network_security(vnet_data)
        self.security_findings["virtual_networks"].extend(vnet_findings)

def aggregate_network_watcher_data(self, fetched_data):
    self.aggregated_data["network_watchers"].extend(fetched_data)

def aggregate_load_balancer_data(self, fetched_data):
    self.aggregated_data["load_balancers"].extend(fetched_data)

def aggregate_application_gateway_data(self, fetched_data):
    self.aggregated_data["application_gateways"].extend(fetched_data)

def aggregate_azure_firewall_data(self, fetched_data):
    self.aggregated_data["azure_firewalls"].extend(fetched_data)

def aggregate_azure_active_directory_data(self, fetched_data):
    aad_findings = self.assess_azure_active_directory_security(fetched_data)
    self.security_findings["azure_active_directory"].update(aad_findings)

    self.aggregated_data["azure_active_directory"]["users"].extend(fetched_data["users"])
    self.aggregated_data["azure_active_directory"]["groups"].extend(fetched_data["groups"])
    self.aggregated_data["azure_active_directory"]["role_assignments"].extend(fetched_data["role_assignments"])
    self.aggregated_data["azure_active_directory"]["service_principals"].extend(fetched_data["service_principals"])
    self.aggregated_data["azure_active_directory"]["app_registrations"].extend(fetched_data["app_registrations"])
    self.aggregated_data["azure_active_directory"]["conditional_access_policies"].extend(fetched_data["conditional_access_policies"])
    self.aggregated_data["azure_active_directory"]["identity_providers"].extend(fetched_data["identity_providers"])
    self.aggregated_data["azure_active_directory"]["user_settings"].extend(fetched_data["user_settings"])
    self.aggregated_data["azure_active_directory"]["audit_logs"].extend(fetched_data["audit_logs"])
    self.aggregated_data["azure_active_directory"]["sign_in_logs"].extend(fetched_data["sign_in_logs"])

def aggregate_azure_resource_graph_data(self, fetched_data):
    self.aggregated_data["azure_resource_graph"].extend(fetched_data)

def aggregate_azure_security_center_data(self, fetched_data):
    asc_findings = self.assess_azure_security_center_security(fetched_data)
    self.security_findings["azure_security_center"].update(asc_findings)

    self.aggregated_data["azure_security_center"]["security_policies"].extend(fetched_data["security_policies"])
    self.aggregated_data["azure_security_center"]["security_recommendations"].extend(fetched_data["security_recommendations"])
    self.aggregated_data["azure_security_center"]["security_alerts"].extend(fetched_data["security_alerts"])
    self.aggregated_data["azure_security_center"]["compliance_results"].extend(fetched_data["compliance_results"])
    self.aggregated_data["azure_security_center"]["regulatory_compliance_standards"].extend(fetched_data["regulatory_compliance_standards"])
    self.aggregated_data["azure_security_center"]["secure_scores"].extend(fetched_data["secure_scores"])
    self.aggregated_data["azure_security_center"]["automation_settings"].extend(fetched_data["automation_settings"])

def aggregate_azure_monitor_data(self, fetched_data):
    monitor_findings = self.assess_azure_monitor_security(fetched_data)
    self.security_findings["azure_monitor"].update(monitor_findings)

    self.aggregated_data["azure_monitor"]["metrics"].extend(fetched_data["metrics"])
    self.aggregated_data["azure_monitor"]["diagnostic_settings"].extend(fetched_data["diagnostic_settings"])
    self.aggregated_data["azure_monitor"]["log_profiles"].extend(fetched_data["log_profiles"])
    self.aggregated_data["azure_monitor"]["action_groups"].extend(fetched_data["action_groups"])
    self.aggregated_data["azure_monitor"]["autoscale_settings"].extend(fetched_data["autoscale_settings"])
    self.aggregated_data["azure_monitor"]["alert_rules"].extend(fetched_data["alert_rules"])
    self.aggregated_data["azure_monitor"]["app_insights_components"].extend(fetched_data["app_insights_components"])
    self.aggregated_data["azure_monitor"]["log_analytics_workspaces"].extend(fetched_data["log_analytics_workspaces"])

def aggregate_data(self, fetched_data):
    self.aggregate_virtual_machine_data(fetched_data["virtual_machines"])
    self.aggregate_storage_account_data(fetched_data["storage_accounts"])
    self.aggregate_network_interface_data(fetched_data["network_interfaces"])
    self.aggregate_network_security_group_data(fetched_data["network_security_groups"])
    self.aggregate_public_ip_address_data(fetched_data["public_ip_addresses"])
    self.aggregate_virtual_network_data(fetched_data["virtual_networks"])
    self.aggregate_network_watcher_data(fetched_data["network_watchers"])
    self.aggregate_load_balancer_data(fetched_data["load_balancers"])
    self.aggregate_application_gateway_data(fetched_data["application_gateways"])
    self.aggregate_azure_firewall_data(fetched_data["azure_firewalls"])
    self.aggregate_azure_active_directory_data(fetched_data["azure_active_directory"])
    self.aggregate_azure_resource_graph_data(fetched_data["azure_resource_graph"])
    self.aggregate_azure_security_center_data(fetched_data["azure_security_center"])
    self.aggregate_azure_monitor_data(fetched_data["azure_monitor"])

    return self.aggregated_data, self.security_findings