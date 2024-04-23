import subprocess
import json

class DataFetcher:
    def __init__(self, azure_config):
        self.subscription_id = azure_config["subscription_id"]
        self.resource_group_name = azure_config["resource_group_name"]

    def run_az_cli_command(self, command):
        try:
            output = subprocess.check_output(command, shell=True, universal_newlines=True)
            return json.loads(output)
        except subprocess.CalledProcessError as e:
            print(f"Error running Azure CLI command: {e}")
            return None

    def fetch_virtual_machine_data(self):
        command = f"az vm list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --show-details --query '[].{{name: name, resourceGroup: resourceGroup, location: location, size: hardwareProfile.vmSize, osType: storageProfile.osDisk.osType, provisioningState: provisioningState, ipAddresses: [].{{publicIpAddress: publicIpAddress, privateIpAddress: privateIpAddress}}, networkInterfaces: [].{{id: id}}, disks: storageProfile.dataDisks[*].{{name: name, diskSizeGB: diskSizeGB, createOption: createOption}}, accessPolicies: osProfile.linuxConfiguration.ssh.publicKeys[].keyData, extensions: resources[?type=='Microsoft.Compute/virtualMachines/extensions'], availabilitySet: availabilitySet.id, managedIdentity: identity.type}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_storage_account_data(self):
        command = f"az storage account list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, sku: sku.name, kind: kind, accessTier: accessTier, minimumTlsVersion: minimumTlsVersion, allowBlobPublicAccess: allowBlobPublicAccess, networkRuleSet: networkRuleSet, encryption: encryption, blobServices: blobServices, fileServices: fileServices, queueServices: queueServices, tableServices: tableServices}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_network_interface_data(self):
        command = f"az network nic list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, ipConfigurations: ipConfigurations[].{{name: name, publicIpAddress: publicIpAddress.id, privateIpAddress: privateIpAddress, subnet: subnet.id}}, networkSecurityGroup: networkSecurityGroup.id, dnsSettings: dnsSettings, enableAcceleratedNetworking: enableAcceleratedNetworking, enableIpForwarding: enableIpForwarding}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_network_security_group_data(self):
        command = f"az network nsg list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, securityRules: securityRules[].{{name: name, description: description, protocol: protocol, sourcePortRange: sourcePortRange, destinationPortRange: destinationPortRange, sourceAddressPrefix: sourceAddressPrefix, destinationAddressPrefix: destinationAddressPrefix, access: access, priority: priority, direction: direction}}, defaultSecurityRules: defaultSecurityRules[].{{name: name, description: description, protocol: protocol, sourcePortRange: sourcePortRange, destinationPortRange: destinationPortRange, sourceAddressPrefix: sourceAddressPrefix, destinationAddressPrefix: destinationAddressPrefix, access: access, priority: priority, direction: direction}}, subnets: subnets[].id, networkInterfaces: networkInterfaces[].id}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_public_ip_address_data(self):
        command = f"az network public-ip list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, sku: sku.name, allocationMethod: publicIpAllocationMethod, version: publicIpAddressVersion, ipAddress: ipAddress, idleTimeoutInMinutes: idleTimeoutInMinutes, dnsSettings: dnsSettings, ipTags: ipTags}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_virtual_network_data(self):
        command = f"az network vnet list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, addressSpace: addressSpace.addressPrefixes, subnets: subnets[].{{name: name, addressPrefix: addressPrefix}}, dhcpOptions: dhcpOptions, virtualNetworkPeerings: virtualNetworkPeerings[].{{name: name, remoteVirtualNetwork: remoteVirtualNetwork.id, allowVirtualNetworkAccess: allowVirtualNetworkAccess, allowForwardedTraffic: allowForwardedTraffic, allowGatewayTransit: allowGatewayTransit, useRemoteGateways: useRemoteGateways}}, enableDdosProtection: enableDdosProtection, enableVmProtection: enableVmProtection}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_network_watcher_data(self):
        command = f"az network watcher list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, provisioningState: provisioningState}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_load_balancer_data(self):
        command = f"az network lb list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, frontendIpConfigurations: frontendIpConfigurations[].{{name: name, publicIpAddress: publicIpAddress.id, privateIpAddress: privateIpAddress, subnet: subnet.id}}, backendAddressPools: backendAddressPools[].{{name: name}}, loadBalancingRules: loadBalancingRules[].{{name: name, protocol: protocol, frontendPort: frontendPort, backendPort: backendPort, enableFloatingIp: enableFloatingIp, idleTimeoutInMinutes: idleTimeoutInMinutes, loadDistribution: loadDistribution}}, probes: probes[].{{name: name, protocol: protocol, port: port, intervalInSeconds: intervalInSeconds, numberOfProbes: numberOfProbes}}, inboundNatRules: inboundNatRules[].{{name: name, frontendIpConfiguration: frontendIpConfiguration.id, protocol: protocol, frontendPort: frontendPort, backendPort: backendPort, idleTimeoutInMinutes: idleTimeoutInMinutes, enableFloatingIp: enableFloatingIp, enableTcpReset: enableTcpReset}}}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_application_gateway_data(self):
        command = f"az network application-gateway list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, sku: sku, sslPolicy: sslPolicy, gatewayIpConfigurations: gatewayIpConfigurations[].{{name: name, subnet: subnet.id}}, authenticationCertificates: authenticationCertificates[].{{name: name}}, trustedRootCertificates: trustedRootCertificates[].{{name: name}}, frontendIpConfigurations: frontendIpConfigurations[].{{name: name, publicIpAddress: publicIpAddress.id, privateIpAddress: privateIpAddress, subnet: subnet.id}}, frontendPorts: frontendPorts[].{{name: name, port: port}}, backendAddressPools: backendAddressPools[].{{name: name, backendAddresses: backendAddresses[].{{ipAddress: ipAddress, fqdn: fqdn}}}}, backendHttpSettingsCollection: backendHttpSettingsCollection[].{{name: name, port: port, protocol: protocol, cookieBasedAffinity: cookieBasedAffinity, pickHostNameFromBackendAddress: pickHostNameFromBackendAddress, probeEnabled: probeEnabled, probePath: probe.path}}, httpListeners: httpListeners[].{{name: name, frontendIpConfiguration: frontendIpConfiguration.id, frontendPort: frontendPort.id, protocol: protocol, hostName: hostName, requireServerNameIndication: requireServerNameIndication, sslCertificate: sslCertificate.id}}, urlPathMaps: urlPathMaps[].{{name: name, defaultBackendAddressPool: defaultBackendAddressPool.id, defaultBackendHttpSettings: defaultBackendHttpSettings.id, pathRules: pathRules[].{{name: name, paths: paths, backendAddressPool: backendAddressPool.id, backendHttpSettings: backendHttpSettings.id}}}}, requestRoutingRules: requestRoutingRules[].{{name: name, ruleType: ruleType, httpListener: httpListener.id, backendAddressPool: backendAddressPool.id, backendHttpSettings: backendHttpSettings.id, rewriteRuleSet: rewriteRuleSet.id, redirectConfiguration: redirectConfiguration.id}}}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_azure_firewall_data(self):
        command = f"az network firewall list --subscription {self.subscription_id} --resource-group {self.resource_group_name} --query '[].{{name: name, resourceGroup: resourceGroup, location: location, ipConfigurations: ipConfigurations[].{{name: name, publicIpAddress: publicIpAddress.id, privateIpAddress: privateIpAddress, subnet: subnet.id}}, applicationRuleCollections: applicationRuleCollections[].{{name: name, priority: priority, action: action.type, rules: rules[].{{name: name, description: description, sourceAddresses: sourceAddresses, protocols: protocols[].{{port: port, protocolType: protocolType}}, targetFqdns: targetFqdns, fqdnTags: fqdnTags}}}}, networkRuleCollections: networkRuleCollections[].{{name: name, priority: priority, action: action.type, rules: rules[].{{name: name, description: description, protocols: protocols, sourceAddresses: sourceAddresses, destinationAddresses: destinationAddresses, destinationPorts: destinationPorts}}}}, natRuleCollections: natRuleCollections[].{{name: name, priority: priority, action: action.type, rules: rules[].{{name: name, description: description, protocols: protocols, sourceAddresses: sourceAddresses, destinationAddresses: destinationAddresses, destinationPorts: destinationPorts, translatedAddress: translatedAddress, translatedPort: translatedPort}}}}, threatIntelMode: threatIntelMode, threatIntelWhitelist: threatIntelWhitelist.{{fqdns: fqdns, ipAddresses: ipAddresses}}}}' -o json"
        return self.run_az_cli_command(command)

    def fetch_azure_active_directory_data(self):
        command_users = "az ad user list --query '[].{displayName: displayName, userPrincipalName: userPrincipalName, mail: mail, userType: userType, accountEnabled: accountEnabled}' -o json"
        command_groups = "az ad group list --query '[].{displayName: displayName, description: description, mailEnabled: mailEnabled, mailNickname: mailNickname, securityEnabled: securityEnabled}' -o json"
        command_role_assignments = "az role assignment list --all --query '[].{principalName: principalName, roleDefinitionName: roleDefinitionName, scope: scope}' -o json"
        command_service_principals = "az ad sp list --query '[].{displayName: displayName, appId: appId, servicePrincipalNames: servicePrincipalNames, objectType: objectType}' -o json"
        command_app_registrations = "az ad app list --query '[].{displayName: displayName, appId: appId, objectType: objectType, publisherDomain: publisherDomain, replyUrls: replyUrls, homepage: homepage}' -o json"
        command_conditional_access_policies = "az ad conditional-access policy list --query '[].{displayName: displayName, state: state, conditions: conditions, grantControls: grantControls, sessionControls: sessionControls}' -o json"
        command_identity_providers = "az ad identity-provider list --query '[].{name: name, type: type, clientId: clientId, clientSecret: clientSecret}' -o json"
        command_user_settings = "az ad user settings list --query '[].{displayName: displayName, templateId: templateId, values: values}' -o json"
        command_audit_logs = "az ad audit-log list --query '[].{activityDateTime: activityDateTime, loggedByService: loggedByService, operationName: operationName, resultReason: resultReason, initiatedBy: initiatedBy, targetResources: targetResources}' -o json"
        command_sign_in_logs = "az ad sign-in log list --query '[].{createdDateTime: createdDateTime, userPrincipalName: userPrincipalName, appId: appId, ipAddress: ipAddress, status: status, locationInfo: locationInfo, clientAppUsed: clientAppUsed}' -o json"

        users = self.run_az_cli_command(command_users)
        groups = self.run_az_cli_command(command_groups)
        role_assignments = self.run_az_cli_command(command_role_assignments)
        service_principals = self.run_az_cli_command(command_service_principals)
        app_registrations = self.run_az_cli_command(command_app_registrations)
        conditional_access_policies = self.run_az_cli_command(command_conditional_access_policies)
        identity_providers = self.run_az_cli_command(command_identity_providers)
        user_settings = self.run_az_cli_command(command_user_settings)
        audit_logs = self.run_az_cli_command(command_audit_logs)
        sign_in_logs = self.run_az_cli_command(command_sign_in_logs)

        return {
            "users": users,
            "groups": groups,
            "role_assignments": role_assignments,
            "service_principals": service_principals,
            "app_registrations": app_registrations,
            "conditional_access_policies": conditional_access_policies,
            "identity_providers": identity_providers,
            "user_settings": user_settings,
            "audit_logs": audit_logs,
            "sign_in_logs": sign_in_logs
        }

    def fetch_azure_resource_graph_data(self):
        command = "az graph query -q 'Resources | project name, type, location, resourceGroup, subscriptionId, properties' --query 'data[].{name: name, type: type, location: location, resourceGroup: resourceGroup, subscriptionId: subscriptionId, properties: properties}' -o json"
        return self.run_az_cli_command(command)

    def fetch_azure_security_center_data(self):
        command_security_policies = "az security policy list --query '[].{name: name, policyType: type, policyDefinition: policyDefinition, policySetDefinition: policySetDefinition, assignments: assignments}' -o json"
        command_security_recommendations = "az security assessment list --query '[].{name: name, resourceDetails: resourceDetails, status: status, remediation: remediation, impact: impact, impactedResources: impactedResources}' -o json"
        command_security_alerts = "az security alert list --query '[].{name: name, alertType: alertType, severity: severity, status: status, compromisedEntity: compromisedEntity, remediationSteps: remediationSteps}' -o json"
        command_compliance_results = "az security compliance list --query '[].{name: name, type: type, resourceStatus: resourceStatus, policyAssessment: policyAssessment}' -o json"
        command_regulatory_compliance_standards = "az security regulatory-compliance-standard list --query '[].{name: name, type: type, description: description, state: state, passedControls: passedControls, failedControls: failedControls, skippedControls: skippedControls}' -o json"
        command_secure_scores = "az security secure-score list --query '[].{name: name, type: type, score: properties.score.current, weight: properties.weight, maxScore: properties.score.max}' -o json"
        command_automation_settings = "az security setting list --query '[].{name: name, type: type, enabled: properties.value}' -o json"

        security_policies = self.run_az_cli_command(command_security_policies)
        security_recommendations = self.run_az_cli_command(command_security_recommendations)
        security_alerts = self.run_az_cli_command(command_security_alerts)
        compliance_results = self.run_az_cli_command(command_compliance_results)
        regulatory_compliance_standards = self.run_az_cli_command(command_regulatory_compliance_standards)
        secure_scores = self.run_az_cli_command(command_secure_scores)
        automation_settings = self.run_az_cli_command(command_automation_settings)

        return {
            "security_policies": security_policies,
            "security_recommendations": security_recommendations,
            "security_alerts": security_alerts,
            "compliance_results": compliance_results,
            "regulatory_compliance_standards": regulatory_compliance_standards,
            "secure_scores": secure_scores,
            "automation_settings": automation_settings
        }

    def fetch_azure_monitor_data(self):
        command_metrics = "az monitor metrics list --resource-group {self.resource_group_name} --query '[].{{name: name.value, timeStamp: timeStamp, average: average, minimum: minimum, maximum: maximum, total: total, count: count}}' -o json"
        command_diagnostic_settings = "az monitor diagnostic-settings list --resource-group {self.resource_group_name} --query '[].{{name: name, storageAccountId: storageAccountId, eventHubAuthorizationRuleId: eventHubAuthorizationRuleId, eventHubName: eventHubName, workspaceId: workspaceId, logs: logs, metrics: metrics}}' -o json"
        command_log_profiles = "az monitor log-profiles list --query '[].{{name: name, locations: locations, categories: categories, retentionPolicy: retentionPolicy}}' -o json"
        command_action_groups = "az monitor action-group list --query '[].{{name: name, shortName: shortName, enabled: enabled, emailReceivers: emailReceivers, smsReceivers: smsReceivers, webhookReceivers: webhookReceivers, itsmReceivers: itsmReceivers, azureAppPushReceivers: azureAppPushReceivers, automationRunbookReceivers: automationRunbookReceivers, voiceReceivers: voiceReceivers, logicAppReceivers: logicAppReceivers, azureFunctionReceivers: azureFunctionReceivers, armRoleReceivers: armRoleReceivers}}' -o json"
        command_autoscale_settings = "az monitor autoscale list --query '[].{{name: name, enabled: enabled, profiles: profiles, notifications: notifications, targetResourceUri: targetResourceUri}}' -o json"
        command_alert_rules = "az monitor alert list --query '[].{{name: name, severity: severity, scopes: scopes, evaluationFrequency: evaluationFrequency, windowSize: windowSize, targetResourceType: targetResourceType, targetResourceRegion: targetResourceRegion, criteria: criteria, autoMitigate: autoMitigate, actions: actions}}' -o json"
        command_app_insights_components = "az monitor app-insights component list --query '[].{{name: name, applicationType: applicationType, applicationId: applicationId, sdkVersion: sdkVersion, ingestionMode: ingestionMode, publicNetworkAccessForQuery: publicNetworkAccessForQuery, publicNetworkAccessForIngestion: publicNetworkAccessForIngestion, disableIpMasking: disableIpMasking}}' -o json"
        command_log_analytics_workspaces = "az monitor log-analytics workspace list --query '[].{{name: name, resourceGroup: resourceGroup, location: location, sku: sku.name, retentionInDays: retentionInDays, customerId: customerId, provisioningState: provisioningState}}' -o json"

        metrics = self.run_az_cli_command(command_metrics)
        diagnostic_settings = self.run_az_cli_command(command_diagnostic_settings)
        log_profiles = self.run_az_cli_command(command_log_profiles)
        action_groups = self.run_az_cli_command(command_action_groups)
        autoscale_settings = self.run_az_cli_command(command_autoscale_settings)
        alert_rules = self.run_az_cli_command(command_alert_rules)
        app_insights_components = self.run_az_cli_command(command_app_insights_components)
        log_analytics_workspaces = self.run_az_cli_command(command_log_analytics_workspaces)

        return {
            "metrics": metrics,
            "diagnostic_settings": diagnostic_settings,
            "log_profiles": log_profiles,
            "action_groups": action_groups,
            "autoscale_settings": autoscale_settings,
            "alert_rules": alert_rules,
            "app_insights_components": app_insights_components,
            "log_analytics_workspaces": log_analytics_workspaces
        }

    def fetch_data(self):
        virtual_machine_data = self.fetch_virtual_machine_data()
        storage_account_data = self.fetch_storage_account_data()
        network_interface_data = self.fetch_network_interface_data()
        network_security_group_data = self.fetch_network_security_group_data()
        public_ip_address_data = self.fetch_public_ip_address_data()
        virtual_network_data = self.fetch_virtual_network_data()
        network_watcher_data = self.fetch_network_watcher_data()
        load_balancer_data = self.fetch_load_balancer_data()
        application_gateway_data = self.fetch_application_gateway_data()
        azure_firewall_data = self.fetch_azure_firewall_data()
        azure_active_directory_data = self.fetch_azure_active_directory_data()
        azure_resource_graph_data = self.fetch_azure_resource_graph_data()
        azure_security_center_data = self.fetch_azure_security_center_data()
        azure_monitor_data = self.fetch_azure_monitor_data()

        fetched_data = {
            "virtual_machines": virtual_machine_data,
            "storage_accounts": storage_account_data,
            "network_interfaces": network_interface_data,
            "network_security_groups": network_security_group_data,
            "public_ip_addresses": public_ip_address_data,
            "virtual_networks": virtual_network_data,
            "network_watchers": network_watcher_data,
            "load_balancers": load_balancer_data,
            "application_gateways": application_gateway_data,
            "azure_firewalls": azure_firewall_data,
            "azure_active_directory": azure_active_directory_data,
            "azure_resource_graph": azure_resource_graph_data,
            "azure_security_center": azure_security_center_data,
            "azure_monitor": azure_monitor_data
        }

        return fetched_data