# Example configurations / Exemplos de configuração

All values are fictional. Every file is checked by the test suite (no unknown fields, passes validation), so they stay in sync with the code.
Todos os valores são fictícios. Cada ficheiro é verificado pelos testes, por isso nunca fica desatualizado.

| File / Ficheiro | Scenario / Cenário |
|---|---|
| [collector.full.json](collector.full.json) | Collector with every option: per-agent tokens, alerts (Slack, Teams, webhook, email), SSO (Entra ID, Google, Okta) / Collector com todas as opções |
| [agent.full.json](agent.full.json) | Agent with every checker at once / Agente com todos os checkers |
| [agent/web-tls.json](agent/web-tls.json) | Websites, mail (SMTP STARTTLS) and local certificate files / Sites, email e certificados locais |
| [agent/windows-iis.json](agent/windows-iis.json) | Windows server: IIS, RDP, Exchange, SQL Server certificates (certificate store) / Servidor Windows |
| [agent/azure.json](agent/azure.json) | Azure: Key Vault, App Registrations, Enterprise Apps (SAML), managed certificates, IoT Hub/DPS device certificates |
| [agent/aws.json](agent/aws.json) | AWS: ACM, IAM server certificates, access key age, Secrets Manager rotation, IoT Core device certificates, multi-account |
| [agent/gcp.json](agent/gcp.json) | GCP: Certificate Manager, SSL certificates, service account keys, Secret Manager, whole organization |
| [agent/vault.json](agent/vault.json) | HashiCorp Vault: PKI, KV v2, AppRole secret IDs, tokens, leases |
| [agent/vmware.json](agent/vmware.json) | VMware: vCenter and ESXi certificates, vSphere licences |
| [agent/ot-ics.json](agent/ot-ics.json) | ICS/OT: OPC UA servers (PLC, SCADA, MES), HMI and historian HTTPS, OPC UA PKI stores, device end of support (inventory), `ot_safe` |
| [ot-assets.csv](ot-assets.csv) | Inventory file: device end of support, firmware support, contracts, domains / Ficheiro de inventário |
| [agent/iiot-iot.json](agent/iiot-iot.json) | IIoT/IoT: MQTT and AMQP brokers, edge gateways, broker certificate files, AWS IoT Core / Azure IoT Hub device identity certificates, `ot_safe` |

One agent can combine several scenarios: merge the sections you need into one file. / Um agente pode juntar vários cenários: junta as secções que precisas num só ficheiro.
