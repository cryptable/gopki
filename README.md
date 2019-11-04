# gopki
Tiny PKI for microservices to implement 2-way SSL and from P2P or policy based verification based on cryptographic certificates. The system will install certificate, auto-renewal, decommissioning and revoking complete hidden from the developers. The system will explain to the application to validate certificate to create P2P communication or Zoning based on certificate policies (or naming convetion).
This will be tightly integrated into Kubernetes clusters where it will first be conceived for. Due to the emphemeral properties of containers, certificate and private will be centrally stored and securely pushed in memory to containers when they start and bootstrap with gopki.
This is the central server which shall communicate with different kind of integrations:
- go http integration 
- Spring One integration 

Any other ideas are welcome
