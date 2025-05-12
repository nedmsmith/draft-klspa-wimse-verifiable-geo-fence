---
title: "Trustworthy and Verifiable Geo-fencing for Workloads"
abbrev: "GeoW"
category: info

docname: draft-lkspa-wimse-verifiable-geo-fence-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
ipr: trust200902
area: "Apps & Realtime"
workgroup: "Workload Identity in Multi System Environments"
keyword:
 - geo-fence
 - location affinity
 - host affinity
venue:
  group: "Workload Identity in Multi System Environments"
  type: ""
  mail: "wimse@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/wimse/"
  github: "nedmsmith/draft-klspa-wimse-verifiable-geo-fence"
  latest: "https://nedmsmith.github.io/draft-klspa-wimse-verifiable-geo-fence/draft-lkspa-wimse-verifiable-geo-fence.html"

author:
- ins: R. Krishnan
  name: Ramki Krishnan
  org: Intel
  email: ramki.krishnan@intel.com
- ins: N. Smith
  name: Ned Smith
  org: Intel
  email: ned.smith@intel.com
- ins: D. Lopez
  name: Diego R. Lopez
  org: Telefonica
  email: diego.r.lopez@telefonica.com
- ins: A. Prasad
  name: A Prasad
  org: Oracle
  email: a.prasad@oracle.com
- ins: S. Addepalli
  name: Srinivasa Addepalli
  org: Aryaka
  email: srinivasa.addepalli@aryaka.com

contributor:
  - ins: G. Arfaoui
    name: Ghada Arfaoui
    org: Orange
    email: ghada.arfaoui@orange.com

normative:

informative:
 I-D.ietf-wimse-arch: wimse-arch
 galileo:
  title: Galileo Satellite Navigation
  author:
    org: European Commission, EU Space
  target: https://defence-industry-space.ec.europa.eu/eu-space/galileo-satellite-navigation_en
 doj-cisa:
  title: DOJ and CISA Issue New National Security Program to Regulate Foreign Access to Sensitive Data
  author:
    org: DOJ and CISA
  target: https://www.justice.gov/opa/pr/justice-department-implements-critical-national-security-program-protect-americans-sensitive
 tcg-geo-loc:
  title: TCG keynote and whitepaper-Trusted Computing Future-Emerging Use Cases and Solutions
  author:
    org: TCG
  target: https://trustedcomputinggroup.org/resource/trusted-computing-future-emerging-use-cases-and-solutions/
 tcg-tpm:
  title: Trusted Platform Module 2.0-A Brief Introduction
  author:
    org: TCG
  target: https://trustedcomputinggroup.org/resource/trusted-platform-module-2-0-a-brief-introduction/
 spire:
  title: SPIFFE/SPIRE workload identity
  author:
    org: Spire open source project
  target: https://spiffe.io/
 spire-tpm:
  title: SPIFFE/SPIRE TPM plugin
  author:
    org: Spire open source project plugin
  target: https://github.com/bloomberg/spire-tpm-plugin
 linux-ima:
  title: Linux integrity measurement architecture
  author:
    org: Sourceforge Linux IMA documentation
  target: https://linux-ima.sourceforge.net/
 gsma-loc:
  title: GSMA location API
  author:
    org: GSMA open gateway documentation
  target: https://www.gsma.com/solutions-and-impact/gsma-open-gateway/gsma-open-gateway-api-descriptions/

entity:
  SELF: "RFCthis"

--- abstract

Financial services, healthcare and government entities have data residency requirements, geo-location affinity and host affinity, to protect sensitive data. Geo-location affinity necessitates workload being cryptographically bound to a geographic boundary. Host affinity entails workload being cryptographically bound to a specific execution environment. These requirements are well described in the Trusted Computing Group keynote and whitepaper on emerging use case and solutions [tcg-geo-loc]. From WIMSE perspective, to address these requirements, workload identity needs to be cryptographically bound to platform identity and domain identity. Examples of platform identity are Device ID such as TPM [tcg-tpm] endorsement. Examples of domain identity are Geographic boundary such as Geo-location area/region/country. This draft aims to address the aforementioned gaps in WIMSE through use cases and high level architectural flows.

--- middle

# Introduction

TODO Introduction - nms


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use Cases: Cryptographic Attestation of Geographic Boundaries
Standardizing the attestation of a host’s geographic location enables interoperable enforcement of policy, compliance, and security guarantees across diverse deployment environments.
The following use cases motivate the need for a verifiable geographic claim.

## **Category 1**: Enterprise need cryptographic proof of trustworthy geographic boundary (region, zone, countries, state etc.) for cloud facing workloads
### **Server workload <-> Server workload**:
Enterprises handling sensitive data—such as EU banks—rely on dedicated cloud hosts (e.g., EU sovereign cloud providers) to ensure high availability while complying with data residency laws.
To meet these requirements, they need to be able to verify the geographic boundary where their dedicated hosts are deployed.

### **User workload <-> Server workload**:
Enterprise (e.g. healthcare) ensuring that it is communicating with a server (e.g. cloud service) located within a specific geographic boundary.

## **Category 2**: Enterprise need cryptographic proof of trustworthy geographic boundary for user facing workloads
* A server (or proxy) authenticates to clients using different TLS certificates, each signed by a different Certificate Authority (CA), based on the geographic boundaries of user workloads.

* Enterprise on-premise Customer Premise Equipment (CPE) provides its geographic boundary using a mobile network. This ensures that the Host (H) – a computing device such as a PC, phone, or router – connected to the CPE, is physically present on-premise.

* Construction & Engineering SaaS workloads can benefit immensely from attested geographic boundary data from end-user devices to restrict access within specific regions (e.g., California). Enabling per-user or group-level geo-fencing helps prevent fraudulent access originating outside the authorized area.

* Healthcare providers need to ensure that the Host (H) is located in a specific geographic boundary (countries e.g. US) when downloading patient data or performing other sensitive operations.

* U.S. Presidential Executive Order compliance: For example, U.S. Cloud Service Providers (CSPs) may have support personnel located in a restricted geographic boundary (countries e.g., Venezuela, Iran, China, North Korea). However, those personnel should not be allowed to support U.S. customers. Geo-location enforcement can ensure policy compliance. See [doj-cisa].

## **Category 3**: Security assurance and compliance
Geographic boundary attestation helps satisfy data residency and data sovereignty requirements for regulatory compliance.

# Approach  summary
Host contains location devices like mobile sensor, GPS sensor, WiFi sensor, GNSS sensor, etc. Host is a compute node, including servers, routers, and end-user appliances like smartphones or tablets or PCs. Host has a discrete TPM. Note on TPM -- The EK certificate is a digital certificate signed by the TPM manufacturer's CA which verifies the identity and trustworthiness of the TPM's Endorsement Key (EK);  TPM attestation key (AK) is cryptographically backed by TPM EK. For the initial version of the draft, host is bare metal Linux OS host and interactions are with TPM.

Trusted hosts are the hosts which have trustworthy device composition (TPM EK, Mobile-SIM, GPS device id etc.), endorsed by manufacturer/owner, and use a trustworthy OS. A set of trusted hosts along with the device composition details and OS details are recorded in a shared datastore (database or ledger) by the host owner.

Workload (W) and Agent run on a set of trusted hosts. W can be a server app, a mobile/PC app (including browser), or a network host (e.g., router). Proof of Residency of W on a trusted host is obtained using TPM. W asks its Agent for proof, which in turn asks TPM for AK-attested proof.

Agent sends attested geographic boundary (e.g., cloud region, city, country etc.) and W’s parameters to Workload Identity Manager (WIM).

* Example for Agent used in this document: SPIFFE/SPIRE agent can be enhanced to add attested geographic boundary that will become part of Identity granted (e.g., SVID).

* Example for WIM used in this document: SPIFFE/Spire server

* WIM gives signed Workload ID (WID) with geographic boundary as an additional field. This could be a certificate or a token.

# System boot/reboot and Agent start/restart time attestation/remote verification
The location agent, which is a modified SPIFFE/SPIRE (spire) agent using a geo-location plugin mechanism, is a daemon running on bare-metal Linux OS Host (H) as a process with direct access to TPM (root permissions for TPM 2.0 access may be needed for certain Linux distributions for certain H hardware configurations). The agent can gather the location from host local location sensors (e.g. GPS, GNSS). The agent has a TPM plugin (spire-tpm) which interacts with the TPM. The server (SPIFFE/SPIRE server) is running in cluster which is isolated from the cluster in which the agent is running.

## Boot/reboot time attestation/remote verification of OS for integrity and proof of residency on H
As part of system boot/reboot process, boot loader based measured system boot with remote SPIFFE/SPIRE server verification is used to ensure only approved OS is running on an approved hardware platform.

Measurement Collection: During the boot process, the boot loader collects measurements (hashes) of the boot components and configurations. The boot components are Firmware/BIOS/UEFI, bootloader, OS, drivers, location devices and initial programs. All the location devices (e.g. GPS sensor, Mobile sensor) version/firmware in a platform are measured during each boot -- this is a boot loader enhancement. Any new location device which is hotswapped in will be evaluated for inclusion only during next reboot.

Log Creation: These measurements are recorded in a log, often referred to as the TCGLog, and stored in the TPM's Platform Configuration Registers (PCRs).

Attestation Report: The TPM generates an attestation report, which includes the signed measurements and the boot configuration log. The signature of the attestation report (aka quote) is by a TPM attestation key (AK). This attestation includes data about the TPM's state and can be used to verify that the AK is indeed cryptographically backed by the TPM EK certificate.

Transmission: The attestation report is then sent to an external verifier (server), through a secure TLS connection.

Remote Verification: The remote server checks the integrity of the attestation report and validates the measurements against known good values from the set of trusted hosts in the shared datastore. The server also validates that the TPM EK certificate has not been revoked and part of approved list of TPM EK identifiers associated with hardware platform. At this point, we can be sure that the hardware platform is approved for running workloads and is running an approved OS.

## Start/restart time attestation/remote verification of agent for integrity and proof of residency on H
As part of agent start/restart process, linux integrity measurement architecture (linux-ima) is used to ensure that only approved executable for agent is loaded.

Measurement collection: The agent executable is measured by linux-ima before it is loaded.
Local Verification: Enforce local validation of a measurement against a approved value stored in an extended attribute of the file.

TPM attestation and remote server verification:

* Agent generates attestation key (AK) using TPM for proof of residency on H.

* Agent sends the AK attestation parameters (PCR quote, workload attestation public etc.) and EK certificate to the server

* Server inspects EK certificate. If ca_path exists, and the EK certificate was signed by any chain in ca_path, validation passes

* If validation passed, the server generates a credential activation challenge. The challenge's secret is encrypted using the EK public key.

* Server sends challenge to agent

* Agent decrypts the challenge's secret

* Agent sends back decrypted secret

* Server verifies that the decrypted secret is the same it used to build the challenge

* Server creates a SPIFFE ID along with the sha256sum of the TPM AK public key. Server stores agent SPIFFE ID mapping to TPM AK public key in a shared datastore.

# Agent geo-location and geo-fencing workflow - this is run periodically (say every 5 minutes) to ensure that the host is in the same location
## Step 1: Agent gets attested composite location using Geo-location service (GL)
Geo-location service (GL) runs outside of H -- besides the location from device location sources (e.g. GPS, GNSS), it will connect to mobile location service providers (e.g., Telefonica) using GSMA location API (gsma-loc).

* Agent gathers the location from H local location sensors (e.g. GPS, GNSS). Agent connects to GL using secure connection mechanism like TLS. Agent provides the gathered location to GL over the secure connection.

* Location (L) has a quality associated with it. For example, IP address-based L is of lower quality as compared to other sources.

* GL ensures that the device composition of H (reference to H composition table for further details) is intact (e.g. SIM card not plugged out of H) by periodically polling the state of H. H is a member of the set of trusted hosts in the shared datastore -- the shared datastore has the host composition details. Note that e-SIM does not have the plugging out problem like standard SIM but could be subject to e-SIM swap attack. Host composition (HC) comprises of TPM EK, Mobile-SIM etc.

* GL derives a combined location, including location quality, from various location sensors for a H with multiple location sensors -- this includes the gathered location from Agent running on H. As an example, GPS is considered less trustworthy as compared to mobile.

* The composite location comprises of combined geo-location (which includes location quality), host composition (TPM EK, mobile-SIM etc.) and time from a trusted source. GL signs the composite location with a private key whose public key certificate is a public trusted transparent ledger such as certificate transparency log. Now we have a attested composite location.

* Agent is returned the attested composite location over the secure connection. Agent signs the attested composite location using TPM AK establishing proof of residency of composite location to H. This is called attested proof-of-residency aware composite location (APL).

## Step 2: Agent gets attested geographic boundary using Geo-fencing (GF) service
* Geo-fence policies are of four flavours - (1) boolean membership of given boundary (rectangular, circular, state etc.), (2) precise location, (3) precise bounding box/circle of location, (4) approximate location with no definition of boundary.
The first one, boolean membership of given boundary, is the most common and will be assumed as the default. They are available in the form of pre-defined templates or can be configured on demand.
Enterprises, who are the user of the hosts, choose the geo-fence policies to be enforced for various hosts.
Note that the hosts must belong to the set of trusted hosts in a shared ledger.
The geo-fence policies applied to the set of trusted hosts are recorded in a shared ledger.

* Location agent on H supplies (APL) to geo-fence service (GF) over a secure connection. GF performs geo-fence policy enforcement by matching the location against configured geo-fence policies. GF signs the geo-fence policy match result, along with a trusted time (potentially leverage RFC 3161), with a private key whose public key certificate is a public trusted transparent ledger such as certificate transparency log.

* Geo-fence policy match result details (non-exhaustive): 1) Geo-fence policy which matched 2) Boolean - inside or outside geo-fence - applicable to boolean membership of given boundary policy type.

* Agent is returned the attested geo-fence policy match result. Agent signs the attested geo-fence policy match result using TPM AK establishing proof of residency of geo-fence policy match result to H. This is called attested proof-of-residency aware geo-fence policy match result (APGL).

# Workload (W) attestation and remote verification - key steps
* Agent ensures that W connects to it on H local socket (e.g. Unix domain socket). Agent generates private/public key pair for W. Agent signs the W public key with its TPM AK. Agent sends the signed W public key along with its SPIFFE ID and last known APGL to the server. Note that the TPM AK is already verified by the server as part of the agent attestation process establishing proof of residency of Agent to H.

* Server gets the Agent TPM AK public key from the SPIFFE ID by looking it up in the shared datastore. Server verifies the W public key signature using the TPM AK public key. Server then sends an encrypted challenge to the agent. The challenge's secret is encrypted using the W public key.

* Agent decrypts the challenge using its W private key and sends the response back to the server.

* Server verifies that the decrypted secret is the same it used to build the challenge. It then issues SPIFFE ID for W. The SPIFFE ID is signed by the server and contains the W public key and the geographic boundary (e.g. cloud region, city, country etc.) of the host. The geographic boundary is obtained from the last known APGL. The server also stores the W SPIFFE ID mapping to W public key in a shared datastore.

# Networking Protocol Changes
Workload ID (WID), with location field, in the form of a proof-of-residency certificate or token needs to be conveyed to the peer during connection establishment. The connection is end-to-end across proxies like

## Using TLS

* HTTP session termination (SASE firewall, API gateways etc.) - terminate and re-establish TLS.

* RDP latest version - terminate and re-establish TLS; tcp/ip.

* SCTP session termination (Mobile network SASE firewall etc.) - terminate and re-establish TLS; sctp/ip; does not use TCP or UDP.

## Not Using TLS

* SSH tunnel (Jump hosts etc.) - terminate and re-establish ssh; tcp/ip; does not use TLS.

* IPSEC tunnel (Router control plane etc.) - terminates IPSEC tunnel and forwards encapsulated traffic; ip; does not use TLS.

## Approaches

* Enhance applications (e.g. MCP protocol) to convey Workload ID (WID), with location field.

* Enhance HTTP headers to convey Workload ID (WID), with location field.

* Enhance TLS to convey Workload ID (WID), with location field.

* Enhance SSH/IPSEC to convey Workload ID (WID), with location field.

# Host Composition Table

| Component  | Functionality       | Comments |
|---
| Host | The system that is composed of all of the following software or hardware components. | |
| Trusted hardware devices (focus on geo-location) | Storage root of trust: * TPM - Location root of trust options: GPS sensor, GNSS sensor - signal authentication  prevents spoofing [galileo], Mobile sensor - modem, antenna, SIM - Mobile device location is obtained from mobile network operator and not from device, Wi-Fi sensor - modem, antenna | |
| Boot loader | All the devices (version/firmware) in a platform are trusted and measured during each boot (boot loader enhancement), Any new device (e.g. Mobile location sensor) which is hotswapped in will be evaluated for inclusion only during next reboot. | |
| Trusted OS | Trusted drivers for storage/location root of trust. Does not tamper GPS location/Wi-Fi data. ||
| Geo-location Agent SW - OS level service | Trusted application. Does not tamper GPS location/Wi-Fi data. Sign GPS location data (latitude/ longitude/ altitude), proximal Wi-Fi access points using TPM attestation key. | Possibly a Spire-agent plug-in with TPM attestation. |

**Note**: A GPS sensor with a cryptographic signature, also known as GNSS signal authentication, uses digital signatures in the broadcast signal to ensure the authenticity and integrity of the GPS data, protecting against spoofing attacks.

# Authorization Policy Implementers

Policy Implementers use attested a geographic boundary from W to make decisions.
Example implementers:

* SaaS application.

* K8s node agent.

* OS process scheduler.

If the policy implementer is at the SaaS application level, things are simpler.
However, if it is pushed down to, say, K8s or OS process scheduler or JVM class loader/deserializer, then malware can be prevented (similar to code-signed application).

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
