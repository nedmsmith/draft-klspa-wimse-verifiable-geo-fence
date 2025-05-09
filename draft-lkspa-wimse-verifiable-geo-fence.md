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
 spire-tpm:
  title: SPIFFE/Spire TPM plugin
  author:
    org: Spire open source project
  target: https://github.com/bloomberg/spire-tpm-plugin

entity:
  SELF: "RFCthis"

--- abstract

Financial services, healthcare and government entities have data residency
requirements, geo-location affinity and host affinity, to protect sensitive data. Geo-location affinity necessitates workload being cryptographically bound to a geographic boundary. Host affinity entails workload being cryptographically bound to a specific execution environment.
These requirements are well described in the Trusted Computing Group keynote and whitepaper on emerging use case and solutions [tcg-geo-loc]. From WIMSE perspective, to address these requirements, workload identity needs to be cryptographically bound to platform identity and domain identity. Examples of platform identity are Device ID such as TPM [tcg-tpm] endorsement. Examples of domain identity are Geographic boundary such as Geo-location area/region/country. This draft aims to address the aforementioned gaps in WIMSE through use cases and high level architectural flows.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use Cases: Cryptographic Attestation of Geographic Boundaries
Standardizing the attestation of a host’s geographic location enables interoperable enforcement of policy, compliance, and security guarantees across diverse deployment environments.
The following use cases motivate the need for a verifiable geographic claim.

## **Category 1**: Enterprise need cryptographic proof of trustworthy geographic boundary (region, zone, countries, state etc.) for cloud facing workloads
* **Server workload <-> Server workload**:

Enterprises handling sensitive data—such as EU banks—rely on dedicated cloud hosts (e.g., EU sovereign cloud providers) to ensure high availability while complying with data residency laws.
To meet these requirements, they need to be able to verify the geographic boundary where their dedicated hosts are deployed.

* **User workload <-> Server workload**:

(e.g. healthcare enterprise) ensuring that  it is communicating with a server (e.g. cloud service) located within a specific geographic boundary.

## **Category 2**: Enterprise need cryptographic proof of trustworthy geographic boundary for user facing workloads

* A server (or proxy) authenticates to clients using different TLS certificates, each signed by a different Certificate Authority (CA), based on the geographic boundaries of user workloads.

* Enterprise on-premise Customer Premise Equipment (CPE) provides its geographic boundary using a mobile network. This ensures that the Host (H) – a computing device such as a PC, phone, or router – connected to the CPE, is physically present on-premise.

* Construction & Engineering SaaS workloads can benefit immensely from attested geographic boundary data from end-user devices to restrict access within specific regions (e.g., California). Enabling per-user or group-level geo-fencing helps prevent fraudulent access originating outside the authorized area.

* Healthcare providers need to ensure that the Host (H) is located in a specific geographic boundary (countries e.g. US) when downloading patient data or performing other sensitive operations.

* U.S. Presidential Executive Order compliance: For example, U.S. Cloud Service Providers (CSPs) may have support personnel located in a restricted geographic boundary (countries e.g., Venezuela, Iran, China, North Korea). However, those personnel should not be allowed to support U.S. customers. Geo-location enforcement can ensure policy compliance. See [alert].

## **Category 3**: Security assurance and compliance

Geographic boundary attestation helps satisfy data residency and data sovereignty requirements for regulatory compliance.

# High-level Approach

## Step 1

Host (H) contains location Devices (HD) like mobile sensor, GPS sensor, WiFi sensor, GNSS sensor, etc. H is a compute node, including servers, routers, and end-user appliances like smartphones or tablets or PCs.

## Step 2

Location agent on H gets its attested location (L), and signed by, geo-location service (GL). Signed location delivered as a certificate or signed token (e.g., JWT)? Proof of Residency of location agent on H is obtained using vTPM. Location agent asks vTPM for AIK-attested proof.

### GL can run inside H or outside of H:

* Inside H: Only GPS/GNSS device location sources are available or would like to maximize location privacy.

* Outside H: In turn will connect to mobile location service providers (e.g., Telefonica), and use other sources such as WiFi-based location service providers (e.g., Google) or device location sources (e.g., GNSS).

### Location Quality

* Location (L) has a quality associated with it.
For example, IP address-based L is of lower quality as compared to other sources.

### Definition of attested location generated by GL

* GL ensures that the composition of H is intact (e.g. SIM card not plugged out from CPE) by periodically polling the state of H. Note that e-SIM does not have the plugging out problem like standard SIM.

* GL derives a composite location, including location quality, from various location sensors for a H with multiple location sensors.

* GL signs the composite location, along with a trusted time, with a private key whose public key certificate is a public trusted transparent ledger such as certificate transparency log.

### Geo-location Service

* Geo-location service should check allowed hosts in a shared ledger (TPM EK, mobile-SIM).

* Note that the location is a property of H. Other entities on H (e.g., an application) will have to associate with L through proof of residency on H.

## Step 3

Geo-fence policies are of various types (rectangular, circular etc.).
They are available in the form of pre-defined templates or can be configured on demand.
Enterprises choose the geo-fence policies to be enforced for various hosts. Note that the hosts must belong to the list of allowed hosts in a shared ledger (TPM EK, mobile-SIM).
The geo-fence policies applied to various hosts are recorded in a shared ledger.

## Step 4

Location agent on H supplies attested location (L) to geo-fence service (GF) which performs geo-fence policy enforcement by matching the location against configured geo-fence policies (available in a shared ledger) and returns an attested geo-fence policy match result.

### Geo-fence policy engine is part of GF and uses L and quality of L to make decisions

Geo-fence policy engine can be coded anywhere, including H such as a mobile app for maximizing privacy, a workload/server app, an workload orchestrator, an OS process scheduler, a JVM deserializer, or a storage server.

### Definition of attested geo-fence policy match result (GFL)

Geo-fence policy match result details:

* Geo-fence policy hash which matched

* Boolean (inside or outside geo-fence)

* Distance from geo-fence

GF signs the geo-fence policy match result, along with a trusted time, with a private key whose public key certificate is a public trusted transparent ledger such as certificate transparency log.

GF logs geo-fence policy match result in a shared ledger.

### Log result in ledger - todo

## Step 5

Workload (W) and Workload Agent run on H.
W can be a server app, a mobile/PC app (including browser), or a network host (e.g., router).

## Step 6

Between W and H, there may be several layers of software (e.g., baremetal, hypervisors, VMs, containers, etc.).
Our focus is on W and a virtual-TPM (vTPM) accessible to W, with vTPM transitively and securely linked to bare metal TPM.

If W is directly on bare metal H, the vTPM = TPM on baremetal.

For the first version of the draft, vTPM = TPM on baremetal. Host OS is Linux.

## Step 7

Proof of Residency of W on H is obtained using vTPM. W asks its Workload Agent for proof, which in turn asks vTPM for AIK-attested proof.
(Note: TPM-EK authenticity checked in ledger by Geo-fencing service earlier, as described above.)

W’s Proof of Residency on H + H’s attested location from geo-fencing service = attested location for W

## Step 8

Workload Agent sends attested location + W’s parameters to Workload Identity Manager (WIM).

* Example for a Workload Agent: SPIFFE/Spire agent can be enhanced to add attested location that will become part of Identity granted (e.g., SVID).

* Example for WIM: SPIFFE/Spire server

## Step 9

Workload Identity Manager gives signed Workload ID (WID) with location as a field or location-matches boolean result as a field. This could be a certificate or a token.

The agent (SPIFFE/SPIRE agent) is a daemon running on bare-metal Linux OS as a process with root permissions and direct access to TPM. The agent has a TPM plugin which interacts with the TPM. The server (SPIFFE/SPIRE server) is running in cluster which is isolated from the cluster in which the agent is running.

### Step 9.1 - Boot time attestation of OS and agent
Measurement Collection: During the boot process, the boot loader collects measurements (hashes) of the boot components and configurations. The boot components are Firmware/BIOS/UEFI, bootloader, OS, drivers and initial programs (includes agent).

Log Creation: These measurements are recorded in a log, often referred to as the TCGLog, and stored in the TPM's Platform Configuration Registers (PCRs).

Attestation Report: The TPM generates an attestation report, which includes the signed measurements and the boot configuration log.

Transmission: The attestation report is then sent to an external verifier (server), usually through a secure channel such as TLS/SSL.

Verification: The server checks the integrity of the attestation report and validates the measurements against known good values. The server also validates that the TPM EK certificate has not been revoked and part of allowed list of TPM EK identifiers. At this point, we can be sure that the agent is running on a trusted platform.

The plugin uses TPM credential activation as the method of attestation. The plugin operates as follows:

<!--
Agent generates AK (attestation key) using TPM
Agent sends the AK attestation parameters and EK certificate or public key to the server
Server inspects EK certificate or public key
If hash_path exists, and the public key hash matches filename in hash_path, validation passes
If ca_path exists, and the EK certificate was signed by any chain in ca_path, validation passes
If validation passed, the server generates a credential activation challenge using
The EK public key
The AK attestation parameters
Server sends challenge to agent
Agent decrypts the challenge's secret
Agent sends back decrypted secret
Server verifies that the decrypted secret is the same it used to build the challenge
Server creates a SPIFFE ID in the form of spiffe://<trust_domain>/agent/tpm/<sha256sum_of_tpm_pubkey>
-->
# Networking Protocol Changes

Workload ID (WID), with location field, in the form of a proof-of-residency certificate or token needs to be conveyed to the peer during connection established. The connection is end-to-end across proxies like

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

# Host Details

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
