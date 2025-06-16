---
title: "Trustworthy and Verifiable Geofencing for Workloads"
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
 - geofence
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
  - ins: Michael Epley
    name: Michael Epley
    org: Red Hat
    email: mepley@redhat.com

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
    title: Linux Integrity Measurement Architecture
    author:
      org: Sourceforge Linux IMA documentation
    target: https://linux-ima.sourceforge.net/
  gsma-loc:
    title: GSMA location API
    author:
      org: GSMA open gateway documentation
    target: https://www.gsma.com/solutions-and-impact/gsma-open-gateway/gsma-open-gateway-api-descriptions/
  spiffe-x509-svid:
    title: SPIFFE X.509-SVID Standard
    author:
      org: SPIFFE Project
    target: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
  spiffe-jwt-svid:
    title: SPIFFE JWT-SVID Standard
    author:
      org: SPIFFE Project
    target: https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
  RFC-7800:
    title: Proof-of-Possession Key Semantics for JSON Web Tokens (JWT)
    author:
      org: IETF
    target: https://datatracker.ietf.org/doc/html/rfc7800
  RFC-8705:
    title: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
    author:
      org: IETF
    target: https://datatracker.ietf.org/doc/html/rfc8705
  tpm-performance:
    title: TPM Performance - How Fast is Your TPM?
    author:
      org: Stian Kristoffersen (Substack)
    target: https://stiankri.substack.com/p/tpm-performance

entity:
  SELF: "RFCthis"
--- abstract

Financial services, healthcare, and government entities have data residency requirements that aim to protect sensitive data by specifying its location. Data location can be both geographic and host-centric. Geolocation affinity means workloads are cryptographically bound to a geographic boundary. Host affinity means workloads are cryptographically bound to a specific execution environment. WIMSE architecture can be improved to show how location can be cryptographically bound to WIMSE identities. This document augments WIMSE architecture to include geolocation and host affinity use cases and workflows.

--- middle

# Introduction

This document describes a framework for trustworthy and verifiable geofencing of workloads.
It details use cases, architectural flows, and protocol enhancements that leverage trusted hardware (e.g., TPM), attestation protocols, and geolocation services.
The goal is to enable interoperable, cryptographically verifiable claims about workload residency and location, supporting compliance, security, and operational requirements in multi-system environments.

As organizations increasingly adopt cloud and distributed computing, the need to enforce data residency, geolocation affinity, and host affinity has become critical for regulatory compliance and risk management.
Traditional approaches to geographic and host enforcement rely on trust in infrastructure providers or network-based controls, which are insufficient in adversarial or multi-tenant environments.

Recent advances in trusted computing, remote attestation, and workload identity standards enable a new class of solutions where the geographic location and host integrity of workloads can be cryptographically attested and verified.
By binding workload identity to both platform and domain attributes, such as TPM-backed device identity and verifiable geographic boundaries, organizations can enforce fine-grained policies to define where and how sensitive workloads are executed.

Data residency requirements are described in more detail in [tcg-geo-loc].

An example of platform identity binding (i.e., host affinity) is described in [tcg-tpm].

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use Cases

Data residency use cases can be divided into three categories: (1) server-centric location, (2) user-centric location, and (3) regulatory compliance.

## Category 1: Server-centric Location

Enterprises (e.g., healthcare, banking) need cryptographic proof of a trustworthy geographic boundary (i.e., region, zone, country, state, etc.) for cloud-facing workloads.

### Server workload <-> Server workload - General:
Enterprises handling sensitive data rely on dedicated cloud hosts (e.g., EU sovereign cloud providers) that ensure compliance with data residency laws, while also ensuring appropriate levels of service (e.g., high availability).
To meet data residency legal requirements, enterprises need to verify that workload data is processed by hosts within a geographic boundary and that workload data is only transmitted between specified geographic boundaries.

### Server workload <-> Server workload - Agentic AI:
Enterprises need to ensure that the AI agent is located within a specific geographic boundary when downloading sensitive data or performing other sensitive operations. A secure AI agent, running on a trusted host with TPM-backed attestation, interacts with geolocation and geofencing services to obtain verifiable proof of its geographic boundary. The agent periodically collects location data from trusted sensors, obtains attested composite location from a geolocation service, and enforces geofence policies via a geofencing service. The resulting attested geofence proof is used to bind workload identity to both the host and its geographic location, enabling secure, policy-driven execution of AI workloads and compliance with data residency requirements.

[Figure -- Cybersecure and Compliant Agentic AI Workflow](https://github.com/nedmsmith/draft-klspa-wimse-verifiable-geo-fence/blob/main/pictures/secure-agentic-workflow.svg/)

### Server workload <-> Server workload - Federated AI:
In federated learning scenarios, multiple organizations collaborate to train machine learning models without sharing raw data. Each organization needs to ensure that its training data remains within a specific geographic boundary. This requires cryptographic proof that the training process is occurring on trusted hosts within the defined boundaries.

### User workload <-> Server workload:
Enterprises ensure that they are communicating with a server (e.g., cloud services) located within a specific geographic boundary.

## Category 2: User-centric Location

Enterprises need cryptographic proof of trustworthy geographic boundary for user-facing workloads.

* A server (or proxy) authenticates to clients using different TLS certificates, each signed by a different Certificate Authority (CA), based on the geographic boundaries of user workloads.

* Enterprise Customer Premise Equipment (CPE) provides on-premises computing that is a basis for defining geolocation boundaries.
A telco network provides a means for communication between premises.

* Construction & Engineering of SaaS workloads can benefit from attested geographic boundary data from end-user devices to restrict access within specific geopolitical regions (e.g., California).
Enabling per-user or group-level geofencing helps prevent fraudulent access originating outside the authorized area.

* Healthcare providers need to ensure that the host is located in a specific geographic boundary when downloading patient data or performing other sensitive operations.

* U.S. Presidential Executive Order (doj-cisa) compliance directs Cloud Service Provider (CSP) support personnel be located in restricted geographies (e.g., Venezuela, Iran, China, North Korea).
However, those personnel should not be allowed to support U.S. customers.
Geolocation enforcement can ensure policy compliance. See [doj-cisa].

## Category 3: Regulatory Compliance

Geographic boundary attestation helps satisfy data residency and data sovereignty requirements for regulatory compliance.

# Problem Statements

* **Bearer Tokens:** Typically generated via user MFA and used to establish HTTP sessions. A malicious actor can steal a bearer token (e.g., from a still-valid HAR file uploaded to a support portal, as seen in the Okta attack) and present it to a server workload. The attacker may be in a forbidden location and on an unauthorized host (e.g., their own laptop). Proof-of-Possession (PoP) tokens ([RFC-7800]) and PoP via mutual TLS ([RFC-8705]) attempt to mitigate this threat, but face the challenges described below.

* **PoP Token:** How is trust established between the presenter (client) and the token issuer, so that the presenter can securely connect to the recipient (server)?

* **PoP via Mutual TLS:** Client certificates are generally not supported in browsers. In production, man-in-the-middle entities such as API gateways often terminate TLS connections, breaking the end-to-end trust model.

* **Host TPMs for Signature:** It is not scalable to sign every API call with a TPM key, as typical enterprise laptops/servers support only about 5 signatures per second ([tpm-performance]).

* **IP Address-Based Location:** This is the typical approach, but it has limitations: network providers can use geographic-region-based IANA-assigned IP addresses anywhere in the world, and enterprise VPNs can hide the user's real IP address.

* **Wi-Fi-Based Location:** For user laptop endpoints with agents (e.g., ZTNA), traditional geographic enforcement relies on trusting the Wi-Fi access point’s location. However, Wi-Fi access points are mobile and can be moved, undermining this trust.

# Approach Summary

This approach enables cryptographically verifiable geofencing by binding workload identity to both platform and geographic attributes using trusted hardware (e.g., TPM), attestation protocols, and geolocation services. The framework supports secure, policy-driven enforcement of data residency and location requirements for workloads in multi-system environments.

Key elements of the approach include:
- **Trusted Hardware Roots:** Workload identity is anchored in hardware roots of trust such as TPMs, GNSS sensors, and mobile network modules, ensuring device integrity and authentic location data.
- **Remote Attestation:** Workload Identity Agents collect measurements from the platform and location sensors, and use TPM-backed attestation to prove the integrity and residency of the workload to a remote Workload Identity Manager.
- **Composite Location Claims:** The system combines multiple sources of location (e.g., GNSS, mobile network, Wi-Fi) and device composition (e.g., SIM, TPM EK) to create a composite, quality-scored location claim, which is cryptographically signed and verifiable.
- **Policy Enforcement:** Workload Identity Managers and downstream policy implementers use these verifiable claims to enforce geofencing and data residency policies, ensuring that workloads only run or access data within approved geographic or jurisdictional boundaries.
- **Continuous Monitoring:** The framework supports periodic re-attestation and monitoring of device composition and location, detecting changes such as SIM swaps or sensor removal that could affect trust.
- **Interoperability:** The approach is designed to integrate with existing workload identity frameworks (e.g., SPIFFE/SPIRE), enabling adoption in cloud, edge, and enterprise environments.

For example, in this document:
  * The **Workload Identity Manager** is represented by the SPIFFE/SPIRE server (spire).
  * The **Workload Identity Agent** is represented by the SPIFFE/SPIRE agent (spire).

# SPIFFE/SPIRE Architecture Modifications

In the context of the SPIFFE/SPIRE architecture (spire), the SPIFFE/SPIRE agent includes a new geolocation plugin -- this is depicted in the figure below. The agent is a daemon running on bare-metal Linux OS host (H) as a process with direct access to TPM (root permissions for TPM 2.0 access may be needed for certain Linux distributions for certain H hardware configurations).
The agent, using the geolocation plugin, can gather the location from host-local location sensors (e.g., GNSS).
The agent has a TPM plugin (spire-tpm) which interacts with the TPM.
The Workload Identity Manager (SPIFFE/SPIRE server) is running in a cluster which is isolated from the cluster in which the agent is running.

[Figure -- Modified SPIFFE-SPIRE architecture with new geolocation plugin](https://github.com/nedmsmith/draft-klspa-wimse-verifiable-geo-fence/blob/main/pictures/spiffe-spire.svg)

# Control Plane - End-to-End Workflow

The end-to-end workflow for the proposed framework consists of several key steps, including attestation for system bootstrap and workload identity agent initialization, workload identity agent geolocation and geofencing processing, workload attestation, and remote verification.

[Figure -- End-to-end Workflow](https://github.com/nedmsmith/draft-klspa-wimse-verifiable-geo-fence/blob/main/pictures/end-to-end-flow.svg)

## Attestation for System Bootstrap and Workload Identity Agent Initialization

### Attestation of OS Integrity and Proof of Residency on Host

As part of system boot/reboot process, boot loader-based measured system boot with remote workload identity manager verification is used to ensure only approved OS is running on an approved hardware platform.

Measurement Collection: During the boot process, the boot loader collects measurements (hashes) of the boot components and configurations.
The boot components are Firmware/BIOS/UEFI, bootloader, OS, drivers, location devices, and initial programs.
All the location devices (e.g., GNSS sensor, mobile sensor) version/firmware in a platform are measured during each boot -- this is a boot loader enhancement.
Any new location device which is hot-swapped in will be evaluated for inclusion only during next reboot.

Log Creation: These measurements are recorded in a log, often referred to as the TCGLog, and stored in the TPM's Platform Configuration Registers (PCRs).

Attestation Report: The TPM generates an attestation report, which includes the signed measurements and the boot configuration log.
The signature of the attestation report (aka quote) is by a TPM attestation key (AK).
This attestation includes data about the TPM's state and can be used to verify that the AK is indeed cryptographically backed by the TPM EK certificate.

Transmission: The attestation report is then sent to an external verifier (Workload Identity Manager), through a secure TLS connection.

Remote Verification: The remote Workload Identity Manager checks the integrity of the attestation report and validates the measurements against known good values from the set of trusted hosts in the shared data store. The shared data store can be split as follows for higher security - (1) Host TPM EKs (e.g., MDM) used by Workload Identity Manager and (2) Host TPM EKs + Geolocation sensor details (e.g., location sensor hardware database). The Workload Identity Manager also validates that the TPM EK certificate has not been revoked and is part of the approved list of TPM EK identifiers associated with the hardware platform. At this point, we can be sure that the hardware platform is approved for running workloads and is running an approved OS.

### Start/Restart time attestation/remote verification of workload identity agent for integrity and proof of residency on Host

As part of workload identity agent start process, Linux Integrity Measurement Architecture (Linux IMA) is used to ensure that only approved executable for agent is loaded.

Measurement collection: For the workload identity agent start case, the agent executable is measured by Linux IMA, for example through cloud init and stored in TPM PCR through tools e.g., Linux ima-evm-utils before it is loaded. For the workload identity agent restart case, it is not clear how the storage in TPM PCR will be accompished - TODO - ideally this should be natively handled in the IMA measurement process with an ability to retrigger on restart on refresh cycles.

Local Verification: Enforce local validation of a measurement against an approved value stored in an extended attribute of the file.

TPM attestation and remote Workload Identity Manager verification:

* Workload Identity Agent generates a private/public key pair and attestation key (AK) using TPM for proof of residency on H.

* Workload Identity Agent sends the public key and AK attestation parameters (PCR quote, workload attestation public key, etc.) and EK certificate to the Workload Identity Manager.

* Workload Identity Manager inspects EK certificate. If CA path exists, and the EK certificate was signed by any chain in CA path, validation passes.

* If validation passed, the Workload Identity Manager generates a credential activation challenge. The challenge's secret is encrypted using the EK public key and separately using the workload identity agent public key.

* Workload Identity Manager sends challenge to workload identity agent.

* Workload Identity Agent decrypts the challenge's secret.

* Workload Identity Agent sends back decrypted secret.

* Workload Identity Manager verifies that the decrypted secret is the same it used to build the challenge.

* Workload Identity Manager creates a SPIFFE ID along with the SHA-256 sum of the TPM AK public key appended with the SHA-256 sum of the workload identity agent public key. Workload Identity Manager stores workload identity agent SPIFFE ID mapping to TPM AK public key in a shared data store.

# Geolocation Manager and Host Composition change tracking

Geolocation Manager runs outside of host -- besides the location from device location sources (e.g., GNSS), it will connect to mobile location service providers (e.g., Telefonica) using GSMA location API (gsma-loc). This described process below is run periodically (say every 5 minutes) to check if the host composition has changed.

* Workload Identity Agent periodically gathers host composition details (e.g. SIM card, location sensor) and sends to
Geolocation Manager.

* Geolocation Manager can cross verify that the components of the host are still intact or if anything is plugged out. Plugging out components can decrease the quality of location. Host composition comprises TPM EK, GNSS sensor hardware id, Mobile sensor hardware id, Mobile-SIM IMSI, etc. Refer to Host Composition Table for further details. Note that e-SIM does not have the plugging out problem like standard SIM but could be subject to e-SIM swap attack.

## Workload Identity Agent Geolocation Workflow
This described process below is run periodically (say every 1 minute) to check if the host's location has changed and get an attested location.

* Workload Identity Agent gathers the location from host-local location sensors (e.g., GNSS) and/or location providers (e.g. Google, Apple). Location has a quality associated with it. For example, IP address-based location is of lower quality as compared to other sources. The location is signed by TPM AK along with a timestamp. Workload Identity Agent provides the signed location to Workload Identity Manager using a nonce protocol to prevent replay attacks.

* Workload Identity Manager verifies the TPM AK of the signed location from the workload identity agent and provides it to Geolocation Manager.

* Geolocation Manager derives a combined location, including location quality, from various location sensors for a host with multiple location sensors -- this includes the gathered location from workload identity agent running on host. As an example, GNSS is considered less trustworthy as compared to mobile.

* Geolocation Manager composite location comprises combined geolocation (which includes location quality), host composition (TPM EK, mobile-SIM, etc.), and time from a trusted source.

* Geolocation Manager converts the composite location to a geographic boundary comprising of city, state and country.

* Geolocation Manager signs the geographic boundary with a private key. The public key certificate of Geolocation Manager is in a public, trusted, transparent ledger such as a certificate transparency log. Geolocation Manager provides the signed geographic boundary to the Workload Identity Manager.

* Workload Identity Manager generates a host/workload geographic boundary token using the following fields - (1) issue time, (2) expiry time, (3) monotonically increasing nonce for troubleshooting, (4) Host TPM EK, (5) geographic boundary from geolocation manager, (6) workload agent ID (7) workload IDs (applicable to thick clients) - and attests it using its private key generating a host/workload geographic boundary token.

* The geographic boundary token is returned to the workload identity agent. The public key certificate of Workload Identity Manager is in a public, trusted, transparent ledger such as a certificate transparency log and verifiable by the Workload Identity Agent.

**Privacy centric design option**: Workload Identity Agent converts the gelocation to a geographic boundary comprising of city, state and country, before sending it to the workload identity manager. This way, the workload identity manager does not have access to the exact location of the host. The geographic boundary token is still signed by the Geolocation Manager and Workload Identity Manager.

**Mobile network trust design option**: The mobile network operator can provide the location of the host to the Geolocation Manager, which can then derive the geographic boundary. This is useful for mobile devices that may not have GNSS sensors or when GNSS is not available (e.g., indoors) or when GNSS (e.g. GPS) location is subject to spoofing. The mobile network operator can provide the location of the host based on the mobile network's knowledge of the device's location, which is more trustworthy than the device's own location sensors.

## Workload Public Key Attestation and Remote Verification - Key Steps - This is the current workflow used by workload identity agent with TPM plugin

Workload Identity Agent ensures that workload connects to it on a host-local socket (e.g., Unix-domain socket). Workload Identity Agent generates private/public key pair for workload. Workload Identity Agent signs the workload public key with its TPM AK. Workload Identity Agent sends the signed workload public key along with its SPIFFE ID. Note that the TPM AK is already verified by the Workload Identity Manager as part of the workload identity agent attestation process, establishing proof of residency of workload identity agent to host.

Workload Identity Manager gets the workload identity agent TPM AK public key from the SPIFFE ID by looking it up in the shared data store. Workload Identity Manager verifies the workload public key signature using the TPM AK public key. Workload Identity Manager then sends an encrypted challenge to the workload identity agent. The challenge's secret is encrypted using the workload public key.

Workload Identity Agent decrypts the challenge using its workload private key and sends the response back to the Workload Identity Manager.

Workload Identity Manager verifies that the decrypted secret is the same it used to build the challenge. It then issues workload id (e.g. SPIFFE ID) for workload public key. The workload is signed by the workload identity manager and contains the workload public key and TPM AK.

Workload gets the its private key and workload ID from Workload Identity Agent.


# Data Plane - Networking Protocol Changes
Workload ID (e.g. SPIFFE ID) and host/workload geographic boundary token, needs to be conveyed to the peer during connection establishment. The connection is end-to-end across proxies like:

## Using TLS
HTTP session termination (SASE firewall, API gateways, etc.) - terminate and re-establish TLS.

RDP latest version - terminate and re-establish TLS; TCP/IP.

SCTP session termination (Mobile network SASE firewall, etc.) - terminate and re-establish TLS; SCTP/IP; Does not use TCP or UDP.

NFS - terminate and re-establish TLS; TCP/IP.

## Not Using TLS
SSH tunnel (jump hosts, etc.) - terminate and re-establish SSH; TCP/IP; Does not use TLS.

IPsec tunnel (router control plane, etc.) - terminates IPsec tunnel and forwards encapsulated traffic; IP; Does not use TLS.

## Approaches
Enhance HTTP headers to convey Workload ID and host/workload geographic boundary token. This is in the initial focus given the popularity of HTTP. Benefits (1) This will cover Workload Identity Agent AI MCP protocol which uses HTTP 2.0. (2) Unlike TLS, HTTP headers are not terminated by proxies like API gateways, so the WID and host/workload geographic boundary token can be conveyed end-to-end.

Enhance TLS to convey Workload ID and host/workload geographic boundary token.

Enhance SSH/IPsec to convey Workload ID and host/workload geographic boundary token.

# Data Plane - HTTP header enhancement
A new HTTP header field 'X-Workload-Geo-ID' is proposed for conveying the host/workload geographic boundary token. The header fields are designed to be cryptographically verifiable, ensuring that the information is trustworthy and can be validated by intermediate proxies and servers.

## Thick client workload - Laptop/mobile host (e.g. microsoft teams laptop/desktop app), Data center host (e.g. microsoft teams server)

The following steps describe the end-to-end workflow for a thick client workload (e.g., Microsoft Teams client) and a data center host (e.g., Microsoft Teams server) using the proposed HTTP header enhancements:

* Workload (e.g. microsoft teams client) gets Oauth bearer token for the cloud application (e.g. microsoft teams server) from the Authentication/Authorization server using the user credentials and workload credential using private key JWT (https://oauth.net/private-key-jwt/). Private key JWT is alternative to shared client secret Oauth mechanism.

* Workload contacts the workload agent to
  * Append the X-Workload-Geo-ID header field to the HTTP request, which contains (1) Current Host/workload geographic boundary token. (2) current timestamp (3) monotonically increasing nonce for troubleshooting.
  * Sign the modified HTTP request using the workload identity agent private key.

* Intermediate proxies (e.g., API gateways, SASE firewalls) inspect the X-Workload-Geo-ID header field and perform the following checks:
  * Verify that the host/workload geographic boundary token in the header is valid by verifying the signature against the workload identity manager public key and that the token has not expired.
  * Verify that the workload agent ID in the host/workload geographic boundary token matches a allowed workload agent ID.
  * Verify that the HTTP request signature in the host/workload geographic boundary token is valid by verifying it against the workload agent public key.
  * If the verification passes, the request is forwarded to the destination server. If the verification fails, the request is dropped, and an error response is generated.

* The server or Intermediate proxy can enforce policies based on the following fields in the host/workload geographic boundary token in X-Workload-Geo-ID header
  * Host TPM EK, Workload Agent ID, geographic boundary and destination URL.

* The server can verify the X-Workload-Geo-ID header field by performing the following additional checks
  * The server verifies that host/workload geographic boundary token has its workload ID. It may be possible that the workload ID may have been key rotated - as long as the previous workload ID matches, it is acceptable.

## Thin client workload - Laptop/mobile host (e.g. microsoft teams browser app), Data center host (e.g. microsoft teams server)

* The key differences as compared to the thick client workload are:
  * The browser extension, on behalf of the thin client, connects to the workload identity agent running on the host (e.g., laptop/mobile) to sign the HTTP request with the workload identity agent private key.
  * The server does not need to verify the workload ID in the host/workload geographic boundary token, as the workload ID is not present in the token. The server or intermediate proxy can still enforce policies based on the host TPM EK, workload agent ID, geographic boundary, and destination URL.

# Token Format

# Host/Workload Geographic Boundary Token as SPIFFE JWT-SVID

The host/workload geographic boundary token is issued as a SPIFFE JWT-SVID, following the SPIFFE JWT-SVID standard [spiffe-jwt-svid]. This enables cryptographically verifiable claims about a host's geographic boundary, workloads running on the host, and hardware roots of trust, using a format interoperable with SPIFFE-based systems. The JWT is signed by the Workload Identity Manager and is conveyed as a compact string (e.g., in the `X-Workload-Geo-ID` HTTP header).

## JWT-SVID Structure

A SPIFFE JWT-SVID consists of three parts:
- **Header**: Specifies the signing algorithm, token type, and optionally a key ID.
- **Payload**: Contains the claims, including standard SPIFFE JWT-SVID claims and custom claims for geographic boundary attestation.
- **Signature**: Cryptographic signature over the header and payload, created using the issuer's private key.

### JWT-SVID Header Example
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-1234"
}
```

### JWT-SVID Payload Example
```json
{
  "sub": "spiffe://example.org/host/123e4567-e89b-12d3-a456-426614174000",
  "aud": ["https://service.example.com"],
  "iat": 1718473200,
  "exp": 1718476800,
  "jti": "jwt-unique-id-5678",
  "nonce": 1234567890,
  "host_geographic_boundary": "San Jose, California, USA",
  "host_hardware_details": {
    "host_tpm_endorsement_public_key": "MIIBIjANBgkqh..."
  }
}
```

**Signature:**
```
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Field Explanations

**Standard SPIFFE JWT-SVID Claims:**
- `sub`: The SPIFFE ID of the host or workload this token represents.
- `aud`: Audience(s) for which this token is intended.
- `iat`: Issued at time (UNIX timestamp).
- `exp`: Expiration time (UNIX timestamp).
- `jti`: JWT ID (unique identifier).

**Custom Claims for Geographic Boundary:**
- `nonce`: Unique, random unsigned long integer for replay protection.
- `host_geographic_boundary`: The host's geographic boundary (city, state, country).
- `host_hardware_details`: Object with hardware root of trust details (e.g., TPM EK public key).

# Authorization Policy Implementers

Policy implementers use attested geographic boundary from Workload to make decisions. Example implementers:

* Web application firewall, e.g., Istio Ingress/Egress Gateway

* SaaS application.

* K8s node agent.

* OS process scheduler.

If the policy implementer is at the SaaS application level, things are simpler. However, if it is pushed down to, say, K8s or OS process scheduler or JVM class loader/deserializer, then malware can be prevented (similar to a code-signed application).

# Security Considerations

The proposed framework introduces several security considerations that must be addressed to ensure the integrity and trustworthiness of geofencing:

- **TPM and Hardware Trust**: The security of the solution depends on the integrity of the TPM and other hardware roots of trust. Physical attacks, firmware vulnerabilities, or supply chain compromises could undermine attestation. Regular updates, secure provisioning, and monitoring are required.

- **Geolocation Spoofing**: Location sensors (e.g., GPS) are susceptible to spoofing or replay attacks. Use of cryptographically authenticated signals (e.g., Galileo GNSS, mobile network) and cross-verification with multiple sources can mitigate this risk.

- **SIM and e-SIM Attacks**: Physical SIM removal or e-SIM swap attacks can break the binding between device and location. Continuous monitoring of device composition and periodic re-attestation are recommended.

- **Software Integrity**: The geolocation agent and supporting software must be protected against tampering. Use of Linux IMA, secure boot, and measured launch environments helps ensure only approved software is executed.

- **Communication Security**: All attestation and geolocation data must be transmitted over secure, authenticated channels (e.g., TLS) to prevent interception or manipulation.

- **Policy Enforcement**: The enforcement of geofence policies must be robust against attempts by malicious workloads or agents to bypass controls. Policy decisions should be based on verifiable, signed attestation evidence.

- **Time Source Integrity**: Trusted time sources are necessary to prevent replay attacks and ensure the freshness of attestation data.

- **Data Store Security**: The shared data store containing trusted host compositions must be protected against unauthorized access and tampering, using encryption and access controls. The shared data store can be split as follows for higher security - 1) Host EKs (e.g., MDM) used by Workload Identity Manager and 2) Host EKs + Geolocation sensor details (e.g., location sensor hardware datastore)

By addressing these considerations, the framework aims to provide a secure and reliable foundation for verifiable geofencing in diverse deployment environments.

# IANA Considerations

This document has no IANA actions.

# Appendix - Items to follow up

## Restart time attestation/remote verification of workload identity agent for integrity and proof of residency on Host

For the workload identity agent restart case, it is not clear how the storage in TPM PCR will be accompished - TODO - ideally this should be natively handled in the IMA measurement process with an ability to retrigger on restart on refresh cycles.

# Acknowledgments
{:numbered="false"}

The authors thank the members of the WIMSE working group and the broader trusted computing and workload identity communities for their feedback and contributions. Special thanks to the Trusted Computing Group (TCG), the SPIFFE/SPIRE open-source community, and industry partners for foundational work and ongoing collaboration.





