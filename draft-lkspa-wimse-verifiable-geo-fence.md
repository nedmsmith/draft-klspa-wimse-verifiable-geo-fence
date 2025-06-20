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

In the context of the SPIFFE/SPIRE architecture (spire), the SPIFFE/SPIRE Agent includes a new geolocation plugin -- this is depicted in the figure below. The Agent is a daemon running on bare-metal Linux OS host (H) as a process with direct access to TPM (root permissions for TPM 2.0 access may be needed for certain Linux distributions for certain H hardware configurations).
The Agent, using the geolocation plugin, can gather the location from host-local location sensors (e.g., GNSS).
The Agent has a TPM plugin (spire-tpm) which interacts with the TPM.
The Workload Identity Manager (SPIFFE/SPIRE server) is running in a cluster which is isolated from the cluster in which the Agent is running.

[Figure -- Modified SPIFFE-SPIRE architecture with new geolocation plugin](https://github.com/nedmsmith/draft-klspa-wimse-verifiable-geo-fence/blob/main/pictures/spiffe-spire.svg)

# Control Plane - End-to-End Workflow

The end-to-end workflow for the proposed framework consists of several key steps, including attestation for system bootstrap and Workload Identity Agent initialization, Workload Identity Agent geolocation and geofencing processing, workload attestation, and remote verification.

[Figure -- End-to-end Workflow](https://github.com/nedmsmith/draft-klspa-wimse-verifiable-geo-fence/blob/main/pictures/end-to-end-flow.svg)

## Attestation for System Bootstrap and Workload Identity Agent Initialization

### Attestation of OS Integrity and Proof of Residency on Host

As part of system boot/reboot process, boot loader-based measured system boot with remote Workload Identity Manager verification is used to ensure only approved OS is running on an approved hardware platform.

**Measurement Collection**: During the boot process, the boot loader collects measurements (hashes) of the boot components and configurations.
The boot components are Firmware/BIOS/UEFI, bootloader, OS, drivers, location devices, and initial programs.
All the location devices (e.g., GNSS sensor, mobile sensor) version/firmware in a platform are measured during each boot -- this is a boot loader enhancement.
Any new location device which is hot-swapped in will be evaluated for inclusion only during next reboot.

**Log Creation**: These measurements are recorded in a log, often referred to as the TCGLog, and stored in the TPM's Platform Configuration Registers (PCRs).

**Attestation Report**: The TPM generates an attestation report, which includes the signed measurements and the boot configuration log.
The signature of the attestation report (aka quote) is by a TPM Attestation Key (AK).
This attestation includes data about the TPM's state and can be used to verify that the AK is indeed cryptographically backed by the TPM Endorsement Key (EK) certificate.

**Transmission**: The attestation report is then sent to an external verifier (Workload Identity Manager), through a secure TLS connection.

**Remote Verification**: The remote Workload Identity Manager checks the integrity of the attestation report and validates the measurements against known good values from the set of trusted hosts in the shared data store. The shared data store can be split as follows for higher security - (1) Host TPM EK (e.g., MDM) shared data store used by Workload Identity Manager and (2) Host TPM EK + Geolocation sensor detail shared data store. The Workload Identity Manager also validates that the TPM EK certificate has not been revoked and is part of the approved list of TPM EK identifiers associated with the hardware platform. At this point, we can be sure that the hardware platform is approved for running workloads and is running an approved OS.

### Start/Restart time attestation/remote verification of Workload Identity Agent for integrity and proof of residency on Host - Linux IMA and Workload Identity Agent public/private key attestation are newly added

The Workload Identity Agent is a process with elevated privileges with access to TPM and location sensor hardware.

**Measurement Collection**: For the Workload Identity Agent start case, the Agent executable is measured by Linux IMA, for example through cloud init and stored in TPM PCR through tools e.g., Linux ima-evm-utils before it is loaded. For the Workload Identity Agent restart case, it is not clear how the storage in TPM PCR will be accompished - ideally this should be natively handled in the IMA measurement process with an ability to retrigger on restart on refresh cycles (see TODO 1).

**Local Verification**: Enforce local validation of a measurement against an approved value stored in an extended attribute of the file.

**TPM attestation and remote Workload Identity Manager verification**:

Step 1:
  * Workload Identity Agent generates a TPM Attestation Key (AK) for proof of residency on Host.

  * Workload Identity Agent sends the AK attestation parameters (PCR quote, attestation public key, etc.) and TPM EK certificate to the Workload Identity Manager.

  * Workload Identity Manager inspects TPM EK certificate. If CA path exists, and the TPM EK certificate was signed by any chain in CA path, validation passes.

  * If validation passed, the Workload Identity Manager generates a credential activation challenge. The challenge's secret is encrypted using the TPM EK public key.

  * Workload Identity Manager sends challenge to Workload Identity Agent.

  * Workload Identity Agent connects to the TPM to decrypt the challenge's secret using the TPM AK private key stored in the TPM.

  * Workload Identity Agent sends back decrypted secret.

  * Workload Identity Manager verifies that the decrypted secret is the same it used to build the challenge.

  * Workload Identity Manager issues a Workload Identity Agent AK ID using the TPM AK public key and TPM EK certificate.

Step 2:
  * Workload Identity Agent generates a private/public key pair.

  * Workload Identity Agent connects to the TPM to sign the public key with the TPM AK private key.

  * Workload Identity Agent sends the public key signed by TPM AK, to the Workload Identity Manager.

  * Workload Identity Manager ensures the TPM AK is associated with a temporary Workload Identity Agent ID.

  * If validation passed, the Workload Identity Manager generates a credential activation challenge. The challenge's secret is encrypted using the Workload Identity Agent public key.

  * Workload Identity Manager sends challenge to Workload Identity Agent.

  * Workload Identity Agent decrypts the challenge's secret.

  * Workload Identity Agent sends back decrypted secret.

  * Workload Identity Manager verifies that the decrypted secret is the same it used to build the challenge.

  * Workload Identity Manager issues the Workload Identity Agent ID using the Workload Identity Agent public key, TPM AK signature of Workload Identity Agent public key and Workload Identity Agent AK ID.

## Workload Public Key Attestation and Remote Verification - Key Steps - This is slightly modified from the current TPM plugin flow - Workload Identity Agent public/private key attestation instead of TPM AK attestation is the change

* Workload Identity Agent ensures that workload connects to it on a host-local socket (e.g., Unix-domain socket). Workload Identity Agent generates private/public key pair for the workload. Workload Identity Agent signs the workload public key with its private key. Workload Identity Agent sends the signed workload public key along with its Workload Identity Agent ID to Workload Identity Manager. Note that the Workload Identity Agent ID is already verified by the Workload Identity Manager as part of the Workload Identity Agent attestation process, establishing proof of residency of Workload Identity Agent to host.

* Workload Identity Manager verifies that the Workload Identity Agent ID TPM EK is present in the Host TPM EK shared data store. Workload Identity Manager verifies the workload public key signature using the Workload Identity Agent public key. Workload Identity Manager then sends an encrypted challenge to the Workload Identity Agent. The challenge's secret is encrypted using the workload public key.

* Workload Identity Agent decrypts the challenge using the generated workload private key and sends the response back to the Workload Identity Manager.

* Workload Identity Manager verifies that the decrypted secret is the same it used to build the challenge. It then issues workload id (e.g. SPIFFE ID) for workload public key. The workload is signed by the Workload Identity Manager and contains the workload public key and Workload Identity Agent ID.

* Workload gets its private key and workload ID from Workload Identity Agent.

## Geolocation Manager and Host Composition change tracking

Geolocation Manager runs outside of host -- besides the location from device location sources (e.g., GNSS), it will connect to mobile location service providers (e.g., Telefonica) using GSMA location API (gsma-loc). This described process below is run periodically (say every 5 minutes) to check if the host hardware composition has changed. Host hardware composition comprises TPM EK, GNSS sensor hardware id, Mobile sensor hardware id (IMEI), Mobile-SIM IMSI. Note that this workflow is feasible only in enterprise environments where the host hardware is owned and managed by the enterprise.

* Workload Identity Agent periodically gathers host composition details (e.g. Mobile sensor hardware id (IMEI), Mobile-SIM IMSI) and sends to Geolocation Manager.

* Geolocation Manager can cross verify that the components of the host are still intact or if anything is plugged out. Plugging out components can decrease the quality of location. Host hardware composition comprises TPM EK, GNSS sensor hardware id, Mobile sensor hardware id (IMEI), Mobile-SIM IMSI. Note that e-SIM does not have the plugging out problem like standard SIM but could be subject to e-SIM swap attack.

## Workload Identity Agent Geolocation Gathering Workflow

This described process below is run periodically (say every .5 minutes or 30 seconds for frequently mobile hosts such as smartphones; say every 5 minutes for less frequently mobile hosts such as laptops; say every 50 minutes for stationary hosts) to check if the host's location has changed and get an attested location.

* Workload Identity Agent gathers the location (1) directly from host-local location sensors (e.g., GNSS) which provide a hardware attested location and/or (2) using existing Operating System (OS) APIs which gathers a composite location from location providers (e.g. Google, Apple). Location has a quality associated with it. For example, IP address based or Wi-Fi based location is of lower quality as compared to other sources.

* For each of the registered workload IDs (or website URL), based on the configured location policy (precise, approximated within a fixed radius, geographic region based indicating city/state/country - TODO 2), the location is converted appropriately to a workload id specific location. For thin clients (browser clients), the workload id is website URL. This ensures that the privacy of the workload is preserved, while still allowing for geolocation enforcement.

* All the above details are captured in the host/workload geographic boundary information which contains the following fields:
  * Workload ID specific location details for each client workload where each entry contains:
    * client workload ID - relevant for thick clients (e.g. Microsoft Teams client)
    * server workload ID (or website URL) - relevant for all clients (thick or thin)
    * client location type (e.g. precise, approximated, geographic region based)
    * client location (e.g. latitude/longitude, city/state/country)
    * client location quality (e.g. GNSS, mobile network, Wi-Fi, IP address)
  * Time of collection (timestamp)

* It is important to note that the host/workload geographic boundary information is kept in the Workload Identity Agent memory and is not stored on disk. The information is refreshed periodically to ensure that the location is up-to-date. This information is used only by workloads in the host and never leaves the host.

* If the location is gathered only using existing OS APIs, it may be done in the workload (thick client) or browser extension (thin client). The host/workload geographic boundary information is stored in thick client memory (relevant only to specific client) or browser extension memory (relevant to all thin clients and indexed using user in OAuth bearer token/server website URL).

# Data Plane - HTTP Networking Protocol

A new HTTP header field 'X-Workload-Geo-ID' is proposed for conveying the host/workload geographic boundary information. A new HTTP header field 'X-Request-Signature' is proposed for conveying the signature of the HTTP request. The signature is generated by the Workload Identity Agent using the Workload Identity Agent Private Key. The following steps describe the end-to-end workflow for HTTP requests between client workloads (e.g. Microsoft Teams thick client app, Microsoft Teams thin client browser app) and server workloads (e.g. Microsoft Teams server), including intermediate proxies (e.g., API gateways, SASE firewalls):

* Client workload gets OAuth bearer token for the server workload from the Authentication/Authorization server.

* Client workload (browser extension for thin client) contacts the Workload Identity Agent to get the latest host/workload geographic boundary information relevant to it. If the location is gathered only using existing OS APIs, it may be done in the workload (thick client) or browser extension (thin client). The client workload (browser extension for thin client) constructs a X-Workload-Geo-ID extension header containing the following fields:
  * The latest host/workload geographic boundary information relevant to the client workload ID (thick clients) or user in OAuth bearer token/server website URL (thin clients).
  * The current timestamp.
  * A unique nonce which is monotonically increasing (for replay protection and troubleshooting).

* Client workload then appends the X-Workload-Geo-ID header field to the HTTP request.

* Client workload passes the hash of the HTTP request to the Workload Identity Agent for signature. The Workload Identity Agent signs the HTTP Request using the Workload Identity Agent Private Key and returns the signature of the HTTP request to the workload.
  * The resulting signature is included in a separate header, such as `X-Request-Signature`.
  * The Workload Identity Agent ID is also included in the `X-Request-Signature` header.
  * The public key used to verify the signature can be derived using the Workload Identity Agent ID. This enables recipients (intermediate proxies or server workloads) to validate the authenticity of the signature and the binding to the specific Workload Identity Agent.

* Intermediate proxies (e.g., API gateways, SASE firewalls) inspect the X-Workload-Geo-ID and X-Request-Signature header fields and perform the following checks:
  * Verify that the Workload Identity Agent ID in the X-Request-Signature header matches a configured Workload Identity Agent ID. They can retrieve the host TPM EK certificate from the Workload Identity Agent ID and compare it with the host TPM EK certificate in the shared data store.
  * Verify that the HTTP request signature in the X-Request-Signature header is valid by verifying it against the Workload Identity Agent Public Key in the X-Request-Signature header.
  * Verify that the timestamp in the X-Workload-Geo-ID header is within an acceptable range (e.g., 5 minutes).
  * Verify that the nonce in the X-Workload-Geo-ID header is unique and predominantly increasing to prevent replay attacks.

* Note that these HTTP extension header checks can be performed by the server as well, but it is more efficient to do them at the intermediate proxy level and aligns well with how Zero Trust Network Access (ZTNA) solutions operate. If the verification passes, the request is forwarded to the destination server. If the verification fails, the request is dropped, and an error response is generated.

* Intermediate proxies (e.g., API gateways, SASE firewalls) or server workloads can use the host TPM EK certificate in the Workload Identity Agent ID to retrieve the mobile geolocation sensor IMEI/IMSI from the Host TPM EK + Geolocation sensor detail shared data store. Using the IMEI/IMSI, they can retrieve the location of the host from the mobile network operator's location service. This is useful for mobile devices that may not have GNSS sensors or when GNSS is not available (e.g., indoors) or when GPS/GNSS location is subject to spoofing. As compared to IP address, Wi-Fi and GPS/GNSS geolocation methods, mobile network location services provide a more reliable and cryptographically verifiable location. Based on the mobile geolocation and existing geolocation in the X-Workload-Geo-ID header, a more accurate composite location can be constructed.

* Intermediate proxies (e.g., API gateway, Firewall) or server workloads can enforce policies based on:
  * Workload Identity Agent ID (running on the same host as the client workload),
  * user in OAuth bearer token,
  * server website URL,
  * client workload location,
  * client workload location type (e.g. precise, approximated, geographic region based),
  * client workload location quality (e.g. GNSS, mobile network, Wi-Fi, IP address).

* For thick clients, server workload verifies that the client workload ID in the X-Workload-Geo-ID header matches the expected client workload ID.

# Solution mapping back to Problem Statements

* **Bearer Tokens**, **PoP Token**, **PoP via Mutual TLS**, **Host TPMs for Signature** challenges are addressed
  * by the use of Workload Identity Agent public/private key attestation, which provides a cryptographically verifiable proof of residency on host and workload identity. The Workload Identity Agent generates a public/private key pair for each workload and signs the workload public key with its private key. The Workload Identity Manager verifies the signature using the Workload Identity Agent Public Key, ensuring that the workload is running on a trusted host.
  * by signing HTTP requests with the Workload Identity Agent Private Key, which provides a scalable and cryptographically verifiable proof of residency on host and workload identity. The signature is verified by the intermediate proxies (e.g., API gateways, SASE firewalls) or server workloads using the Workload Identity Agent Public Key.

* **IP Address-Based Location** and **Wi-Fi-Based Location** challenges are addressed
  * by the use of a combination of host-local location sensors (e.g., GNSS) and mobile network location services, with direct hardware-based attestation, which provide a more reliable and cryptographically verifiable location than IP address or Wi-Fi-based methods.

# Data Plane - Other (non HTTP) Networking Protocols

## Using TLS
RDP - terminate and re-establish TLS; TCP/IP.

SCTP - terminate and re-establish TLS; SCTP is directly over IP; Does not use TCP or UDP.

NFS - terminate and re-establish TLS; TCP/IP.

## Not Using TLS
SSH tunnel (jump hosts, etc.) - terminate and re-establish SSH; TCP/IP; Does not use TLS.

IPsec tunnel (router control plane, etc.) - terminates IPsec tunnel and forwards encapsulated traffic; IP; Does not use TLS.

# Scalability Considerations

Having a geolocation sensor on every host is not scalable from a deployment and management perspective
and can be cost prohibitive.
In the case of end user hosts, the geolocation sensor can be on a mobile host (e.g., smartphone with Mobile network capabilities and optionally GNSS capabilities) which can be leveraged by a laptop/desktop host which is proximal to the mobile host. The mobile host serves as the location anchor host.
In the case of data center hosts, the geolocation sensor can be on a host with Mobile network and/or GNSS capabilities which can be leveraged by other data center hosts. This host serves as the location anchor host.

End user location anchor host - goal is to provide a easy to use wireless solution that can be used by end users without requiring them to install a geolocation sensor on their laptop/desktop host.
* The smartphone can be used as a location anchor host for the laptop/desktop host. The smartphone connects to the laptop/desktop host using Bluetooth Low Energy (BLE) or Ultra-Wideband (UWB) technology and continuously measures the following:
  * signal strength of the laptop/desktop host
  * round trip time (RTT) between the smartphone and laptop/desktop host

Data center location anchor host - goal is to provide a easy to use solution that can be used by data center operators without requiring them to install a geolocation sensor on every data center host.
* Use a software-based cryptographically signed round-trip-time (RTT) measurement between the location anchor host and other data center hosts. One possible implementation to add a host proximity plugin to the SPIFFE/SPIRE agent, which can measure RTT between the location anchor host and other data center hosts. The RTT measurement can be used to determine the proximity of the other data center hosts to the location anchor host. The tradeoff is that software-based RTT measurement may not provide sub-microsecond accuracy due to inherent software jitter, but it can still provide a reasonable approximation of the proximity of the other data center hosts to the location anchor host.

# Authorization Policy Implementers

Policy implementers use attested geographic boundary from Workload to make decisions. Example implementers:
* Intermediate proxies (e.g., API gateway, Firewall)
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

- **Data Store Security**: The shared data stores containing trusted host compositions and location sensor details must be protected against unauthorized access and tampering, using encryption and access controls.

By addressing these considerations, the framework aims to provide a secure and reliable foundation for verifiable geofencing in diverse deployment environments.

# IANA Considerations

This document has no IANA actions.

# Appendix - Items to follow up

## TODO 1: Restart time attestation/remote verification of workload identity agent for integrity and proof of residency on Host

For the workload identity agent restart case, it is not clear how the storage in TPM PCR will be accompished - ideally this should be natively handled in the IMA measurement process with an ability to retrigger on restart on refresh cycles.

## TODO 2: Location privacy options

The current approach includes some location privacy options for the geolocation in the host/workload geographic boundary information. This may need to be expanded further in the future.

# Acknowledgments
{:numbered="false"}

The authors thank the members of the WIMSE working group and the broader trusted computing and workload identity communities for their feedback and contributions. Special thanks to the Trusted Computing Group (TCG), the SPIFFE/SPIRE open-source community, and industry partners for foundational work and ongoing collaboration.







