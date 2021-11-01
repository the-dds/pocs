In 2021 we've started looking at the [OMG Data Distribution Service (DDS)](https://www.omg.org/dds-directory/) standards and its implementations from a security angle. This page contains a summary of our work.

Being DDS an little-discussed by critical technology, in the light of our findings we encourage other researchers, DDS users and implementors to contribute to increasing its security and community awareness.
- [What is DDS?](#what-is-dds)
- [DDS Standards and Implementations](#dds-standards-and-implementations)
- [Who Uses DDS?](#who-uses-dds)
- [What are the Findings?](#what-are-the-findings)
	- [Network Attack Surface](#network-attack-surface)
	- [Configuration Files Attack Surface](#configuration-files-attack-surface)
	- [Fuzzing Network Deserialization](#fuzzing-network-deserialization)
- [PoCs](#pocs)
- [Talks and Publications](#talks-and-publications)
- [Who we are?](#who-we-are)
- [Advisories](#advisories)

# What is DDS?

DDS is a middleware technology that enables crucial technologies like autonomous driving, healthcare machinery, military tactical systems, or missile launch stations. Designed around industrial-level requirements, DDS sits deep in the control network, allowing an arbitrary number of endpoints like sensors or actuators to communicate transparently, with an abstract API based on familiar data type specifications (e.g., C structs) and simple function calls, regardless of the complexity of the data.

```C
Snippet
```

# DDS Standards and Implementations

The OMG Data-Distribution Service for Real-Time Systems® (DDS®) is the first open international middleware standard directly addressing publish-subscribe communications for real-time and embedded systems.

- Specifications: https://www.dds-foundation.org/omg-dds-standard/

Focusing on [OMG members vendors](https://www.omg.org/dds-directory/vendor/list.htm), we looked at the 3 most popular open-source implementations:

- Fast-DDS by eProsima: https://github.com/eProsima/Fast-DDS
- OpenDDS by OCI: https://github.com/objectcomputing/OpenDDS
- CycloneDDS by Eclipse (ADLINK): https://github.com/eclipse-cyclonedds/cyclonedds

and the 3 most popular commercial distributions:

- ConnexDDS by RTI:
  - https://www.rti.com/free-trial
  - https://github.com/rticommunity/rticonnextdds-examples
- GurumDDS by Gurum Networks: https://www.gurum.cc/freetrial
- CoreDX DDS by Twin Oaks Computing: http://www.twinoakscomputing.com/coredx/download

# Who Uses DDS?

Notably, DDS is used by NASA at the KSC, by SIEMENS for smart grid applications, by Volkswagen and Bosch for autonomous valet parking systems, by NAV CANADA for ATC, and by the Robot Operating System 2 (ROS2) to control industrial and consumer robots.

Other applications are listed in the [DDS Foundation Wiki](https://www.omgwiki.org/ddsf/doku.php?id=ddsf:public:applications:start).

# What are the Findings?

We found vulnerabilities in the OMG specifications and in most of the implementations, both closed and open source. We release part of the code that helped us run our research project.

## Network Attack Surface

Being DDS mainly a network-based protocol, the network is also the main attack surface. We approached DDS from the bottom up, and the first thing we did was writing a [Scapy layer to dissect and forge RTPS frames](https://github.com/secdev/scapy/pull/3403) (RTPS, or Real-Time Publish Subscribe is the foundation of DDS). Inspecting DDS and RTPS frame is the best way to learn the packet structure. Although network fuzzing wasn't directly effective, it greatly helped us to master the tiny details of DDS. This led us to find an reflection/amplification vulnerability (CVE-2021-38487, CVE-2021-38429) in the standard, which allows an attacker to redirect flood an arbitrary host.

## Configuration Files Attack Surface

DDS configuration is highly dependent on XML, JSON, YAML, or similar formats, which make them another attack vector. By writing a Radamsa-based file fuzzer we found various parsing vulnerabilities (CVE-2021-38437, CVE-2021-38441, CVE-2021-38443, CVE-2021-38427, CVE-2021-38433) as well as one of the implementations using an old, unmaintained and vulnerable XML library (CVE-2021-38437), so an attacker can use a malicious configuration file to gain initial access.

## Fuzzing Network Deserialization 

We focus on fuzzing the message interpretation routines in all implementations, how to pick good fuzz targets, and prepare them for popular frameworks like OSS-Fuzz and UnicornAFL (for closed-source implementations).

We're working on releasing fuzzers into OSS-Fuzz for the following implemetations:

- Fast-DDS: https://github.com/eProsima/Fast-DDS/tree/master/fuzz
- CycloneDDS: https://github.com/google/oss-fuzz/tree/master/projects/cyclonedds
- OpenDDS: WIP

# PoCs

Coming soon

# Talks and Publications

- [Black Hat Europe 2021](https://www.blackhat.com/eu-21/briefings/schedule/index.html#the-data-distribution-service-dds-protocol-is-critical-lets-use-it-securely-24934), The Data Distribution Service (DDS) Protocol is Critical: Let's Use it Securely! *Nov 11th, 2021, London, UK.*
- [S4x22](https://s4xevents.com/speakers/), A Security Deep Dive Into The DDS Protocol. *Jan 27th, 2022, Miami, FL, USA.*

# Who we are?

Trend Micro Research has been leading this research, with the invaluable contribution of a great team, comprising researchers and experts from various realms.

- Ta-Lun Yen, Threat Researcher, [TXOne Networks](https://www.txone-networks.com/)
- [Federico Maggi](https://maggi.cc), Senior Researcher, [Trend Micro Research](https://www.trendmicro.com/en_us/research.html)
- Erik Boasson, Senior Technologist and lead [CycloneDDS](https://github.com/eclipse-cyclonedds/cyclonedds) developer, [ADLINK Technology](https://www.adlinktech.com/)
- [Victor Mayoral-Vilches](https://cybersecurityrobotics.net/author/victor/), Robotics Security Researcher, [Alias Robotics](https://aliasrobotics.com)
- [Mars Cheng](https://mars-cheng.github.io/blog/about/), Threat Researcher, [TXOne Networks](https://www.txone-networks.com/)
- Patrick Kuo, Threat Researcher, [TXOne Networks](https://www.txone-networks.com/)
- Chizuru Toyama, Staff Engineer, [TXOne Networks](https://www.txone-networks.com/)

# Advisories

| CVE            | Scope              | CWE      | Notes                     |
|----------------|--------------------|----------|---------------------------|
|                | **OMG (specs)**    | **CWE-406**  | **Network reflection**        |
| CVE-2021-38487 | RTI ConnextDDS     |          | Patched                   |
| CVE-2021-38429 | OCI OpenDDS        |          | Patched                   |
| N/A            | Eclipse CycloneDDS |          | Already mitigated         |
| N/A            | GurumDDS           |          | Already mitigated         |
| N/A            | eProsima Fast-DDS  |          | [WIP Mitigation](https://github.com/eProsima/Fast-DDS/issues/2267)     | 
| N/A            | Twin Oaks CoreDX   |          | WIP Mitigation            |
| CVE-2021-38445 | OCI OpenDDS        | CWE-130  | Failed assertion          |
| CVE-2021-38447 | OCI OpenDDS        | CWE-405  | Resource exhaustion       |
| CVE-2021-38435 | RTI ConnextDDS     | CWE-131  | Seg.fault via network     |
| CVE-2021-38423 | GurumDDS           | CWE-131  | Seg.fault via network     |
| CVE-2021-38439 | GurumDDS           | CWE-122  | Heap-overflow via network |
| CVE-2021-38437 | GurumDDS           | CWE-1104 | Unmaintained XML lib.     |
| CVE-2021-38441 | CycloneDDS         | CWE-123  | Heap-write in XML parser  |
| CVE-2021-38443 | CycloneDDS         | CWE-228  | 8-bytes heap-write in XML parser        |
| CVE-2021-38427 | RTI ConnextDDS     | CWE-121  | Stack overflow in XML parser |
| CVE-2021-38433 | RTI ConnextDDS     | CWE-121  | Stack overflow in XML parser |