# Securing DDS

This repository is intended to host material in support to our conference talks.
## Talks and Publications

- [Black Hat Europe 2021](https://www.blackhat.com/eu-21/briefings/schedule/index.html#the-data-distribution-service-dds-protocol-is-critical-lets-use-it-securely-24934), The Data Distribution Service (DDS) Protocol is Critical: Let's Use it Securely! *Nov 11th, 2021, London, UK.*
- [ROS Industrial Conference 2021](https://rosindustrial.org/events/2021/12/1/ros-industrial-conference-2021), Breaking ROS 2 security assumptions: Targeting the top 6 DDS implementations. *Dec 1-2, 2021, Fraunhofer IPA, Stuttgart, Germany*
- [S4x22](https://s4xevents.com/speakers/), A Security Deep Dive Into The DDS Protocol. *Jan 27th, 2022, Miami, FL, USA.*
## PoCs

Coming soon

---

**In 2021 we've started looking at the [OMG Data Distribution Service (DDS)](https://www.omg.org/dds-directory/) standards and its implementations from a security angle. Being DDS a little-discussed yet critical technology, in the light of our findings we encourage other researchers, DDS users and implementors to promote security awareness about DDS and its ecosystem.**

---

- [Securing DDS](#securing-dds)
  - [Talks and Publications](#talks-and-publications)
  - [PoCs](#pocs)
  - [What is DDS?](#what-is-dds)
  - [DDS Standards and Implementations](#dds-standards-and-implementations)
  - [Who Uses DDS?](#who-uses-dds)
  - [What are the Findings?](#what-are-the-findings)
  - [Network Attack Surface](#network-attack-surface)
  - [Configuration Files Attack Surface](#configuration-files-attack-surface)
  - [Continuous Fuzzing](#continuous-fuzzing)
  - [Who we are?](#who-we-are)
  - [Advisories](#advisories)

---

## What is DDS?

DDS is a middleware technology that enables crucial technologies like [autonomous driving](https://www.rti.com/blog/2016/02/24/dds-proof-points-for-autonomous-cars/), [healthcare machinery](https://www.rti.com/ge2015dec), military tactical systems, or [missile launch stations](https://www.aerospacetestinginternational.com/news/products-services/orion-prepares-for-space-with-advanced-data-acquisition-system.html). Designed around industrial-level requirements, DDS sits deep in the control network, allowing an arbitrary number of endpoints like sensors or actuators to communicate transparently, with an abstract API based on familiar data type specifications (e.g., C structs) and simple function calls, regardless of the complexity of the data.

```C++
using namespace org::eclipse::cyclonedds;

int main()
{
  dds::domain::DomainParticipant participant(0);
  dds::pub::Publisher publisher(participant));
  dds::topic::Topic<HelloWorld> topic(participant, "HelloWorld");
  dds::pub::DataWriter<HelloWorld> writer(publisher, topic);
  
  unsigned i = 0;
  while (true)
  {
    HelloWorld msg(i++, "Hello, world!");
    writer << msg;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  
  return 0;
}
```

## DDS Standards and Implementations

The OMG Data-Distribution Service for Real-Time Systems® (DDS®) is the first open international middleware standard directly addressing publish-subscribe communications for real-time and embedded systems. The DDS [specifications](https://www.dds-foundation.org/omg-dds-standard/) are public.

Focusing on [OMG members vendors](https://www.omg.org/dds-directory/vendor/list.htm), we looked at the 3 most popular open-source implementations:

- [Fast-DDS](https://github.com/eProsima/Fast-DDS) by [eProsima](https://www.eprosima.com/)
- [OpenDDS](https://github.com/objectcomputing/OpenDDS) by [OCI](https://objectcomputing.com/)
- [CycloneDDS](https://github.com/eclipse-cyclonedds/cyclonedds) by [Eclipse](https://www.eclipse.org) ([ADLINK](https://www.adlinktech.com/))

and the 3 most popular commercial distributions:

- ConnextDDS by RTI:
  - [ConnextDDS](https://www.rti.com/free-trial)
  - [RTI ConnextDDS Connectors](https://github.com/rticommunity/rticonnextdds-connector)
- [GurumDDS](https://www.gurum.cc/freetrial) by Gurum Networks
- [CoreDX DDS](http://www.twinoakscomputing.com/coredx/download) by Twin Oaks Computing

## Who Uses DDS?

Notably, DDS is used by [NASA at the KSC](https://www.omgwiki.org/ddsf/doku.php?id=ddsf:public:applications:aerospace_and_defense:nasa_launch_and_control_systems), by SIEMENS for smart grid applications, by Volkswagen and Bosch for autonomous valet parking systems, by NAV CANADA for ATC, and by the Robot Operating System 2 (ROS2) to control industrial and consumer robots.

DDS is the foundation of other industry standards including [OpenFMB](https://openfmb.ucaiug.org/), [Adaptive AUTOSAR](https://www.autosar.org/), [MD PnP](https://mdpnp.org/), [GVA](https://www.slideshare.net/RealTimeInnovations/generic-vehicle-architecture-dds-at-the-core), [NGVA](https://www.natogva.org/), and [ROS 2](https://design.ros2.org/articles/ros_on_dds.html).

Other applications are listed in the [DDS Foundation Wiki](https://www.omgwiki.org/ddsf/doku.php?id=ddsf:public:applications:start).

## What are the Findings?

We found vulnerabilities in the OMG specifications and in most of the implementations, both closed and open source. We release part of the code that helped us run our research project.

## Network Attack Surface

Being DDS mainly a network-based protocol, the network is also the main attack surface. We approached DDS from the bottom up, and the first thing we did was writing a [Scapy layer to dissect and forge RTPS frames](https://github.com/secdev/scapy/pull/3403) (RTPS, or Real-Time Publish Subscribe is the foundation of DDS). Inspecting DDS and RTPS frame is the best way to learn the packet structure. Although network fuzzing wasn't directly effective, it greatly helped us to master the tiny details of DDS. This led us to find an reflection/amplification vulnerability (CVE-2021-38487, CVE-2021-38429) in the standard, which allows an attacker to redirect flood an arbitrary host.

## Configuration Files Attack Surface

DDS configuration is highly dependent on XML, JSON, YAML, or similar formats, which make them another attack vector. By writing a Radamsa-based file fuzzer we found various parsing vulnerabilities (CVE-2021-38437, CVE-2021-38441, CVE-2021-38443, CVE-2021-38427, CVE-2021-38433) as well as one of the implementations using an old, unmaintained and vulnerable XML library (CVE-2021-38437), so an attacker can use a malicious configuration file to gain initial access.

## Continuous Fuzzing

We focus on fuzzing the message interpretation routines and configuration parsing in all implementations, how to pick good fuzz targets, and prepare them for popular frameworks like OSS-Fuzz and UnicornAFL (for closed-source implementations).

We're working on releasing fuzzers into OSS-Fuzz for the following implementations:

- Fast-DDS: [https://github.com/eProsima/Fast-DDS/tree/master/fuzz](https://github.com/eProsima/Fast-DDS/tree/master/fuzz)
- CycloneDDS: [https://github.com/google/oss-fuzz/tree/master/projects/cyclonedds](https://github.com/google/oss-fuzz/tree/master/projects/cyclonedds)
- OpenDDS: WIP

## Who we are?

Trend Micro Research has been leading this research, with the invaluable contribution of a great team, comprising researchers and experts from various realms.

- [Ta-Lun Yen](https://twitter.com/evanslify/), Threat Researcher, [TXOne Networks](https://www.txone-networks.com/)
- [Federico Maggi](https://maggi.cc), Senior Researcher, [Trend Micro Research](https://www.trendmicro.com/en_us/research.html)
- [Erik Boasson](https://github.com/eboasson), Senior Technologist and lead [CycloneDDS](https://github.com/eclipse-cyclonedds/cyclonedds) developer, [ADLINK Technology](https://www.adlinktech.com/)
- [Victor Mayoral-Vilches](https://cybersecurityrobotics.net/author/victor/), Robotics Security Researcher, [Alias Robotics](https://aliasrobotics.com)
- [Mars Cheng](https://mars-cheng.github.io/blog/about/), Threat Researcher, [TXOne Networks](https://www.txone-networks.com/)
- Patrick Kuo, Threat Researcher, [TXOne Networks](https://www.txone-networks.com/)
- [Chizuru Toyama](https://www.linkedin.com/in/chizuru-toyama-0a070427/), Staff Engineer, [TXOne Networks](https://www.txone-networks.com/)

## Advisories

| CVE            | Scope              | CWE      | Notes                     |
|----------------|--------------------|----------|---------------------------|
| -              | **OMG (specs)**    | **CWE-406**  | **Network reflection**        |
| CVE-2021-38487 | RTI ConnextDDS     | CWE-406  | Patched                   |
| CVE-2021-38429 | OCI OpenDDS        | CWE-406  | Patched                   |
| -              | Eclipse CycloneDDS | -        | Mitigated natively        |
| -              | GurumDDS           | -        | Mitigated natively        |
| Requested      | eProsima Fast-DDS  | CWE-406  | [WIP mitigation](https://github.com/eProsima/Fast-DDS/issues/2267)     |
| Requested      | Twin Oaks CoreDX   | CWE-406  | WIP mitigation            |

| CVE            | Scope              | CWE      | Notes                     |
|----------------|--------------------|----------|---------------------------|
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
