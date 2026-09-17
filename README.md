# Cloud-Native Security Operations Center (SOC) Honeypot Lab

This project implements a fully cloud-native Security Operations Center (SOC) sandbox and honeypot deployment within Microsoft Azure. The architecture is engineered to ingest raw event log pipelines, track unauthorized brute-force authentications globally, and synthesize live geospatial threat intelligence using Microsoft Sentinel.

## Architectural Overview

The environment is built inside an isolated Azure resource group containing the following active components:
* **Honeypot Virtual Machine:** A public-facing Windows Server Datacenter instance configured with open Network Security Group (NSG) rules to attract automated external brute-force vectors.
* **Log Analytics Workspace:** The central ingestion engine running Azure Monitor Agent pipelines to collect local Windows Security Event logs (specifically filtering for RDP Event ID 4625).
* **Microsoft Sentinel (SIEM):** The Security Information and Event Management platform running customized analytics queries to coordinate threat detection.
* **Geospatial Watchlists:** A custom-mapped dictionary mapping raw incoming IP addresses to specific longitude, latitude, city, and country records.
* **Azure Workbook Dashboard:** A dynamic visualization surface compiling live attack coordinates onto an interactive global map.

## Data Pipeline and Processing Logic

1. **Ingestion:** Attackers locate the open RDP port on the VM, triggering repeated failed authentication attempts recorded locally under Event ID 4625.
2. **Parsing:** The Azure Log Analytics workspace stream processes the raw logs in real time.
3. **Enrichment:** A customized Kusto Query Language (KQL) pipeline executes an `ipv4_lookup` function against a 55,000-item global Geolocation database watchlist.
4. **Visualization:** The extracted geographic telemetry points (latitude, longitude, and failure counts) are mapped directly into an Azure Monitor Workbook template for immediate security visualization.

## Sample Analytical Logic (KQL)

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, city = cityname, country = countryname
```

## Technical Specifications

* **Cloud Platform:** Microsoft Azure
* **SIEM/SOAR:** Microsoft Sentinel
* **Query Language:** Kusto Query Language (KQL)
* **Log Framework:** Windows Security Logging Infrastructure (Event ID 4625 - An account failed to log on)
