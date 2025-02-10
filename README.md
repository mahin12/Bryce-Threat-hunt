🚨 Bryce Montgomery Threat Hunt Report


🔍 Overview
This report details an insider threat investigation into Bryce Montgomery, a high-privilege executive suspected of unauthorized data access and exfiltration. The investigation revealed the use of steganography, file compression, and guest workstations to bypass security controls and evade Data Loss Prevention (DLP) monitoring.
---

🔬 Investigation & Findings
1️⃣ Tracking Bryce's File Access
Initial analysis of DeviceFileEvents revealed Bryce accessed critical corporate documents such as:
Q1-2025-ResearchAndDevelopment.pdf
Q2-2025-HumanTrials.pdf
Q3-2025-AnimalTrials-SiberianTigers.pdf
Hash (b3302e58be7eb604fda65d1d04a5e18325c66792) confirmed file integrity across different devices.
KQL Query:
kql
Copy
Edit
DeviceFileEvents
| where DeviceName == "corp-ny-it-0334"
| where InitiatingProcessAccountName == "bmontgomery"
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, SHA1
2️⃣ Identifying Other Workstations Used
The DeviceFileEvents table was queried for instances of the same file hashes appearing on multiple workstations.
lobby-fl2-ae5fc was flagged, confirming Bryce accessed corporate files on a guest workstation.
KQL Query:
kql
Copy
Edit
DeviceFileEvents
| where PreviousFileName contains "Q1-2025-ResearchAndDevelopment.pdf" 
   or PreviousFileName contains "Q2-2025-HumanTrials.pdf" 
   or PreviousFileName contains "Q3-2025-AnimalTrials-SiberianTigers.pdf"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, PreviousFileName, FileName
3️⃣ Detecting Steganography Usage
DeviceProcessEvents logs revealed Bryce used steghide.exe on lobby-fl2-ae5fc to embed corporate PDFs into personal images.
Affected images:
suzie-and-bob.bmp
bryce-and-kid.bmp
bryce-fishing.bmp
KQL Query:
kql
Copy
Edit
DeviceProcessEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where ProcessCommandLine contains "steghide.exe"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
✅ Resulting File Path: C:\ProgramData\bryce-fishing.bmp

4️⃣ Identifying Compression & Exfiltration Attempts
Logs confirmed 7z.exe was used to compress the stego images into a zip file (marketing_misc.zip).
The final destination of the zip file was F:\ on the lobby workstation, indicating an attempt to move the data outside company systems.
KQL Query:
kql
Copy
Edit
DeviceFileEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where InitiatingProcessCommandLine contains "suzie-and-bob.bmp" 
   or InitiatingProcessCommandLine contains "bryce-fishing.bmp" 
   or InitiatingProcessCommandLine contains "bryce-and-kid.bmp"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine, FolderPath, SHA256
✅ Compressed File Location: F:\marketing_misc.zip

5️⃣ Linking Bryce Directly to the Exfiltration
The final piece of evidence tied Bryce directly to the exfiltration:
The SHA256 hash (707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71) confirmed that a process linked to Bryce interacted with the stolen data.
A critical log at 2025-02-05T08:57:32.2582822Z showed marketing_misc.zip being moved into Bryce’s personal folder before potential exfiltration.
KQL Query:
kql
Copy
Edit
DeviceFileEvents
| where SHA256 contains "07236346de27a608698b9e1ffef07b1987aa7fe8473aac171e66048ff322e2d6"
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, PreviousFileName, InitiatingProcessCommandLine, FolderPath, SHA256
✅ Final Exfiltration Path: F:\Bryce Personal\marketing_misc.zip

🚀 Conclusion & Response Actions
Key Evidence Summary:
🚨 Finding	📝 Details
Workstation Used	corp-ny-it-0334, lobby-fl2-ae5fc
Steganography Tool	steghide.exe
Compromised Files	Q1-2025-ResearchAndDevelopment.pdf, Q2-2025-HumanTrials.pdf, Q3-2025-AnimalTrials-SiberianTigers.pdf
Stego Image Output	C:\ProgramData\bryce-fishing.bmp
Compressed Archive	marketing_misc.zip (Stored at F:\)
Timestamp of Exfiltration	2025-02-05T08:57:32.2582822Z
SHA256 Hash of Process	707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71
