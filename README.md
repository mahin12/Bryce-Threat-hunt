<!DOCTYPE html>
<html lang="en">

<body>

<h1>🚨 Bryce Montgomery Threat Hunt Report</h1>

<h2>🔍 Overview</h2>
<p>This report details an insider threat investigation into Bryce Montgomery, a high-privilege executive suspected of unauthorized data access and exfiltration. The investigation revealed the use of steganography, file compression, and guest workstations to bypass security controls and evade Data Loss Prevention (DLP) monitoring.</p>

<hr>

<h2>🔬 Investigation & Findings</h2>

<h3>1️⃣ Tracking Bryce's File Access</h3>
<p>Initial analysis of <code>DeviceFileEvents</code> revealed Bryce accessed critical corporate documents such as:</p>
<ul>
    <li><code>Q1-2025-ResearchAndDevelopment.pdf</code></li>
    <li><code>Q2-2025-HumanTrials.pdf</code></li>
    <li><code>Q3-2025-AnimalTrials-SiberianTigers.pdf</code></li>
</ul>
<p>Hash (<code>b3302e58be7eb604fda65d1d04a5e18325c66792</code>) confirmed file integrity across different devices.</p>

<pre>
<code>
DeviceFileEvents
| where DeviceName == "corp-ny-it-0334"
| where InitiatingProcessAccountName == "bmontgomery"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, SHA1
</code>
</pre>

<hr>

<h3>2️⃣ Identifying Other Workstations Used</h3>
<p>The <code>DeviceFileEvents</code> table was queried for instances of the same file hashes appearing on multiple workstations.</p>
<p><strong>lobby-fl2-ae5fc</strong> was flagged, confirming Bryce accessed corporate files on a guest workstation.</p>

<pre>
<code>
DeviceFileEvents
| where PreviousFileName contains "Q1-2025-ResearchAndDevelopment.pdf"
   or PreviousFileName contains "Q2-2025-HumanTrials.pdf"
   or PreviousFileName contains "Q3-2025-AnimalTrials-SiberianTigers.pdf"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, PreviousFileName, FileName
</code>
</pre>

<hr>

<h3>3️⃣ Detecting Steganography Usage</h3>
<p><code>DeviceProcessEvents</code> logs revealed Bryce used <code>steghide.exe</code> on <code>lobby-fl2-ae5fc</code> to embed corporate PDFs into personal images.</p>

<p><strong>Affected images:</strong></p>
<ul>
    <li><code>suzie-and-bob.bmp</code></li>
    <li><code>bryce-and-kid.bmp</code></li>
    <li><code>bryce-fishing.bmp</code></li>
</ul>

<pre>
<code>
DeviceProcessEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where ProcessCommandLine contains "steghide.exe"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
</code>
</pre>

<p>✅ <strong>Resulting File Path:</strong> <code>C:\ProgramData\bryce-fishing.bmp</code></p>

<hr>

<h3>4️⃣ Identifying Compression & Exfiltration Attempts</h3>
<p>Logs confirmed <code>7z.exe</code> was used to compress the stego images into a zip file (<code>marketing_misc.zip</code>).</p>
<p>The final destination of the zip file was <code>F:\</code> on the <strong>lobby workstation</strong>, indicating an attempt to move the data outside company systems.</p>

<pre>
<code>
DeviceFileEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where InitiatingProcessCommandLine contains "suzie-and-bob.bmp"
   or InitiatingProcessCommandLine contains "bryce-fishing.bmp"
   or InitiatingProcessCommandLine contains "bryce-and-kid.bmp"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine, FolderPath, SHA256
</code>
</pre>

<p>✅ <strong>Compressed File Location:</strong> <code>F:\marketing_misc.zip</code></p>

<hr>

<h3>5️⃣ Linking Bryce Directly to the Exfiltration</h3>
<p>The final piece of evidence tied Bryce directly to the exfiltration:</p>
<ul>
    <li>The <strong>SHA256 hash</strong> (<code>707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71</code>) confirmed that a <strong>process linked to Bryce interacted with the stolen data</strong>.</li>
    <li>A critical log at <strong>2025-02-05T08:57:32.2582822Z</strong> showed <code>marketing_misc.zip</code> being moved into <strong>Bryce’s personal folder</strong> before potential exfiltration.</li>
</ul>

<pre>
<code>
DeviceFileEvents
| where SHA256 contains "07236346de27a608698b9e1ffef07b1987aa7fe8473aac171e66048ff322e2d6"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, PreviousFileName, InitiatingProcessCommandLine, FolderPath, SHA256
</code>
</pre>

<p>✅ <strong>Final Exfiltration Path:</strong> <code>F:\Bryce Personal\marketing_misc.zip</code></p>

<hr>

<h2>🚀 Conclusion & Response Actions</h2>

<h3>🔹 Key Evidence Summary:</h3>

<table border="1">
<tr>
    <th>🚨 Finding</th>
    <th>📝 Details</th>
</tr>
<tr>
    <td><strong>Workstation Used</strong></td>
    <td><code>corp-ny-it-0334</code>, <code>lobby-fl2-ae5fc</code></td>
</tr>
<tr>
    <td><strong>Steganography Tool</strong></td>
    <td><code>steghide.exe</code></td>
</tr>
<tr>
    <td><strong>Compromised Files</strong></td>
    <td><code>Q1-2025-ResearchAndDevelopment.pdf</code>, <code>Q2-2025-HumanTrials.pdf</code>, <code>Q3-2025-AnimalTrials-SiberianTigers.pdf</code></td>
</tr>
<tr>
    <td><strong>Stego Image Output</strong></td>
    <td><code>C:\ProgramData\bryce-fishing.bmp</code></td>
</tr>
<tr>
    <td><strong>Compressed Archive</strong></td>
    <td><code>marketing_misc.zip</code> (Stored at <code>F:\</code>)</td>
</tr>
<tr>
    <td><strong>Timestamp of Exfiltration</strong></td>
    <td><code>2025-02-05T08:57:32.2582822Z</code></td>
</tr>
<tr>
    <td><strong>SHA256 Hash of Process</strong></td>
    <td><code>707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71</code></td>
</tr>
</table>

<hr>

<p>⚠️ <strong>Confidential – For Internal Use Only</strong></p>

</body>
</html>
