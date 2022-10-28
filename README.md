# D2FAP (Dean Dorton Forensic Artifact Parser)
This is a simple Powershell script designed to aid in the triage portion of an incident response.  The idea is to automate the parsing of many commonly collected artifacts and provide some high level signatures to define events that may be of import to the event at hand.

In the digital forensics world, there are many great resources on operating system artifacts that can be used during an investigation.  
There are also many great open-source tools that can be used to parse out the artifacts for review by an analyst.  

The challenge in the incident response process typically comes back to the analysis of these individual artifacts in a timely manner to gain a broader understanding of an attack.  **This is especially burdensome when there is a complex attack afoot - such as a ransomware investigation that touches many systems.**  In fact , each system alone can contain **several Gigabytes of artifacts and hundreds of thousands of events** to review.  Imagine trying to understand an attack that touches 10-20 systems during a time crucial response effort for which it is imperative to understanding key questions such as:

How did they get in?

What systems did they interact with?

What did they look at or take?

What accounts were compromised?

Creating a unified timeline to quickly and accurately understand the answers to these questions and help guide the response effort is crucial.  While many tools exist to parse individual artifacts, few tools exist to aggregate these to create a unified timeline for a single system, or across many systems.  To be clear - there are such tools, some are complex to setup and learn to use and some take a long time to process the data in a meaningful way.

The goal of this tool is to provide a simple, easy to use script to help automate the use of many of these great tools, combine the results into a unified timeline, and apply some simple logic (detections) for the analyst to review and gain a better understanding of broad based malware attacks.  In our experience, we have used this tool to churn through 26 GB of artifacts from 22 systems in around 2 hours to produce a useful unified timeline.

## Requirements
This tool runs only only PowerShell v5 and requires Administrative rights (Requirement of PowerForensics for parsing MFT).  On the backend - this tools utilizes many external tools to be able to perform the actual parsing of the data.  These tools include:

**PowerForensics** (https://github.com/Invoke-IR/PowerForensics) by Invoke-IR - PowerForensics provides an all in one platform for live disk forensic analysis

**powershell-yaml** (https://github.com/cloudbase/powershell-yaml) by CloudBase - PowerShell CmdLets for YAML format manipulation

**Browsing History View** (https://www.nirsoft.net/utils/browsing_history_view.html) by NirSoft - A utility that reads the history data of different Web browsers (Mozilla Firefox, Google Chrome, Internet Explorer, Microsoft Edge, Opera) and displays the browsing history of all these Web browsers in one table

**ShellBagExplorer** (https://ericzimmerman.github.io/#!index.md) by Eric Zimmerman - ShellBags Explorer, command line edition, for exporting shellbag data

Each one of these tools will be checked for availability upon each run and either installed or downloaded (to a working folder of your choice).

## Process
This tool is designed to aid in a very specific part of the overall response process.  Sepcifically - after initial containment - there is an opportunity to start to understand the scope of the incident.  Sometimes this can be done by looking through network firewall logs - but those arent available in all instances.  In many cases, responders need to rely on artifacts that reside on the disks of the attacked systems.

In these cases, responders will use tools to collect data directly from the hosts before shutting them down.  There are many great tools that can be used in this part of the process:

**LRC (Live Response Collection)** - https://www.brimorlabsblog.com/2019/04/live-response-collection-cedarpelta.html

**KAPE (Kroll Artifact Parser and Extractor)** - Kroll developed tool - https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape

**GRR (Google Rapid Response)** - https://github.com/google/grr

All of these tools do a great job of collecting specific files and artifacts from hosts that can be used to understand the incident.  Typically, they will collect artifacts such as:

* Master File Table
* USRJournal
* AMCache
* SRUMDB
* Prefecth Files
* Registry Hives, User Hives
* Internet History Files
* Windows Event Logs

These are the files that D2FAP will focus on parsing.  Once collected, and before a more substantial investigation that can take weeks gets underway (full disk forensics, detailed reporting) - making sense of all these immediately collected artifacts is essential to the response effort.  This is where D2FAP lives:

#IMAGE INSERT

During the collection of the logs, often times analysts are already making note of some kinds of indicators of compromise.  These are simple things like:

* Unusual Files on servers
* Malware Alerts
* Users who executed malware
* IP Addresses/Domains in Security Logs

It is important to note these items, as the data collection process is underway.  All of these items can be used to apply to artifacts during the script analysis process and help analysts more quickly understand the incident.

## D2FAP Usage
### Execution
The script will need to be executing under a PowerShell v5 with administrative rights.  Please note - the max number of threads should be kept in line with the amount of memory available with the host.  Each thread can use from 1-2 GB of RAM; the default of 11 is used on a host with 32GB of RAM with the analysis never exceeding 22 GB of usage. 

```
.\D2fap.ps1 -Config c:\Users\User\config.json
```

If the script is run without the config paramter - the user will be prompted for each of the elements (incident suspected start, end times, known breached accounts, etc).

### Config File
D2FAP ships with an example config file to be filled out prior to execution.  Please note - this config has comments inline to explain each option - however - JSON does not support comments.  Do NOT include the comments in your config

```
{
	'case_id':  'YYYY.MM-CLIENT_SHORT', #Identifier for case - internal tracking only
	'company_short':  'SHORTNAME', #Shortname for affected business unit, company
	'analysis_type':  'strict', #Two options (fuzzy or strict) This applies to provided file name IoC's.  Fuzzy matches will match entire path
	'input_data_dir':  'E:\\vol\\volitile_data', # Full path to unzipped collected artifacts, organized with Folder for each system
	'output_data_dir': 'c:\\users\\USERNAME\\Desktop', #Full path to where you want output of script saved
	'incident_start_time': 'MM/DD/YYYY 00:00:01', #Approximate date/time of when incident started.  If unknown, usually start with 30 days
	'incident_end_time': 'MM/DD/YYYY 23:59:59', #When the incident was contained
	'compromised_accounts': 'administrator,bob', #Legitiamte accounts known to be compromised by threat actor.
	'bad_files': 'netscan.exe,opera.exe', #Filenames known to be dropped by threat actor - RANSOMWARE.exe
	'bad_ip_hostnames': '1.2.3.4,2.3.4.5,COMPUTERNAME', #Known C2 servers, RDP Connections from Compromised Hosts
	'max_threads': '11', #Max number of background jobs (each job is the processing of a systems artifacts) to process at a single time
	'sleep_timer': '500', #Do not change
	'temp_directory': 'c:\\Temp', #Working data directory.  Some files will be copied to here, as well as required binaries
	'yaml_signature_directory': 'c:\\Temp\\yamls' #Make sure you use the FULL PATH to the yaml signatures
}
```

INPUT_DATA_DIR - Make sure that you artifacts are organized into a directory of folders by system, where the folders are named by system:

```
- INPUT_DATA_DIR
-- SYSTEM1_MMDDYYY
--- ARTIFACTS
-- SYSTEM2_MMDDYYY
--- ARTIFACTS
..
```

### YAML Signatures

Highly influenced by the SIGMA signatures project (https://github.com/SigmaHQ/sigma) - the purpose of this is to provide a VERY simple signature format that can be applied to the artifacts we are parsing and some some high level intelligence to direct analysts input.  The eventual goal will be to directly support SIGMA - however the engine required to parse and apply the logic of the signatures was a little more complex (and strong/flexible) we were able to support at this time.

```
detection: DOCM File Written in Temp Outlook Directory
source: File System
filename: MFT
tags: Initial Execution,Macros,Dropped to Disk,Email
category: Execution
operator: all
signatures:
- Content.Outlook
- .docm
```

**DETECTION** - Name that appears in the Detection field of the Timeline if matched

**SOURCE** - Which artifact supported by signatured to parse (BrowserHistory, Event Logs, File System)

**FILENAME** - Comma seperated strings to match filename to be parsed.  Security.evtx, MFT (for Master File Table).  For event logs, will match on partial file name.

**TAGS** - Comma seperated list of TAG's to be applied to detected event

**CATEGORY** - Comma seeated list of Kill Chain stage to be applied to the detected event

**OPERATOR** - ANY or ALL - Simple if any signautres need to match or all

**SIGNATURES** - Any number of strings that need to be matched when parsing artifacts

## Output
The script will output all files into a directory specified in the output_data_dir paramter of the config file.  Two directories will be created:

MFT - Each systems parsed MFT (within the incident range provided) will be output in this directory
system_timelines - Each complete individual timeline (per system) will be output into this directory.

Additional files will be created that will include unified results:

**all_av_detections.csv** - Event logs for supported Antivirus (Defender, SentinelOne, Crowdstrike, Cisco AMP, Symantec) will be parsed and detections will be combined in a unified file.  This can be extremely useful to get a good idea of the overall range of an event, as often there are detections/warning not initially heeded related to the incident.

**complete_incident_timeline.csv** - Unified timeline of all detections/events for all systems.

**file_system_shellbags.csv** - Shellbag events for all systems for the provided timeline.  This can be useful in the response process to understand what MAY have been viewed by a threat actor.

### Reviewing the Unified Timeline
The unified timeline is meant to strip Gigabytes of data into a format easier to review.  That being said - some very useful features can be a bit noisy on the first pass through of analysis.  Using the filtering options for the 'Date' and 'Detection Type' columns can be extremly useful to aid in the analysis process.

Additionaly, you can pay special attention to 'NOTEs' added to some detections that can be useful.

**SUSPICIOUS HOURS** - Indicates events that occur after normal business hours - between 10 PM and 6 AM

**COMPROMISED ACCOUNT** - Added to selected detections if the account name is one provided in the config input for known compromised accounts

### IMPORTANT NOTE - 
This script should be considered only a BEST EFFORT attempt (not forensically sound) to quickly understand the scope of a broad based event.  Becuase something does not show up in the script does not mean it is not in the underlying artifact - a full forensic review should still be comepleted to fully understand the event.  However - this can be VERY useful to understanding the scope and impact of an incident in a timely manner to help direct initial response efforts.

## Current Detections
### File System Detections

```
- POSSIBLE Staging Area Observed - In some cases, threat actors may stage fileson the computers they are interacting with.  By reviewing the MFT and detecting directories where 100 or more files are created in a small time frame, we can observed potential staging areas to understand what threat actors have taken (even if they are deleted from disk - they may still be listed as orphaned objects in the MFT).

- Archive File Created - After staging files for exfiltration, threat actors may compress the files to save outbound bandwidth

- Compromised Account Profile File Activity - Based upon the input known compropmised usernames - this lists file system activity related to the user profile path only of the compromised users.  This is based on a partial match - so a user "ADMIN" will also match the profile path "ADMINISTRATOR".

- BINARY DROPPED in Compromised User Profile - Any time a executable file (detected by file extension according to the MFT) is dropped in the user profile path of input known compromised users.

- POSSIBLE BLOODHOUND OUTPUT DETECTED - Finds file names in the MFT that would match the default patterns used by Bloodhound (both the ZIP and the JSON).



Detection Events that indicate interactive file access.....these will be wrapped up in a CSV report at the end to help understand the possible scope of identifiable ACCESSED/AQCUIRED (but not neccessarily exfiltrated) files the threat actor interacted with.  NOTE - just becuase something is NOT listed here - you can't assume it has not been accessed or aqcuired.  Absence of evidence is not evidence of confidentiality (as there are many ways to access.acquire files that will not leave evidence of access).

- Open file or folder
- Select file in open/save dialog-box
- View Folder in Explorer
- SHELLBAG

```

### YAML Signature Detections
Please note - some of these detections have a wide array of detected 'signatures'.  For instance, the single signature 'Web History - LOTS URL Detected' contains a listing of over 60 domains listed by the LOTS Project.  Current YAML Detections include:

```
Malware Detection - Cisco Amp Behavioral Protection
Malware Detection - Cisco Amp Malicious Activity Protection
Malware Detection - Cisco Amp System Process Protection
Malware Detection - Cisco Amp Script Protection
Malware Detection - Crowdstrike
Malware Detection - Sentinel One
Malware Detection - Symantec Endpoint Protection
Malware Detection - Windows Defender
Defense Evasion - Windows Defender Disabled
Bloodhound CLI Arguments Detected
Collection Tool Detected
Exfiltration Tool Detected
Share Access Detected
Remote Access Tool Detected
ScreenConnect Incoming Connection
Web History - LOTS URL Detected
Credential Theft Technique - CompSpec VSSAdmin Service 1
Credential Theft Technique - CompSpec VSSAdmin Service 2
Credential Theft Technique - CompSpec VSSAdmin Service 3
Credential Theft Technique - CompSpec VSSAdmin Service 4
Cred Dump Tools Dropped Files
DLL File Written in ProgramData Directory
DLL File Written in Public Directory
DUMP File Written in ProgramData Directory
DUMP File Written in Public Directory
DUMP File Written in System32 Directory
EXE File Written in ProgramData Directory
EXE File Written in Public Directory
MIMIKATZ Cli Arguements Detected
Minidump Usage - Possible Credential Theft Technique
Powershell Veeam Backup Credential Access
ZIP File Written in ProgramData Directory
ZIP File Written in public Directory
ZIP File Written in System32 Directory
Powershell Antiforensics Commands Detected
Powershell Windows Defender Disabled Attempt
Event Logs Cleared
Data Discovery Tool Detected
Filesystem Activity - File Opened LNK Created
Port Scanning Tool Detected
Powershell Discovery Command Detected
Interesting Technique - Certutil Decode
DOCM File Written in Temp Outlook Directory
EXE File Written in ProgramData Directory
Execution Technique - ODBCCONF REGSRV
Powershell Possible Hacking Tool Execution
XLSM File Written in Temp Outlook Directory
Exfiltration Domains Detected in Browser History
Scheduled Task Created
New Service Installed
Remote Desktop - Inbound Connection
Remote Desktop - Outbound Connection
Application Installation
Application Popup Detected
Suspicious Download File Extension with Bits
Bits Suspicious Task Added by Powershell
BAT File Written in Startup Directory
EXE File Written in Startup Directory
HTA File Written in Startup Directory
Local Admin Group Updated
Local Group Modified
Local User Account Added
Local Account Password Reset
Powerview Add-DomainObjectAcl DCSync AD Extend Right
VBS File Written in Startup Directory
Powershell - Possible Mimikatz Execution Attempt
Powershell Encoded Command Execution
```

### Outbound RDP Events
Any systems that display more than 1 outbound RDP event during the time frame of the attack will be listed at the end of script execution in a table.  The significance of this can be to help identify hosts the threat actors used as thier base of operations, and using RDP to move laterally to other systems.

These systems are VERY important from an analysis perspective to understand what the threat actor did, tools used, and possible exfiltration.  Additionally, the BMCCache on these hosts is important to anlyze as well and can provide useful information (such as in the case the threat actor uses private mode for browsing/exfil and you need to recover the URL).
