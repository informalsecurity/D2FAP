<#
    .Synopsis
        This is a simple Powershell script designed to aid in the triage portion of an incident response.  The idea is to automate the parsing of many commonly collected artifacts and provide some high level signatures to define events that may be of import to the event at hand
    .Description
        This is a simple Powershell script designed to aid in the triage portion of an incident response.  The idea is to automate the parsing of many commonly collected artifacts and provide some high level signatures to define events that may be of import to the event at hand
    .Example
        powershell D2FAP.ps1
    .Parameter Config
        JSON file with configuration options filled out
    .Notes
        This does NOT help collect artifacts.  You should use a tool like KAPE, LRC, PowerForensics, OR Google Rapid Response Framework to collect artifacts.  They should then be assembled into a single directory, with subfolders named for each computer being analyzed.  The function of this script s to help automate the parsing of the collected artifacts into a unified timeline to help quickly triage malware events where lateral movemement is suspected (like a ransomware event).
#>
[CmdletBinding()]
Param(
    [alias("C")]
    $Config)
#Requires -RunAsAdministrator
#Requires -Version 5.0


If (Test-Path $Config) { 
    #Pull Config File
    $global_config = Get-Content $Config | ConvertFrom-JSON
}

#Get system RAM - Determine MAX Threads Based off of RAM  32 - 6 system, 16 - 3 systems, 8 - 2 Systems
Write-Host "$(Get-Date): ## Starting Analysis"
$ram = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1gb
if ($global_config.max_threads -gt 0) {
    $MaxThreads = $global_config.max_threads
}else {
    $MaxThreads =  [math]::Round($ram / 4)
    #If running in a VM - this does not work, default to 4
    if ($MaxThreads -eq 0) {
        $MaxThreads = 5
    }
}
Write-Host "$(Get-Date): ## Maximum Threads to be processed at any time - $MaxThreads"
if ($global_config.sleep_timer -gt 0) {
     $SleepTimer = $global_config.sleep_timer
}else {
    $SleepTimer = 500
}
$MaxWaitAtEnd = 6000
$i = 0
#HANDLE ERRORS
$ErrorActionPreference = 'SilentlyContinue' 

#Getting all third party pre-requisites
Write-Host "$(Get-Date): ## Checking to see if PowerForensics is Installed"
if (!(Get-Module -ListAvailable -Name PowerForensics)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "$(Get-Date): ## PowerForensics is not installed - Installing PowerForensics"
	Install-Module PowerForensics -Scope CurrentUser
}
Import-Module PowerForensics
#Check for YAML Support - Install-Module powershell-yaml
Write-Host "$(Get-Date): ## Checking to see if YAML Support is Installed"
if (!(Get-Module -ListAvailable -Name powershell-yaml)) {
	Write-Host "$(Get-Date): ## powershell-yaml is not installed - Installing powershell-yaml"
	Install-Module powershell-yaml -Scope CurrentUser
}
Import-Module powershell-yaml
#Currently script should be run from same path as YAML Repo - Future idea to add this as a config or parameter option
if ($global_config.yaml_signature_directory -ne "") {
    if (Test-Path $global_config.yaml_signature_directory) {
        $yaml_path = $global_config.yaml_signature_directory
    } else {
        $yaml_path = Read-Host -Prompt 'Please provide the full path to the YAML signature directory' 
    }
}else {
    $yaml_path = $pwd.Path + "\yamls"
}

Write-Host "$(Get-Date): ## Checking for YAML Signatures in - $yaml_path"
$yaml_files = gci -r -file -include *.yaml $yaml_path
$ycount = $yaml_files.Count
if ($ycount -eq 0) {
    Write-Host "$(Get-Date): ## Loaded $ycount YAML Signatures - Please rerun with correct path to YAML Signatures - Exiting Script"
    Read-Host "Press Enter to Exit this Script and Start Again"
    exit
}
Write-Host "$(Get-Date): ## Loading $ycount  YAML Signatures for processing"
Write-Host "$(Get-Date): ## Checking for Additional Temp Folders and Tools Required"
if (!(test-Path c:\Temp)) {
    New-Item -Path c:\Temp -Name  $system -ItemType "directory"
}
if (!(test-Path c:\Temp\BrowsingHistoryView.exe)) {

	$folder = "c:\Temp\"
	#CHECK FOR Browsing History View
    Write-Host "$(Get-Date): ## Browsing History Viewer is not installed - Installing BHV"
	Invoke-WebRequest -URI "https://www.nirsoft.net/utils/browsinghistoryview.zip" -OutFile $folder"\bhv.zip" -UserAgent "Internet Exploder 5.0"
    Write-Host "$(Get-Date): ## Expanding BHV Explorer Archive"
	Expand-Archive -LiteralPath $folder"\bhv.zip" -DestinationPath $folder
    Move-Item C:\Temp\browsinghistoryview-x64\BrowsingHistoryView.exe C:\Temp\BrowsingHistoryView.exe
    Remove-Item C:\Temp\ShellBagsExplorer\ -Recurse -Force
}
if (!(test-Path c:\Temp\SBECmd.exe)) {
	$folder = "c:\Temp\"
	#CHECK FOR ERICK ZIMMER SHELLBAG EXPLORER TOOL
    Write-Host "$(Get-Date): ## ShellBagExplorer is not installed - Installing ShellBagExplorer"
	Invoke-WebRequest -URI "https://f001.backblazeb2.com/file/EricZimmermanTools/SBECmd.zip" -OutFile $folder"\sbe.zip" -UserAgent "Internet Exploder 5.0"
    Write-Host "$(Get-Date): ## Expanding SHellBag Explorer Archive"
	Expand-Archive -LiteralPath $folder"\sbe.zip" -DestinationPath $folder
    Remove-Item C:\Temp\sbe.zip -Recurse -Force
}



#initialize overall investiation variable
$investigation = @()

if ($global_config.analysis_type -ne '') {
    $global:type_of_analysis = $global_config.analysis_type
} else {
    #Fuzzy or Strict - type of matching to be comeplted
    # This is a hold over from an older verison of this script - check to see if this is still neccessary with new YAML engine
    Do {
        $global:type_of_analysis = Read-Host -Prompt 'Fuzzy analysis (Slower - matches IoC file names as part of full path) or Strict Analysys (Faster - matches IoC file names exactly) - enter "fuzzy" or "strict"' }
    Until((($global:type_of_analysis.ToUpper() -eq "FUZZY") -or ($global:type_of_analysis.ToUpper() -eq "STRICT")))
}



# Show an Open Folder Dialog and return the directory selected by the user.
function Read-FolderBrowserDialog([string]$Message, [string]$InitialDirectory, [switch]$NoNewFolderButton)
{
    $browseForFolderOptions = 0
    if ($NoNewFolderButton) { $browseForFolderOptions += 512 }
    $app = New-Object -ComObject Shell.Application
    $folder = $app.BrowseForFolder(0, $Message, $browseForFolderOptions, $InitialDirectory)
    if ($folder) { $selectedDirectory = $folder.Self.Path } else { $selectedDirectory = '' }
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($app) > $null
    return $selectedDirectory
}

##Get Output Folder If Any
function output_folder() {
    Write-Host "Please provide the path to save the output of the script to"
    Do {
        $global:user_out = Read-Host -Prompt 'Please provide the full path to the directory where you would like the script output saved - leave blank to have output saved to desktop' 
        if (($global:user_out -eq "") -or ($global:user_out -eq $null)) {
             $global:user_out = "aaaa"
        }
        }
    Until((Test-Path -Path $global:user_out) -or ($global:user_out -eq "aaaa"))
}

if ($global_config.output_data_dir -ne '') {
    $global:user_out = $global_config.output_data_dir
} else {
    output_folder
}

#Create Output Folder on Desktop
$dt = Get-Date -Format "yyyy.MM.ddHHmm"
if ($global:user_out -eq "aaaa") { 
    $global:final_output = $env:UserProfile + "\Desktop\IR_" + $dt + "\"
} else {
    $global:final_output = $user_out + "\IR_" + $dt + "\"
}
$mftdir = $global:final_output + "\mft\"
$systimeline = $global:final_output + "\system_timelines\"
New-Item -Path $global:final_output -ItemType Directory | out-null
New-Item -Path $mftdir -ItemType Directory | out-null
New-Item -Path $systimeline -ItemType Directory | out-null

function get_base_path() {
    #GET BASE PATH VARIABLES FOR INPUT
    $global:base_path = Read-FolderBrowserDialog -Message "Please select a directory for where ALL your unzipped artifact data archives are collected; this directory should include unzipped archives organized by system name (and ONLY these folders)" -NoNewFolderButton
}

##TIME COLLECTION
function incident_start_time() {
    #START OF INCIDENT
    $global:det_times | Sort-Object -Property Time -Descending | Out-GridView
    Write-Host "If you have a good idea of when the incident started - enter it here.  IF YOU DONT KNOW - please review the output just presented of AV Detections.  It may provide some insight into how far back the incident goes"
    Do {
        Write-Host "Please be sure to enter the date/Time of the START of the Incident in a common Time/Date Format - like '11/21/2016 9:56:44 AM' or 'Thursday, November 15, 2018 1:30:57 PM'" 
        Write-Host "If you are not sure - a good starting point would be 7 days prior to execution of Ransomware"
        $global:StartIncidentTime = Read-Host -Prompt 'Please Provide the START Incident Time in a common time format such as "Thursday, November 15, 2018 1:30:57 PM"' }
    Until([datetime]$global:StartIncidentTime)
    $global:StartIncidentTime = (Get-Date $global:StartIncidentTime)
}
function incident_end_time() {
    #END OF INCIDENT
    Do {
        Write-Host "Please be sure to enter the date/Time of the END of the Incident in a common Time/Date Format - like '11/21/2016 9:56:44 AM' or 'Thursday, November 15, 2018 1:30:57 PM'" 
        $global:EndIncidentTime = Read-Host -Prompt 'Please Provide the END Incident Time in a common time format such as "Thursday, November 15, 2018 1:30:57 PM"' }
    Until([datetime]$global:EndIncidentTime)
    $global:EndIncidentTime = (Get-Date $global:EndIncidentTime)
}

#GET LIST OF COMPROMISED ACCOUNTS
$global:accounts = @()

function compromised_accounts() {
    Write-Host "## Please list accounts beleived to have been compromised by the threat actor - here is an initial listing of POSSIBLY compromised user accounts based on malware detections observed.  You should include any accounts observed executing malware or for which you suspect there has been unauthorized activity"
    $global:comp_users_possible
    $comp_accounts = Read-Host -Prompt 'Provide a comma seperated list of accounts known to be compomrised (no spaces)'
    foreach ($item in ($comp_accounts -Split ",")) {
        $global:accounts += $item.Trim().ToUpper()
    }
    $global:accounts = $global:accounts | Sort | Get-Unique
}
    
#GET LIST OF FULL FILE NAMES
$global:fnames = @("anydesk.exe","psexec.exe","netscan.exe","PSEXESVC.exe","launcher.bat","unlocker-setup.exe","gmer.exe","mimilsa.log","advanced_port_scanner.exe","PasswordFox64.exe","BulletsPassView64.exe","SniffPass64.exe","netpass64.exe","ChromePass64.exe","mailpv.exe","iepv.exe","rdpv.exe","VNCPassView.exe","WebBrowserPassView.exe","ProcessHacker.exe","7z.exe","system.sav","sam.sav","HHUPD.exe","ntds.lnk","SAM.lnk","BloodHound","ntds.dmp","ntds.zip","lsass.dmp","lsass.zip")
function file_iocs() {
    $global:fnames += $global:temp_fnames
    $global:fnames
    Write-Host "## NOTE - We have already added some common indicators, as well as parsed all your Defnder and Symantec logs to pull out file names detected during this attack (your welcome as Maui would sing)"
    $add_files = Read-Host -Prompt 'Provide a comma seperated list of file names known to be associated with the attack (no spaces) not already included int he list above'
    foreach ($item in ($add_files -Split ",")) {
        $global:fnames += $item.Trim().ToUpper()
    }
    $global:fnames = $global:fnames | Sort | Get-Unique
}

if ($global_config.bad_ip_hostnames -ne '') {
    $global:comp_hosts = $global_config.bad_ip_hostnames
    $global:comp_hosts = $global:comp_hosts.Split(",").Trim().ToUpper()
} else {
    #IP Addresses or Hostnames
    $global:comp_hosts = Read-Host -Prompt 'Provide a comma seperated list of IP Addresses or ComputerNames where the threat actor was KNOWN to be working FROM (leave empty if none); the more info here the better.  If you have found a C2 address or know a threat actor RDP into a system, include it here' 
    $global:comp_hosts = $global:comp_hosts.Split(",").Trim().ToUpper()
}

#get list of systems
function systems_gathered() {
    $global:systems = @()
    $global:vhdx = gci $global:base_path -Recurse *.vhdx
    if ($global:vhdx.Count -gt 0) {
        foreach ($file in $global:vhdx) {
            $system = $null
            $system = (($file.name -Split "\.")[0] -Split "_")[-1]
            $global:systems += $system
        }
    } else {
        foreach ($folder in (gci $global:base_path -Directory)) {
            $system = $null
            $system = ($folder.Name -Split "_")[0]
            $global:systems += $system
        }
    }
}


#This script block is what processes the artifacts for each system being investigated
#This is initiated as a background PS Job - overall timeline is returned back to the main script to create the overall timeline of all systems
$scriptBlock_process_host = {
    param($folder,$global:StartIncidentTime,$global:EndIncidentTime,$ComputerName,$global:fnames,$global:accounts,$global:type_of_analysis,$global:comp_hosts,$yaml_path,$global:final_output,$vfile)
    $timezone = $null
    #GET HOST TIME ZONE
    $eid =  "6013"
    $file = gci -path $folder.FullName -Filter 'System.evtx' -Recurse
    $temp_det = Get-WinEvent -FilterHashtable @{Path=$($file.FullName);ID=$eid} 
    if ($temp_det.Count -gt 0) { 
        foreach ($line in $temp_det.Properties) {
            if($line.Value -like "*Central Standard Time*"){
        		$timezone = 5
    		}
    		if($line.Value -like "*Eastern Standard Time*"){
        		$timezone = 4
    		}
    		if($line.Value -like "*Mountain*"){
        		$timezone = 6
    		}
    		if($line.Value -like "*Pacific*"){
        		$timezone = 7
    		}
        }
    } 

    if (!($timezone)) {
        #DEFAULT TIME ZONE TO EST
        $timezone = 4
        $tz_files = gci -path $folder.FullName -Filter 'system_date_time_tz.txt' -Recurse
        foreach ($file in $tz_files) {
    	    $tz = get-content $file.FullName
            foreach($line in $tz) {
    		    if($line -like "*Central Standard Time*"){
        		    $timezone = 5
    		    }
    		    if($line -like "*Eastern Standard Time*"){
        		    $timezone = 4
    		    }
    		    if($line -like "*Mountain*"){
        		    $timezone = 6
    		    }
    		    if($line -like "*Pacific*"){
        		    $timezone = 7
    		    }
		    }
        }
    }
    if ($timezone -eq 4) {
    	$timezoneinfo = "US Eastern Standard Time"
    }
    if ($timezone -eq 5) {
    	$timezoneinfo = "Central Standard Time"
    }
    if ($timezone -eq 6) {
    	$timezoneinfo = "US Mountain Standard Time"
    }
    if ($timezone -eq 7) {
    	$timezoneinfo = "Pacific Standard Time"
    }

    #Initialize investigation variable
    $global:investigation = @()

    #New YAML Engine
    #Simple Engine to pull YAML Rules and perform matching on different strings with simple any or all conditions
    $yamls = @()
    $yaml_files = gci -r -file $yaml_path
    foreach ($file in $yaml_files) {
        $yamls += Get-Content $file.Fullname | ConvertFrom-YAML -Ordered
    }
    $fname = @()
    foreach ($entry in $global:fnames) {
        $fname += $entry        
    }
    $output = @{}
    $output.add("detection","Known Bad File Name")
    $output.add("source","Event Logs")
    $output.add("id","4688,1,3,7,10,21,24,25")
    $output.add("category","Execution")
    $output.add("tags","Known Files")
    $output.add("operator","any")
    $output.add("filename","Security.evtx,Microsoft-Windows-Sysmon,MFT")
    $output.add("signatures",$fname)
    $yamls += $output
    $output = $null
    $faccount = @()
    foreach ($entry in $global:accounts) {
        $faccount += $entry        
    }
    $output = @{}
    $output.add("detection","Known Compromised Account")
    $output.add("source","Event Logs")
    $output.add("category","Lateral Movement")
    $output.add("tags","Compromised Accounts")
    $output.add("id","4688,1,3,7,10,21,24,25")
    $output.add("operator","any")
    $output.add("filename","Security.evtx,Microsoft-Windows-TerminalServices-RDPClient,icrosoft-Windows-TerminalServices-LocalSessionManager,Microsoft-Windows-Sysmon")
    $output.add("signatures",$faccount)
    $yamls += $output
    $output = $null
    $fhosts = @()
    foreach ($entry in $global:comp_hosts) {
        $fhosts += $entry        
    }
    $output = @{}
    $output.add("detection","Known Compromised Host")
    $output.add("source","Event Logs")
    $output.add("category","Lateral Movement")
    $output.add("id","4688,1,3,7,10,21,24,25")
    $output.add("tags","Compromised Accounts")
    $output.add("operator","any")
    $output.add("filename","Security.evtx,Microsoft-Windows-TerminalServices-RDPClient,icrosoft-Windows-TerminalServices-LocalSessionManager,Microsoft-Windows-Sysmon")
    $output.add("signatures",$fhosts)
    $yamls += $output
    $output = $null
    $event_logs = gci -r $folder.FullName *.evtx
    $yaml_investigation = @()
    foreach ($tfile in $event_logs) {
        $fname = $tfile.Name
        #Write-Host "Searching: $fname"
        $yaml_evt = @()
        foreach ($yaml in $yamls) {
            $yevents = $yaml.filename -Split ","
            foreach ($yamlname in $yevents.Trim()) {
                
                if (($fname -like "*$yamlname*") -and ($yamlname -ne "")) {
                    $yaml_evt += $yaml
                }
            }
        }
        $tfname = $tfile.FullName
        if ($yaml_evt.Count -ge 1) {
            $ycount = $yaml_evt.Count
            $yinit = 0
            foreach ($signature in $yaml_evt) {
                $yinit++
                #Write-Host "Checking $yinit of $ycount signatures"
                #get events to search
                $det = $signature.detection
                $hash = @{}
                $hash.add("Path",$tfile.FullName)
                $hash.add("StartTime",$global:StartIncidentTime)
                $hash.add("EndTime",$global:EndIncidentTime)
                $all = @()
                
                if ($signature.id) {
                    if ($signature.id -like "*,*") {
                        $id = $signature.id -Split ","
                    } else {
                        $id = $signature.id
                    }
                    $hash.add("ID",$id)
                }
                if ($signature.providerName) {
                    $provider = $signature.providerName
                    $hash.add("ProviderName",$provider)
                }
                $message = $signature.signatures
                $tags = $signature.tags -Join [Environment]::NewLine
                $all = Get-WinEvent -FilterHashtable $hash
                if ($message.count -ge 1) {
                    foreach ($match in $all) {
                        $matched = @()
                        $detected = ""
                        foreach ($mess in ($message -split [Environment]::NewLine)) {
                            $mess = $mess.Trim()
                            $matched += $match.message -like "*$mess*"
                            if (($match.message -like "*$mess*") -and ($mess -ne "")) {
                                $detected = $mess
                            }
                        }
                        if ($signature.operator -eq "all") {
                            $matched = $matched | Sort-Object | Get-Unique
                            if (($matched.Count -eq 1) -and ($matched -eq $true)) {
                                $det = $signature.detection
                                if ($detected -ne "") {
                                    $det = $det + " - " + $detected.ToUpper()
                                }
                                $atime = [datetime]$match.TimeCreated
                                if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	                        $det = $det + " - SUSPICIOUS HOURS"
                                }
                                if ($global:accounts.Contains($match.UserId.ToUpper())) {
                                    $det = $det + " - COMPROMISED ACCOUNT"
                                }
                                
                                $output = New-Object -TypeName PSObject
                                $output | add-member NoteProperty "Date" -value $match.TimeCreated
                                $output | add-member NoteProperty "System" -value $match.MachineName
                                $output | add-member NoteProperty "Detection Type" -value $det
                                $output | add-member NoteProperty "Source" -value $fname
                                $output | add-member NoteProperty "Notes" -value $match.message
                                $output | add-member NoteProperty "Username" -value $match.UserId
                                $output | add-member NoteProperty "Tags" -value $tags
                                $output | add-member NoteProperty "Category" -value $signature.category
                                $output | add-member NoteProperty "Include" -value ""
                                $global:investigation += $output
                            }
                        } else {
                            if ($matched.Contains($true)) {
                                $det = $signature.detection
                                if ($detected -ne "") {
                                    $det = $det + " - " + $detected.ToUpper()
                                }
                                $atime = [datetime]$match.TimeCreated
                                if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	                        $det = $det + " - SUSPICIOUS HOURS"
                                }
                                if ($global:accounts.Contains($match.UserId.ToUpper())) {
                                    $det = $det + " - COMPROMISED ACCOUNT"
                                }
                                $output = New-Object -TypeName PSObject
                                $output | add-member NoteProperty "Date" -value $match.TimeCreated
                                $output | add-member NoteProperty "System" -value $match.MachineName
                                $output | add-member NoteProperty "Detection Type" -value $det
                                $output | add-member NoteProperty "Source" -value $fname
                                $output | add-member NoteProperty "Notes" -value $match.message
                                $output | add-member NoteProperty "Username" -value $match.UserId
                                $output | add-member NoteProperty "Tags" -value $tags
                                $output | add-member NoteProperty "Category" -value $signature.category
                                $output | add-member NoteProperty "Include" -value ""
                                $global:investigation += $output
            
                            }
                        }
                    }
                #NO Signature Matches Needed
                } else {
                    foreach ($match in $all) {
                        $det = $signature.detection
                        $atime = [datetime]$match.TimeCreated
                        if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	                $det = $det + " - SUSPICIOUS HOURS"
                        }
                        if ($global:accounts.Contains($match.UserId.ToUpper())) {
                            $det = $det + " - COMPROMISED ACCOUNT"
                        }
                        if (($match.ProviderName -eq "SentinelOne") -or ($match.ProviderName -eq "Symantec Endpoint Protection Client")) {
                            $tmessage = $match.Properties.Value -Join [Environment]::NewLine 
                        } else {
                            $tmessage = $match.message
                        }
                        $output = New-Object -TypeName PSObject
                        $output | add-member NoteProperty "Date" -value $match.TimeCreated
                        $output | add-member NoteProperty "System" -value $match.MachineName
                        $output | add-member NoteProperty "Detection Type" -value $det
                        $output | add-member NoteProperty "Source" -value $fname
                        $output | add-member NoteProperty "Notes" -value $tmessage
                        $output | add-member NoteProperty "Username" -value $match.UserId
                        $output | add-member NoteProperty "Tags" -value $tags
                        $output | add-member NoteProperty "Category" -value $signature.category
                        $output | add-member NoteProperty "Include" -value ""
                        $global:investigation += $output
                        $tmessage = $null
                    }
                }
            }
        }
    }
    #MFT-ALL
    $system = $ComputerName
    $mft_files = gci -path $folder.FullName -Filter '$MFT' -Recurse
    $mft_start_time = ($global:StartIncidentTime).AddHours($timezone)
    $mft_all = @()
    foreach ($file in $mft_files) {
        $temp = $null
        try {
            $temp = Get-ForensicFileRecord -MftPath $file.FullName | Where-Object {(($_.BornTime -ge $mft_start_time) -or ($_.ModifiedTime -ge $mft_start_time) -or ($_.AccessedTime -ge $mft_start_time))} | select-Object -Property FullName,Name,BornTime,ModifiedTime,AccessedTime
        } catch {
            if (!(Test-Path "C:\Temp\")) {
                New-Item -Path "C:\Temp\"
            }
            if (!(Test-Path "C:\Temp\$system")) {
                New-Item -Path "C:\Temp\"
                $tdir = New-Item -Path "C:\Temp\" -Name  $system -ItemType "directory"
                $dest = $tdir.FullName +  '\$mft'
            } else {
                $tdir = "C:\Temp\$system"
                $dest = $tdir + '\$mft'
            }
            
            Copy-Item -Path $file.FullName -Destination $dest
            $temp = Get-ForensicFileRecord -MftPath $dest | Where-Object {(($_.BornTime -ge $mft_start_time) -or ($_.ModifiedTime -ge $mft_start_time) -or ($_.AccessedTime -ge $mft_start_time))} | select-Object -Property FullName,Name,BornTime,ModifiedTime,AccessedTime
            Remove-Item $dest
            try {
                Remove-Item $tdir.FullName
            } catch {
                Remove-Item $tdir
            }
        }
        $output = New-Object -TypeName PSObject
        $output | add-member NoteProperty "HostName" -value $system
        $output | add-member NoteProperty "MFT" -Value $temp
        $output | add-member NoteProperty "FileName" -Value $file.FullName
        $mft_all += $output
        $output = $null
        $temp = $null
    }
    #LAST ACTIVITY
    $last_activity_files = gci -path $folder.FullName -Filter LastActivityView.html -Recurse
    $sys_activity = @()
    foreach ($file in $last_activity_files) {
        $html = New-Object -ComObject "HTMLFile"
        $html.IHTMLDocument2_write($(Get-Content $file.FullName -raw))
        $temp = $html.all.tags("TD") | % innerHTML
        $tcounter = 0
        $titem = @()
        Foreach ($item in $temp) {
            $tcounter++
            $titem += $item
            if ($tcounter -eq 6) {
                [datetime]$atime = $titem[0]
                $output = New-Object -TypeName PSObject
                $output | add-member NoteProperty "HostName" -value $system
                $output | add-member NoteProperty "Action Time" -value $atime
                $output | add-member NoteProperty "Description" -value $titem[1]
                $output | add-member NoteProperty "FileName" -value $titem[2]
                $output | add-member NoteProperty "Full Path" -value $titem[3]
                $output | add-member NoteProperty "More Information" -value $titem[4]
                $output | add-member NoteProperty "File Extension" -value $titem[5]
                $sys_activity += $output
                $tcounter = 0
                $titem = @()
            }
        }
    }
    $sys_activity = $sys_activity | Where-Object {($_."Action Time" -ge $global:StartIncidentTime) -and ($_."Action Time" -le $global:EndIncidentTime)}
    $global:all_activity += $sys_activity
    $sys_activity  = $null
    $global:all_activity_incident = $global:all_activity | sort -Descending "Action Time"
    $global:all_activity  = $null
    #MFT Incident Timeline
    $global:mft_incident = @()
    $start = ($global:StartIncidentTime).AddHours($timezone)
    $end = ($global:EndIncidentTime).AddHours($timezone)
    $temp = $mft_all.mft | Where-Object {([datetime]$_.BornTime -ge $start) -and ([datetime]$_.BornTime -le $end)}
    $temp = $temp | Sort-Object -Property BornTime -Descending
    $output = New-Object -TypeName PSObject
    $output | add-member NoteProperty "HostName" -value $system
    $output | add-member NoteProperty "mft" -value $temp
    $output | add-member NoteProperty "FileName" -value $mft_all.FileName
    $global:mft_incident += $output
    $outputfile = $global:final_output+"\mft\"+$ComputerName+"_mft_all_incident_timeline.csv"
    $global:mft_incident.mft | export-csv -Path $outputfile -NoTypeInformation
    $output = $null
    $temp = $null
    #MFT IOC
    $sysarray = @()
    $around = @()
    $global:list_files = @()
    if ($global:type_of_analysis.ToUpper() -eq "FUZZY") {
        foreach ($item in $global:mft_incident.mft) {
            if (($global:fnames | Where-Object {$item.Name -like "*$_*"}).Count -gt 0){
                $sysarray += $item
                $tmpstart = ([datetime]$item.BornTime).AddMinutes(-1)
                $tmpend = ([datetime]$item.BornTime).AddMinutes(1)
                $around = $global:mft_incident.mft | Where-Object {($_.BornTime -ge $tmpstart) -and ($_.BornTime -le $tmpend)}
                $sysarray += $around
                $around = $null
            }
        }
    }
    if ($global:type_of_analysis.ToUpper() -eq "STRICT") {
        foreach ($item in $global:mft_incident.mft) {
            if (($global:fnames.Contains($item.Name))){
                $sysarray += $item
                $tmpstart = ([datetime]$item.BornTime).AddMinutes(-1)
                $tmpend = ([datetime]$item.BornTime).AddMinutes(1)
                $around = $global:mft_incident.mft | Where-Object {($_.BornTime -ge $tmpstart) -and ($_.BornTime -le $tmpend)}
                $sysarray += $around
                $around = $null
            }
        }
    }
	$output = New-Object -TypeName PSObject
    $output | add-member NoteProperty "HostName" -value $system
    $output | add-member NoteProperty "mft" -value $sysarray
    $global:list_files += $output
    $sysarray = $null
    $output = $null
    #STAGING DETECTION
    $hostname = $system  
	$staging = @()
    $start = ($global:StartIncidentTime).AddHours($timezone)
    $end = ($global:EndIncidentTime).AddHours($timezone)
    $temp2 = $global:mft_incident.mft | Where-Object {((([datetime]$_.BornTime -gt $start) -and ([datetime]$_.BornTime -lt $end))-and (($_.Name -Like "*.pdf*") -or ($_.Name -Like "*.doc*") -or ($_.Name -Like "*.xls*") -or ($_.Name -Like "*.jpg*") -or ($_.Name -Like "*.tif*")) -and (!($_.FullName -like "*\\AppData\\*")))}
    $findings = $temp2 | Select-Object @{Name="Hour";Expression={([datetime]$_.BornTime).Hour}},FullName,BornTime | Group-Object -Property Hour | Sort-object -Property Count -Descending
    $temp2 = $null
    foreach ($row in $findings) {
        if ($row.Count -ge 100) {
            $timestart = $row.Group.BornTime | Sort -Descending | Select -Last 1
            $atime = ([datetime]$timestart).AddHours(-$timezone)
            $note = "[" + $row.Count + " Files Detected]"
            if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	    $note = " SUSPICIOUS HOURS"
            }
            $temparr = @()
            $temparr += "MFT TIME:"
            $temparr += $timestart
            $temparr += "EST TIME:"
            $temparr += $atime
            $temprow = $row.Group.FullName -Split [Environment]::NewLine
            $temprow = $temprow | select -First 50
            $output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $atime
            $output | add-member NoteProperty "System" -value $Hostname
            $output | add-member NoteProperty "Detection Type" -value "POSSIBLE STAGING AREA OBSERVED $note"
            $output | add-member NoteProperty "Source" -value $global:mft_incident.FileName
            $output | add-member NoteProperty "Notes" -value ($temprow -Join [Environment]::NewLine )
            $output | add-member NoteProperty "User" -value ($temparr -Join [Environment]::NewLine)
            $output | add-member NoteProperty "Tags" -value "Staging,Exfiltration,Data Access"
            $output | add-member NoteProperty "Category" -value "Impact"
            $output | add-member NoteProperty "Include" -value ""
            $global:staging += $output
			$output = $null
            $temprow = $null
        }
    }
    $findings = $null
    #Chrome History
    $history = @()
    $tfolder = $folder.FullName
    $files = gci -File -r $tfolder | where {$_.name -like "History"}
    foreach ($file in $files) {
        $bhistory = "C:\Temp\BrowsingHistoryView.exe"
        $safeFName = $file.FullName + ".csv"
        $cmd = 'cmd /c $bhistory /HistorySource 6 /CustomFiles.ChromeFiles $file.FullName /scomma $safeFName /VisitTimeFilterType 1'
        Invoke-Command -ScriptBlock ([ScriptBlock]::Create($cmd))
        $history += Import-csv $safeFName
    }
    $browser_yamls = $yamls | Where-Object {$_.filename -eq "BrowserHistory"}
    $incident_bhistory = $history | Where-Object {(([datetime]$_.'Visit Time' -ge $global:StartIncidentTime) -and ([datetime]$_.'Visit Time' -le $global:EndIncidentTime))}
    #Targeted Browser History to YAML Sigantures
    foreach ($entry in $incident_bhistory) {
        $r1 = ""
        $UserName = ""
        if ($entry.'History File' -like "*LiveResponseData*") {
            $r1 = ($entry.'History File' -Split "LiveResponseData\\CopiedFiles\\Chrome\\")[1]
            $UserName = $r1 -Replace ("\\history\\History","")
        } else {
            $r1 = ($entry.'History File' -Split "\\Users\\")[1]
            $UserName = ($r1 -Split "\\")[0]
        }
        $note = $null
        $added = $false
        foreach ($yaml in $browser_yamls) {
            #Only ANY Supported for Browser History Type YAML at this point
            Foreach ($signature in $yaml.Signatures) {
                if ($entry.URL -like "*$signature*") {
                    $dtype = $yaml.detection + "- " + $signature
                    $output = New-Object -TypeName PSObject
                    $output | add-member NoteProperty "Date" -value $entry.'Visit Time'
                    $output | add-member NoteProperty "System" -value $system
                    $output | add-member NoteProperty "Detection Type" -value $dtype
                    $output | add-member NoteProperty "Source" -value $entry.'History File'
                    $output | add-member NoteProperty "Notes" -value $entry.URL
                    $output | add-member NoteProperty "Username" -value $UserName
                    $output | add-member NoteProperty "Tags" -value $yaml.tags
                    $output | add-member NoteProperty "Category" -value $yaml.category
                    $output | add-member NoteProperty "Include" -value ""
                    $global:investigation += $output
                    $added = $true
                }
            }
        }
        if (!($added)) {
        	$output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $entry.'Visit Time'
            $output | add-member NoteProperty "System" -value $system
            $output | add-member NoteProperty "Detection Type" -value "WEB HISTORY - $note"
            $output | add-member NoteProperty "Source" -value $entry.'History File'
            $output | add-member NoteProperty "Notes" -value $entry.URL
            $output | add-member NoteProperty "Username" -value $UserName
            $output | add-member NoteProperty "Tags" -value "Informational,Web Browsing"
            $output | add-member NoteProperty "Category" -value "Informational"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    #IE/EDGE HISTORY
    $history = @()
    $tfolder = $folder.FullName
    $files = gci -File -r $tfolder | where {$_.name -like "WebCacheV01.dat"}
    foreach ($file in $files) {
        $bhistory = "C:\Temp\BrowsingHistoryView.exe"
        $safeFName = $file.FullName + ".csv"
        $cmd = 'cmd /c $bhistory /HistorySource 6 /CustomFiles.IE10Files $file.FullName /scomma $safeFName /VisitTimeFilterType 1'
        Invoke-Command -ScriptBlock ([ScriptBlock]::Create($cmd))
        $history += Import-csv $safeFName
    }
    $browser_yamls = $yamls | Where-Object {$_.filename -eq "BrowserHistory"}
    $incident_bhistory = $history | Where-Object {(([datetime]$_.'Visit Time' -ge $global:StartIncidentTime) -and ([datetime]$_.'Visit Time' -le $global:EndIncidentTime))}
    #Targeted Browser History to YAML Sigantures
    foreach ($entry in $incident_bhistory) {
        $r1 = ""
        $UserName = ""
        if ($entry.'History File' -like "*LiveResponseData*") {
            $r1 = ($entry.'History File' -Split "LiveResponseData\\CopiedFiles\\ie\\")[1]
            $UserName = $r1 -Replace ("\\WebCache\\WebCacheV01.dat","")
        } else {
            $r1 = ($entry.'History File' -Split "\\Users\\")[1]
            $UserName = ($r1 -Split "\\")[0]
        }
        $note = $null
        $added = $false
        foreach ($yaml in $browser_yamls) {
            #Only ANY Supported for Browser History Type YAML at this point
            Foreach ($signature in $yaml.Signatures) {
                if ($entry.URL -like "*$signature*") {
                    $dtype = $yaml.detection + "- " + $signature
                    $output = New-Object -TypeName PSObject
                    $output | add-member NoteProperty "Date" -value $entry.'Visit Time'
                    $output | add-member NoteProperty "System" -value $system
                    $output | add-member NoteProperty "Detection Type" -value $dtype
                    $output | add-member NoteProperty "Source" -value $entry.'History File'
                    $output | add-member NoteProperty "Notes" -value $entry.URL
                    $output | add-member NoteProperty "Username" -value $UserName
                    $output | add-member NoteProperty "Tags" -value $yaml.tags
                    $output | add-member NoteProperty "Category" -value $yaml.category
                    $output | add-member NoteProperty "Include" -value ""
                    $global:investigation += $output
                    $added = $true
                }
            }
        }
        if (!($added)) {
        	$output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $entry.'Visit Time'
            $output | add-member NoteProperty "System" -value $system
            $output | add-member NoteProperty "Detection Type" -value "WEB HISTORY - $note"
            $output | add-member NoteProperty "Source" -value $entry.'History File'
            $output | add-member NoteProperty "Notes" -value $entry.URL
            $output | add-member NoteProperty "Username" -value $UserName
            $output | add-member NoteProperty "Tags" -value "Informational,Web Browsing"
            $output | add-member NoteProperty "Category" -value "Informational"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    #FIREFOX HISTORY
    $history = @()
    $tfolder = $folder.FullName
    $files = gci -File -r $tfolder | where {$_.name -like "places.sqlite"}
    foreach ($file in $files) {
        $bhistory = "C:\Temp\BrowsingHistoryView.exe"
        $safeFName = $file.FullName + ".csv"
        $cmd = 'cmd /c $bhistory /HistorySource 6 /CustomFiles.FirefoxFiles $file.FullName /scomma $safeFName /VisitTimeFilterType 1'
        Invoke-Command -ScriptBlock ([ScriptBlock]::Create($cmd))
        $history += Import-csv $safeFName
    }
    $browser_yamls = $yamls | Where-Object {$_.filename -eq "BrowserHistory"}
    $incident_bhistory = $history | Where-Object {(([datetime]$_.'Visit Time' -ge $global:StartIncidentTime) -and ([datetime]$_.'Visit Time' -le $global:EndIncidentTime))}
    $added = $false
    #Targeted Browser History to YAML Sigantures
    foreach ($entry in $incident_bhistory) {
        $r1 = ""
        $UserName = ""
        if ($entry.'History File' -like "*LiveResponseData*") {
            $r1 = ($entry.'History File' -Split "LiveResponseData\\CopiedFiles\\firefox\\")[1]
            $UserName = $r1 -Replace ("\\history\\places.sqlite","")
        } else {
            $r1 = ($entry.'History File' -Split "\\Users\\")[1]
            $UserName = ($r1 -Split "\\")[0]
        }
        $note = $null
        foreach ($yaml in $browser_yamls) {
            #Only ANY Supported for Browser History Type YAML at this point
            Foreach ($signature in $yaml.Signatures) {
                if ($entry.URL -like "*$signature*") {
                    $dtype = $yaml.detection + "- " + $signature
                    $output = New-Object -TypeName PSObject
                    $output | add-member NoteProperty "Date" -value $entry.'Visit Time'
                    $output | add-member NoteProperty "System" -value $system
                    $output | add-member NoteProperty "Detection Type" -value $dtype
                    $output | add-member NoteProperty "Source" -value $entry.'History File'
                    $output | add-member NoteProperty "Notes" -value $entry.URL
                    $output | add-member NoteProperty "Username" -value $UserName
                    $output | add-member NoteProperty "Tags" -value $yaml.tags
                    $output | add-member NoteProperty "Category" -value $yaml.category
                    $output | add-member NoteProperty "Include" -value ""
                    $global:investigation += $output
                    $added = $true
                }
            }
        }
        if (!($added)) {
        	$output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $entry.'Visit Time'
            $output | add-member NoteProperty "System" -value $system
            $output | add-member NoteProperty "Detection Type" -value "WEB HISTORY - $note"
            $output | add-member NoteProperty "Source" -value $entry.'History File'
            $output | add-member NoteProperty "Notes" -value $entry.URL
            $output | add-member NoteProperty "Username" -value $UserName
            $output | add-member NoteProperty "Tags" -value "Informational,Web Browsing"
            $output | add-member NoteProperty "Category" -value "Informational"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    #SHELLBAGS
    $directory = $folder.FullName + "\LiveResponseData\CopiedFiles\registry"
    if (!(test-path -Path $directory)) {
        $directory = $folder.FullName + "\registry"
        New-Item -Path $folder.FullName -Name registry -ItemType Directory | out-Null
        $tfiles = @()
        foreach ($datfiles in (gci -File -r $tfolder | where {$_.name -like "*NTUSER.DAT" -and $_.Length -gt 0})) {
            $username = ($datfiles.PSParentPath -Split "\\")[-1]
            $newdatname = $datfiles.PSParentPath + "\\" + $username + "_NTUSER.DAT"
            Move-Item -Path $datfiles.FullName -Destination $newdatname | out-null
        }
        $tfiles += gci -File -r $tfolder | where {$_.name -like "*NTUSER.DAT" -and $_.Length -gt 0}
        $tfiles += gci -File -r $tfolder | where {$_.name -like "SAM" -and $_.Length -gt 0}
        $tfiles += gci -File -r $tfolder | where {$_.name -like "SYSTEM" -and $_.Length -gt 0}
        $tfiles += gci -File -r $tfolder | where {$_.name -like "SOFTWARE" -and $_.Length -gt 0}
        foreach ($file in $tfiles) {
            Copy-Item $file.FullName $directory
        }
        
    }
    $sfname = $directory + "\Deduplicated.csv"
    Remove-Item $sfname
    C:\Temp\SBECmd.exe -d $directory --csv $directory --dedupe --dt 'MM/dd/yyy HH:mm:ss'
    $shells = Import-Csv $sfname
    $directory = $folder.FullName + "\registry"
    Remove-Item $directory -Recurse
    foreach ($thing in $shells) {
        if ((([DateTime]$thing.LastInteracted -gt $global:StartIncidentTime) -and ([DateTime]$thing.LastInteracted -lt $global:EndIncidentTime)) -OR (([DateTime]$thing.LastWriteTime -gt $global:StartIncidentTime) -and ([DateTime]$thing.LastWriteTime -lt $global:EndIncidentTime))) {
            $note = $null
            $atime = [datetime]$thing.LastWriteTime
            if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	    $note = " SUSPICIOUS HOURS"
            }
            $output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $thing.LastWriteTime
            $output | add-member NoteProperty "System" -value $system
            $output | add-member NoteProperty "Detection Type" -value "SHELLBAG $note"
            $output | add-member NoteProperty "Source" -value "NTUSER.DAT"
            $output | add-member NoteProperty "Notes" -value $thing.AbsolutePath
            $output | add-member NoteProperty "Username" -value $thing.SourceFile
            $output | add-member NoteProperty "Tags" -value "Informational,Data Access"
            $output | add-member NoteProperty "Category" -value "Collection"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    #HIVE FILES
    $HIVE_FILES = gci -path $folder.FullName -Filter '*NTUSER.DAT' -Recurse
    foreach ($file in $HIVE_FILES) {
        $username = ($file.Name -Split "_")[0]
        try {
            $userassist = Get-ForensicUserAssist -HivePath $file.FullName | Where-Object {(($_.LastExecutionTimeUtc.AddHours(-$timezone) -gt $global:StartIncidentTime) -and ($_.LastExecutionTimeUtc.AddHours(-$timezone) -lt $global:EndIncidentTime))}
        } catch {
            $tname = -Join (@('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z') | Get-Random -Count 12) 
            $dest = "C:\Temp\$tname.reg"
            copy-item $file.FullName $dest
            $userassist = Get-ForensicUserAssist -HivePath $dest | Where-Object {(($_.LastExecutionTimeUtc.AddHours(-$timezone) -gt $global:StartIncidentTime) -and ($_.LastExecutionTimeUtc.AddHours(-$timezone) -lt $global:EndIncidentTime))}
            Remove-Item $dest
        }
        foreach ($item in $userassist) {
            $note = $null
            $atime = [datetime]$item.LastExecutionTimeUtc.AddHours(-$timezone)
            if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	    $note = " SUSPICIOUS HOURS"
            }
            $output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $item.LastExecutionTimeUtc.AddHours(-$timezone)
            $output | add-member NoteProperty "System" -value $system
            $output | add-member NoteProperty "Detection Type" -value "USER ASSIST / PROGRAM RUN $note"
            $output | add-member NoteProperty "Source" -value $file.Name
            $output | add-member NoteProperty "Notes" -value $item.ImagePath
            $output | add-member NoteProperty "Username" -value $username
            $output | add-member NoteProperty "Tags" -value "Informational,Program Execution"
            $output | add-member NoteProperty "Category" -value "Execution"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    #AMCACHE
    $amfile = gci -path $folder.FullName -Filter '*Amcache.hve' -Recurse
    foreach ($file in $amfile) {
        try {
            $amcache = Get-ForensicAmcache -HivePath $file.FullName | Where-Object {(($_.ModifiedTime2Utc.AddHours(-$timezone) -gt $global:StartIncidentTime) -and ($_.ModifiedTime2Utc.AddHours(-$timezone) -lt $global:EndIncidentTime))}
        } catch {
            
            $tname = -Join (@('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z') | Get-Random -Count 12) 
            $dest = "C:\Temp\$tname.hve"
            copy-item $file.FullName $dest
            $amcache = Get-ForensicAmcache -HivePath $dest | Where-Object {(([datetime]$_.ModifiedTime2Utc.AddHours(-($timezone)) -gt $global:StartIncidentTime) -and ([datetime]$_.ModifiedTime2Utc.AddHours(-($timezone)) -lt $global:EndIncidentTime))}
            Remove-Item $dest
        }
        foreach ($item in $amcache) {
            $note = $null
            $atime = [datetime]$item.ModifiedTime2Utc.AddHours(-$timezone)
            if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	    $note = " SUSPICIOUS HOURS"
            }
            $output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $item.ModifiedTime2Utc.AddHours(-$timezone)
            $output | add-member NoteProperty "System" -value $system
            $output | add-member NoteProperty "Detection Type" -value "AMCACHE / PROGRAM RUN $note"
            $output | add-member NoteProperty "Source" -value $file.FullName
            $output | add-member NoteProperty "Notes" -value $item.Path
            $output | add-member NoteProperty "Username" -value "NA"
            $output | add-member NoteProperty "Tags" -value "Informational,Program Execution"
            $output | add-member NoteProperty "Category" -value "Execution"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    #GENERATE SYSTEM TIMELINE   
    #LAST ACTIVITY
    foreach ($event in $global:all_activity_incident) {
        $include = $true
        if (($event.Description -like "*User Logon*") -or ($event.Description -like "*User Logoff*")) {
           $include = $false
           foreach ($user in $global:accounts) {
               $user = $user.ToUpper()
                if (($event."More Information").ToUpper() -like "*$user*") {
                    $include = $true
                }
            }
        }
        if ($include) {
            $note = $null
            $atime = [datetime]$event."Action Time"
            if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
                $note = " SUSPICIOUS HOURS"
            }
            $deets = $event -Join [Environment]::NewLine | Out-String
            $des = $null
            $des = $event.Description + " " + $note
            $output = New-Object -TypeName PSObject
            $output | add-member NoteProperty "Date" -value $event."Action Time"
            $output | add-member NoteProperty "System" -value $event.HostName
            $output | add-member NoteProperty "Detection Type" -value $des
            $output | add-member NoteProperty "Source" -value "Last Activity Report - HTML" 
            $output | add-member NoteProperty "Notes" -value $deets
            $output | add-member NoteProperty "User" -value "NA"
            $output | add-member NoteProperty "Tags" -value "Informational"
            $output | add-member NoteProperty "Category" -value "Informational"
            $output | add-member NoteProperty "Include" -value ""
            $global:investigation += $output
        }
    }
    $global:all_activity_incident = $null
    #STAGING
    $global:investigation += $global:staging 
    $global:staging = $null
    #MFT
    $archive = @('.7z','.zip','.tar','.tar.gz')
    $start = ($global:StartIncidentTime).AddHours($timezone)
    $end = ($global:EndIncidentTime).AddHours($timezone)
    $comp_user_Activity = @()
    foreach ($user in $global:accounts) {
        $comp_user_Activity += $global:mft_incident.mft | Where-Object {(($_.FullName -like "*Users\$user*") -and (($_.FullName -notlike "*AppData\Local\Google\Chrome\User Data*") -and ($_.Name -notlike "*.etl") -and ($_.Name -notlike "*AppData\Local\Mozilla\Firefox\Profiles\*")))}
        $comp_user_bin = $comp_user_Activity | Where-Object {(($_.Name -like "*.bat*") -or ($_.Name -like "*.elf*") -or ($_.Name -like "*.com*") -or ($_.Name -like "*.exe*") -or ($_.Name -like "*.vbs*") -or ($_.Name -like "*.vbe*") -or ($_.Name -like "*.dll*") -or ($_.Name -like "*.ps1*"))}
    }        
    foreach ($ext in $archive) {
        $exfil_file_Activity += $global:mft_incident.mft | Where-Object {$_.Name -like "*$ext"}
    }
    #YAML ENgine for MFT
    $yaml_evt = @()
    $interesting_fs_actvity = @()
    foreach ($yaml in $yamls) {
        $yevents = $yaml.filename -Split ","
        foreach ($yamlname in $yevents.Trim()) {
            if ($yamlname -eq "MFT") {
                $yaml_evt += $yaml
            }
        }
    }
    foreach ($yaml in $yaml_evt)  {
        $interesting_fs_actvity = @()
        $fcounter = 0
        if ($yaml.operator -eq "any") {
            #any
            foreach ($signature in $yaml.signatures) {
                $interesting_fs_actvity += $global:mft_incident.mft | Where-Object {$_.FullName -like "*$signature*"}
                foreach ($entry in $interesting_fs_actvity) {
    	            $output = New-Object -TypeName PSObject
                    $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
                    $note = $null
                    if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	            $note = " SUSPICIOUS HOURS"
                    }
                    if ($note -ne $null) {
                        $dtype = $yaml.detection + " - $signature - $note"
                    } else {
                        $dtype = $yaml.detection + " - $signature"
                    }
                    $output | add-member NoteProperty "Date" -value $atime
                    $output | add-member NoteProperty "System" -value $ComputerName
                    $output | add-member NoteProperty "Detection Type" -value $dtype
                    $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
                    $output | add-member NoteProperty "Notes" -value $entry.FullName
                    $output | add-member NoteProperty "User" -value "NA"
                    $output | add-member NoteProperty "Tags" -value $yaml.tags
                    $output | add-member NoteProperty "Category" -value $yaml.category
                    $output | add-member NoteProperty "Include" -value ""
                    $global:investigation += $output
                }
                $interesting_fs_actvity = @()
            }
        }
        
        if ($yaml.operator -eq "all") {
            $temp_is_fs_activity = $global:mft_incident.mft
            #all
            foreach ($signature in $yaml.signatures) {
                $temp_is_fs_activity = $temp_is_fs_activity | Where-Object {$_.FullName -like "*$signature*"}
            }
            foreach ($entry in $temp_is_fs_activity) {
    	        $output = New-Object -TypeName PSObject
                $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
                $note = $null
                if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	        $note = " SUSPICIOUS HOURS"
                }
                if ($note -ne $null) {
                    $dtype = $yaml.detection + " - $note"
                } else {
                    $dtype = $yaml.detection
                }
                $output | add-member NoteProperty "Date" -value $atime
                $output | add-member NoteProperty "System" -value $ComputerName
                $output | add-member NoteProperty "Detection Type" -value $dtype
                $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
                $output | add-member NoteProperty "Notes" -value $entry.FullName
                $output | add-member NoteProperty "User" -value "NA"
                $output | add-member NoteProperty "Tags" -value $yaml.tags
                $output | add-member NoteProperty "Category" -value $yaml.category
                $output | add-member NoteProperty "Include" -value ""
                $global:investigation += $output
            }
            $temp_is_fs_activity = $null
            
        }
    }
    $bh_fs_actvity = $global:mft_incident.mft | Where-Object {(($_.FullName -like "*_ous.json") -or ($_.FullName -like "*_users.json") -or ($_.FullName -like "*_computers.json") -or ($_.FullName -like "*_domains.json") -or ($_.FullName -like "*_gpos.json"))}
    foreach ($entry in $bh_fs_actvity) {
    	$output = New-Object -TypeName PSObject
        $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
        $note = $null
        if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	$note = " SUSPICIOUS HOURS"
        }
        $output | add-member NoteProperty "Date" -value $atime
        $output | add-member NoteProperty "System" -value $ComputerName
        $output | add-member NoteProperty "Detection Type" -value "POSSIBLE BLOODHOUND OUTPUT DETECTED - $note"
        $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
        $output | add-member NoteProperty "Notes" -value $entry.FullName
        $output | add-member NoteProperty "User" -value "NA"
        $output | add-member NoteProperty "Tags" -value "Informational,Collection,Archive"
        $output | add-member NoteProperty "Category" -value "Collection"
        $output | add-member NoteProperty "Include" -value ""
        $global:investigation += $output
    }
    foreach ($entry in $exfil_file_Activity) {
    	$output = New-Object -TypeName PSObject
        $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
        $note = $null
        if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	$note = " SUSPICIOUS HOURS"
        }
        $output | add-member NoteProperty "Date" -value $atime
        $output | add-member NoteProperty "System" -value $ComputerName
        $output | add-member NoteProperty "Detection Type" -value "POSSIBLE STAGING/EXFIL - Archive File Created $note"
        $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
        $output | add-member NoteProperty "Notes" -value $entry.FullName
        $output | add-member NoteProperty "User" -value "NA"
        $output | add-member NoteProperty "Tags" -value "Informational,Collection,Archive"
        $output | add-member NoteProperty "Category" -value "Collection"
        $output | add-member NoteProperty "Include" -value ""
        $global:investigation += $output
    }
    foreach ($entry in $comp_user_Activity) {
        $output = New-Object -TypeName PSObject
        $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
        $note = $null
        if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	$note = " SUSPICIOUS HOURS"
        }
        $output | add-member NoteProperty "Date" -value $atime
        $output | add-member NoteProperty "System" -value $ComputerName
        $output | add-member NoteProperty "Detection Type" -value "Compromised Account Profile File Activity $note"
        $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
        $output | add-member NoteProperty "Notes" -value $entry.FullName
        $output | add-member NoteProperty "User" -value "NA"
        $output | add-member NoteProperty "Tags" -value "Informational"
        $output | add-member NoteProperty "Category" -value "Informational"
        $output | add-member NoteProperty "Include" -value ""
        $global:investigation += $output
    }
    foreach ($entry in $comp_user_bin) {
        $output = New-Object -TypeName PSObject
        $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
        $note = $null
        if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	$note = " SUSPICIOUS HOURS"
        }
        $output | add-member NoteProperty "Date" -value $atime
        $output | add-member NoteProperty "System" -value $ComputerName
        $output | add-member NoteProperty "Detection Type" -value "BINARY DROPPED in Compromised User Profile $note"
        $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
        $output | add-member NoteProperty "Notes" -value $entry.FullName
        $output | add-member NoteProperty "User" -value "NA"
        $output | add-member NoteProperty "Tags" -value "Informational"
        $output | add-member NoteProperty "Category" -value "Informational"
        $output | add-member NoteProperty "Include" -value ""
        $global:investigation += $output
    }
    foreach ($entry in $global:list_files.mft) {
        $atime = ([datetime]$entry."BornTime").AddHours(-$timezone)
        $note = $null
        if (($atime.hour -lt 6) -or ($atime.hour -gt 22)) {
        	$note = " SUSPICIOUS HOURS"
        }
        if ($global:fnames.Contains($entry.Name.ToUpper())) {
            $dtype = "Compromised File IOC $note"
        } else {
            $dtype = "Interesting File Activity - File Create Near Time of known IOC $note"
        }
        $output = New-Object -TypeName PSObject
        $output | add-member NoteProperty "Date" -value $atime
        $output | add-member NoteProperty "System" -value $ComputerName
        $output | add-member NoteProperty "Detection Type" -value $dtype 
        $output | add-member NoteProperty "Source" -value ($global:mft_incident.FileName -Replace " ","")
        $output | add-member NoteProperty "Notes" -value $entry.FullName
        $output | add-member NoteProperty "User" -value "NA"
        $output | add-member NoteProperty "Tags" -value "Informational"
        $output | add-member NoteProperty "Category" -value "Informational"
        $output | add-member NoteProperty "Include" -value ""
        $global:investigation += $output
    }
    $global:mft_incident = $null
    $comp_file_Activity = $null
    $cfa = $null
    
    $global:investigation = $global:investigation | Sort -Descending Date
    $systimeline = $global:final_output + "\system_timelines\"
    $fname = $systimeline + $ComputerName + ".csv"  
    $global:investigation | export-csv $fname -NoTypeInformation
    $global:investigation = $null
    DisMount-DiskImage -ImagePath $vfile.FullName
}

#SET OR RESET Base Path for all LRC unzipped files (BASE PATH SHOULD BE ONLY UNZIPPED ARCHIVES WTH SYSTEM NAME - IE A BUNCH OF FOLDERS NAMED COMPUTERNAME_DATECOLLECTED_TIMECOLLECTED\
if ($global_config.input_data_dir -ne '') {
    $global:base_path = $global_config.input_data_dir
} else {
    get_base_path
}

#This function is executed to attempt to get all Event log based AV detections
#Results are presented to the user BEFORE being asked for a timeline
#Can be used to help get an understanding of the overall timeline of events to narrow investigation
function av_prep() {
    $global:det_times = @()
    $ioc_files = @()
    $temp_det = @()
    $stemp_det = @()
    $defender_files = gci -path $base_path -Filter 'Microsoft-Windows-Windows Defender*Operational.evtx' -Recurse
    $symantec_files = gci -path $base_path -Filter 'Symantec Endpoint Protection Client.evtx' -Recurse
    $app_files = gci -path $base_path -Filter 'Application.evtx' -Recurse
    $crowdstrike_files = gci -path $base_path -Filter 'Crowdstrike-Falcon Sensor-CSFalconService*perational.evtx' -Recurse
    $ciscoamp_files = gci -path $base_path -Filter 'BehavioralProtection.evtx' -Recurse
    $ciscoamp_files += gci -path $base_path -Filter 'ScriptProtection.evtx' -Recurse
    $ciscoamp_files += gci -path $base_path -Filter 'MaliciousActivityProtection.evtx' -Recurse
    $ciscoamp_files += gci -path $base_path -Filter 'SystemProcessProtection.evtx' -Recurse
    $s1_files += gci -path $base_path -Filter 'SentinelOn*.evtx' -Recurse
    $DEventId = 1116,1117,1126
    $SEventId = 51
    $AEventId = 51
    $CSEventID = 3,4,9
    $S1EventID = 31
    foreach ($file in $s1_files) {
        $temp_det += Get-WinEvent -FilterHashtable @{Path=$($file.FullName);ID=$S1EventID} 
    }
    foreach ($file in $defender_files) {
        $temp_det += Get-WinEvent -FilterHashtable @{Path=$($file.FullName);ID=$DEventId} 
    }
    foreach ($file in $symantec_files) {
        $stemp_det += Get-WinEvent -FilterHashtable @{Path=$($file.FullName);ID=$SEventId} 
    }
    foreach ($file in $app_files) {
        $stemp_det += Get-WinEvent -FilterHashtable @{Path=$($file.FullName);ID=$AEventId}
    }
    #need good examples to be able to parse
    foreach ($file in $crowdstrike_files) {
        $cstemp_det += Get-WinEvent -FilterHashtable @{Path=$($file.FullName);ID=$CSEventId} 
    }
    foreach ($file in $ciscoamp_files) {
        $catemp_det += Get-WinEvent -FilterHashtable @{Path=$($file.FullName)} | out-null
    }
    $global:temp_fnames = @()
    $global:comp_users_possible = @()
    foreach ($item in $temp_det) {
        if ($item.ProviderName -eq "SentinelOne") {
            $message = $item.Properties.Value -Join [Environment]::NewLine
            $tempvalues = $item.Properties.Value -Split [Environment]::NewLine
            if ($tempvalues[1].Trim() -ne "unknown file") {
                $global:temp_fnames += $tempvalues[1].Trim()
            }
        } else {
            $message = $item.Message
            foreach ($line in (($item.Message).Split([Environment]::NewLine))) {
                $temp = $null
                if ($line -like "*Path:*") {
                    if ($line -like "*\Users\*") {
                        $ready = $false
                        $t = $line.split("\")
                        foreach ($titem in $t) {
                            if ($ready) {
                                $global:comp_users_possible += $titem
                                $ready = $false
                            }
                            if ($titem -eq "Users") {
                                $ready = $true
                            }
                            
                        }

                    }
                    $temp = $line.split("\")[-1]
                    $temp = $temp.split(";")[0]
                    $temp = $temp.split(" ")[0]
                    if (($temp.ToUpper() -ne "POWERSHELL.EXE") -and ($temp.ToUpper() -ne "CMD.EXE")) {
                        $global:temp_fnames += $temp
                    }
                }
            }
        }
        $output = New-Object -TypeName PSObject
        $output | add-member NoteProperty "TIME" -value $item.TimeCreated
        $output | add-member NoteProperty "SYSTEM" -value $item.MachineName
        $output | add-member NoteProperty "DETECTION" -value $message
        $global:det_times += $output
    }
    foreach ($item in $stemp_det) {
        $output = New-Object -TypeName PSObject
        $output | add-member NoteProperty "TIME" -value $item.TimeCreated
        $output | add-member NoteProperty "SYSTEM" -value $item.MachineName
        $output | add-member NoteProperty "DETECTION" -value $item.Properties.Value
        $global:det_times += $output
        foreach ($line in (($item.Properties.Value).Split([Environment]::NewLine))) {
            $temp = $null
            if ($line -like "*Security Risk Found!*") {
                if ($line -like "*\Users\*") {
                    $ready = $false
                    $t = $line.split("\")
                    foreach ($titem in $t) {
                        if ($ready) {
                            $global:comp_users_possible += $titem
                            $ready = $false
                        }
                        if ($titem -eq "Users") {
                            $ready = $true
                        }
                            
                    }

                }
                $temp = ($line -split "File:")[1]
                $temp = ($temp -split "by:")[0]
                $temp = $temp.split("\")[-1]
                $temp = $temp.split(" ")[0]
                $temp = $temp.Trim()
                if (($temp.ToUpper() -ne "POWERSHELL.EXE") -and ($temp.ToUpper() -ne "CMD.EXE")) {
                    $global:temp_fnames += $temp
                
                }
            }
        }
    }
    #NEED TO UPDATE WITH EXTRACTING GOOD MALWARE NAMES TO ADD TO LIST
    foreach ($item in $cstemp_det) {
        $output = New-Object -TypeName PSObject
        $output | add-member NoteProperty "TIME" -value $item.TimeCreated
        $output | add-member NoteProperty "SYSTEM" -value $item.MachineName
        $output | add-member NoteProperty "DETECTION" -value $item.Message
        $global:det_times += $output
    }
    foreach ($item in $catemp_det) {
        $output = New-Object -TypeName PSObject
        $output | add-member NoteProperty "TIME" -value $item.TimeCreated
        $output | add-member NoteProperty "SYSTEM" -value $item.MachineName
        $output | add-member NoteProperty "DETECTION" -value $item.Message
        $global:det_times += $output
    }
    $global:temp_fnames = $global:temp_fnames | sort | Get-Unique
    $global:temp_fnames = $global:temp_fnames.Where({ $_ -ne "" })
    $global:comp_users_possible = $global:comp_users_possible | sort | Get-Unique
    $global:comp_users_possible = $global:comp_users_possible.Where({ $_ -ne "" })
    $output = "$global:final_output\all_av_detections.csv"
    $global:det_times = $global:det_times | sort-object -Property TIME -Descending
    $global:det_times  | export-csv -Path $output -NoTypeInformation
}

if ((gci $global:base_path -Recurse *.vhdx).Count -eq 0) {
    av_prep
} else {
    Write-Host "$(Get-Date): ## Skipping Initial AV Search of All Hosts - Files need to be mounted individually"
}

#SET OR RESET Incident Start Time - IF YOU DO THIS - you will need to rerun all the areas in the import section for the new times to take affect
if ($global_config.incident_start_time -ne '') {
    $global:StartIncidentTime = $global_config.incident_start_time
    $global:StartIncidentTime = (Get-Date $global:StartIncidentTime)
} else {
    incident_start_time
}
if ($global_config.incident_end_time -ne '') {
    $global:EndIncidentTime = $global_config.incident_end_time
    $global:EndIncidentTime = (Get-Date $global:EndIncidentTime)
} else {
    incident_end_time
}

$ts = New-TimeSpan -Start $global:StartIncidentTime -End $global:EndIncidentTime

#SET OR UPDATE List of Compromised Account
#Should just need to add news ones as observed
if ($global_config.compromised_accounts -ne '') {
    $comp_accounts = $global_config.compromised_accounts
    foreach ($item in ($comp_accounts -Split ",")) {
        $global:accounts += $item.Trim().ToUpper()
    }
    $global:accounts = $global:accounts | Sort | Get-Unique
} else {
    compromised_accounts
}
#SET OR RESET file names of files that indicate threat actor activity - these are confirmed malware binaries or unathorized programs installed
if ($global_config.bad_files -ne '') {
    $add_files = $global_config.bad_files
    foreach ($item in ($add_files -Split ",")) {
        $global:fnames += $item.Trim().ToUpper()
    }
    $global:fnames = $global:fnames | Sort | Get-Unique
} else {
    file_iocs
}
#SET OR RESET List of Systems - As you add addition archive folders into the base path - you should rerun this to update the systems covered
systems_gathered
$global:systems_count = ($global:systems).Count

$Complete = Get-date
Write-Host "## Starting Artifact Analysis - " $Complete

if ($global:vhdx.Count -eq 0){
    #Iterate through listing of Computers to test
    foreach ($folder in (gci $global:base_path -Directory)) {
        # Check to see if there are too many open threads")
        $ComputerName = ($folder.Name -Split "_")[0]
        # If there are too many threads then wait here until some close
        While ($(Get-Job -state running).count -ge $MaxThreads){
            Write-Progress  -Activity "Parsing Artifact Data" -Status "Waiting for threads to close" -CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open" -PercentComplete [int]($i / $global:systems_count * 100)
            Start-Sleep -Milliseconds $SleepTimer
        }
        #"Starting job - $Computer"
        $i++
        $vfile = ""
        Start-Job -ScriptBlock $scriptBlock_process_host -ArgumentList $($folder,$global:StartIncidentTime,$global:EndIncidentTime,$ComputerName,$global:fnames,$global:accounts,$global:type_of_analysis,$global:comp_hosts,$yaml_path,$global:final_output,$vfile) -Name $ComputerName | Out-Null
        Write-Progress  -Activity "Parsing Artifact Data" -Status "Starting Threads" -CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open" -PercentComplete ($i / $global:systems_count * 100)
    }
} else {
    foreach ($vfile in $global:vhdx) {
        # Check to see if there are too many open threads")
        $ComputerName = (($vfile.name -Split "\.")[0] -Split "_")[-1]
        #Find unused network drive
        $drv = $null
        Mount-DiskImage -ImagePath $vfile.FullName
        $drv = (Get-Partition(Get-DiskImage -ImagePath $vfile.FullName).Number | Get-Volume).DriveLetter
        $tfolder = $drv + ":\C"
        $folder = Get-Item $tfolder
        # If there are too many threads then wait here until some close
        While ($(Get-Job -state running).count -ge $MaxThreads){
            Write-Progress  -Activity "Parsing Artifact Data" -Status "Waiting for threads to close" -CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open" -PercentComplete [int]($i / $global:systems_count * 100)
            Start-Sleep -Milliseconds $SleepTimer
        }
        #"Starting job - $Computer"
        $i++
        Start-Job -ScriptBlock $scriptBlock_process_host -ArgumentList $($folder,$global:StartIncidentTime,$global:EndIncidentTime,$ComputerName,$global:fnames,$global:accounts,$global:type_of_analysis,$global:comp_hosts,$yaml_path,$global:final_output,$vfile) -Name $ComputerName | Out-Null
        Write-Progress  -Activity "Parsing Artifact Data" -Status "Starting Threads" -CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open" -PercentComplete ($i / $global:systems_count * 100)
    }
}


$Complete = Get-date
Write-Host "## Created All Jobs - Waiting for Jobs to Complete - " $Complete
#STATUS BAR
While ($(Get-Job -State Running).count -gt 0){
    $ComputersStillRunning = ""
    ForEach ($System  in $(Get-Job -state running)){$ComputersStillRunning += ", $($System.name)"}
        $ComputersStillRunning = $ComputersStillRunning.Substring(2)
    Write-Progress  -Activity "Parsing Artifact Data" -Status "$($(Get-Job -State Running).count) threads remaining" -CurrentOperation "$ComputersStillRunning" -PercentComplete ($(Get-Job -State Completed).count / $(Get-Job).count * 100)
    Start-Sleep -Milliseconds $SleepTimer
}

"Reading all jobs"
$the_final_countdown = @()
$Complete = Get-date
Write-Host "## Reading All Jobs - " $Complete
Do {
    $temp = $null
    $temp = Get-Job |Wait-Job | Receive-Job -Keep
}Until((Get-Job -State "Running").Count -eq 0)


foreach ($file in (gci $systimeline)) {
    $the_final_countdown += Import-Csv $file.FullName
}
#POST PROCESSING / REPORTING
$global:files_opened = $the_final_countdown  | Where-Object {($_."Detection Type" -like "*Open file or folder*") -or ($_."Detection Type" -like "*Select file in open/save dialog-box*") -or ($_."Detection Type" -like "*View Folder in Explorer*") -or ($_."Detection Type" -like "*SHELLBAG*") -or ($_."Detection Type" -like "*File Opened LNK Created*") }
$shellbags = "$global:final_output\file_system_actvity.csv"
$global:files_opened | export-csv -Path $shellbags -NoTypeInformation
Write-Host "Systems with lots of outbound RDP activity during the incident"
$the_final_countdown  | Where-Object {$_."Detection Type" -like "*Outbound Connection*"} | Group-Object System | Sort -Descending Count
$foutput = "$global:final_output\complete_incident_timeline.csv"
$the_final_countdown = $the_final_countdown | sort-object -Property Date -Descending
$the_final_countdown  | export-csv -Path $foutput -NoTypeInformation
$time = Get-Date
Write-Host "## FINISHED Timeline Generation  - " $time	