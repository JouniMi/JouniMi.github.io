---
layout: post
title:  "Exploring hunting options for catching Impacket"
tags: [threat hunting, defender for endpoint, kql, impacket]
author: jouni
image: assets/images/impacket_logo.png
comments: false
categories: [ threat hunting ]
---

Hunting for usage of Impacket
=============================

Impacket is one of those tools which the threat actors are constantly using during the attacks. It is interesting tool as it allows interacting with several protocols with Python. It, for example, allows for a PsExec like behavior which is very often one of the key tools the threats use Impacket for. The tools has actually multiple different methods to do this. The tool also has features like secretsdump which tries to dump credentials from a remote host, WMI based interactive shell and many others.

My approach to see if I can catch this is to launch the attack from a non monitored device targeting a device which has the Defender for Endpoint agent installed. Then I am having a look what happens on the device to which the Impacket based attack is targeted to. While I was writing this post I quickly noticed that this needs to be released in multiple parts as there are quite a few features - and even when I touched the ones which I understand the best it took a good while to go through them.

![]({{ site.baseurl }}/assets/images/impacket_logo.png)

PsExec.py and smbexec.py
------------------------

These two offers the capabilities similar to PsExec. These have been used in the wild by the threat actors to get access to remote hosts within a Windows environment so it is interesting to see how the behavior is like on the host to which the attack is targeted to. I think the PsExec.py will be relatively similar to the normal PsExec, writing a service to the target device but we will see. As I have never used Impacket before it is also interesting to see the options available.

Impacket supports several authentication methods, username/password, hashes, kerberos authentication using cached information and AES key for kerberos authentication. Also you can change the name of the binary which will be used in the target machine if you wish. Here is how the output looks like when running with username/password combo without changing any settings:

![]({{ site.baseurl }}/assets/images/psexec.png)
PsExec module with default settings.

The activity was detected by Microsoft Defender with the alert subject of "An active 'RemoteExec' malware was detected on one endpoint". Good boy Defender, though it is possible it was only detected because the binary is being flagged, not by the behavior. Here is the alert story which is actually kinda great, but because it is revolving around the actual binary dropped to the target I think the alert may raise only because the binary is flagged malicious:

![]({{ site.baseurl }}/assets/images/psexec_alert.png)
Impacket psexec module alert story on MDE

Starting to think of different threat hunting angles and the easiest one here comes with the look into the NamedPipeEvents. Apparently the named pipe created here always has a reference to RemCom - which is very easy to spot with the following query:

    let lookuptime = 30d;
    DeviceEvents
    | where ActionType == @"NamedPipeEvent"
    | where Timestamp >ago(lookuptime)
    | project NamedPipeTimeStamp = Timestamp, NamedPipeProcess = InitiatingProcessFileName, NamedPipeProcessId = InitiatingProcessId, NamedPipeProcessStartTime = InitiatingProcessCreationTime, NamedPipeProcessSHA1 = InitiatingProcessSHA1, FileOperation=extractjson("$.FileOperation", AdditionalFields, typeof(string)), NamedPipeEnd=extractjson("$.NamedPipeEnd", AdditionalFields, typeof(string)), PipeName=extractjson("$.PipeName", AdditionalFields, typeof(string))
    | where PipeName contains "RemCom"
    

I wanted to create something not based on the string so I started to create a query using several steps which the activity includes. First I added the namedpipe created by ntoskrnl.exe. Which was great, until I tried to join to the file creation event, which did not work. Why you may ask? Well the reason is that on the DeviceEvents table the InitiatingProcessFileName is ntoskrnl.exe BUT on FileEvents table it is system. And this is the same process doing the activity but the name is inconsistent across the tables. Worry not, we can workaround by using the folderpath instead of filename.

    let lookuptime = 30d;
    let RareFilesCreated =
    DeviceFileEvents
    | where ActionType == 'FileCreated'
    | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFolderPath == @"c:\windows\system32\ntoskrnl.exe"
    | summarize count() by SHA1
    | where count_ < 3 | distinct SHA1; DeviceEvents | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFolderPath == @"c:\windows\system32\ntoskrnl.exe"
    | where ActionType == @"NamedPipeEvent"
    | project NamedPipeTimeStamp = Timestamp, NamedPipeProcess = InitiatingProcessFileName, NamedPipeProcessId = InitiatingProcessId, NamedPipeProcessStartTime = InitiatingProcessCreationTime, NamedPipeProcessSHA1 = InitiatingProcessSHA1, FileOperation=extractjson("$.FileOperation", AdditionalFields, typeof(string)), NamedPipeEnd=extractjson("$.NamedPipeEnd", AdditionalFields, typeof(string)), PipeName=extractjson("$.PipeName", AdditionalFields, typeof(string))
    | join (
    DeviceFileEvents
    | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFolderPath == @"c:\windows\system32\ntoskrnl.exe"
    | where ActionType == 'FileCreated' 
    | where SHA1 in~ (RareFilesCreated)
    | project FileCreationTimestamp = Timestamp, NamedPipeProcess = InitiatingProcessFileName, NamedPipeProcessId = InitiatingProcessId, NamedPipeProcessStartTime = InitiatingProcessCreationTime, NamedPipeProcessSHA1 = InitiatingProcessSHA1, FileCreated = FileName, FileCreatedSHA1 = SHA1, FileCreatedFolder = FolderPath
    ) on NamedPipeProcessId, NamedPipeProcessSHA1, NamedPipeProcessStartTime
    | project-away NamedPipeProcessId1, NamedPipeProcessSHA1, NamedPipeProcessStartTime1
    

There are options at this point. You could look into the service creation or launch of the rare process which was created on to the target system. Or you could even add both if feeling especially adventurous, though I am quite sure that the reality is that it will get too resource heavy. I used the Process Creation as it is a bit easier. I also changed the join kinds to leftouter to see all results from left and only matching from right. I don't want to get multiple lines from single event which is why I grouped the NamedPipes and timestamps with summarize on the final line.

    let lookuptime = 30d;
    let RareFilesCreated =
    DeviceFileEvents
    | where ActionType == 'FileCreated'
    | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFolderPath == @"c:\windows\system32\ntoskrnl.exe"
    | summarize count() by SHA1
    | where count_ < 3 | distinct SHA1; DeviceEvents | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFolderPath == @"c:\windows\system32\ntoskrnl.exe"
    | where ActionType == @"NamedPipeEvent"
    | project DeviceName, NamedPipeTimeStamp = Timestamp, NamedPipeProcess = InitiatingProcessFileName, NamedPipeProcessId = InitiatingProcessId, NamedPipeProcessStartTime = InitiatingProcessCreationTime, NamedPipeProcessSHA1 = InitiatingProcessSHA1, FileOperation=extractjson("$.FileOperation", AdditionalFields, typeof(string)), NamedPipeEnd=extractjson("$.NamedPipeEnd", AdditionalFields, typeof(string)), PipeName=extractjson("$.PipeName", AdditionalFields, typeof(string))
    | join kind=leftouter (
    DeviceFileEvents
    | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFolderPath == @"c:\windows\system32\ntoskrnl.exe"
    | where ActionType == 'FileCreated' 
    | where SHA1 in~ (RareFilesCreated)
    | project DeviceName, FileCreationTimestamp = Timestamp, NamedPipeProcess = InitiatingProcessFileName, NamedPipeProcessId = InitiatingProcessId, NamedPipeProcessStartTime = InitiatingProcessCreationTime, NamedPipeProcessSHA1 = InitiatingProcessSHA1, FileCreated = FileName, FileCreatedSHA1 = SHA1, FileCreatedFolder = FolderPath
    ) on NamedPipeProcessId, NamedPipeProcessSHA1, NamedPipeProcessStartTime
    | project-away NamedPipeProcessId1, NamedPipeProcessSHA11, NamedPipeProcessStartTime1
    | join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFileName =~ "services.exe"
    | where SHA1 in~ (RareFilesCreated)
    | project DeviceName, FileCreated = FileName, FileCreatedSHA1 = SHA1, FileCreatedFolder = FolderPath, StartedProcessCommandLine = ProcessCommandLine, StartedProcessName = FileName, StartedProcessSHA1 = SHA1, StartedProcessParent = InitiatingProcessFileName, StartedProcessTimestamp = Timestamp
    ) on FileCreated, FileCreatedSHA1, FileCreatedFolder
    | where StartedProcessTimestamp between (NamedPipeTimeStamp .. (NamedPipeTimeStamp+1m))
    | project-away  FileCreated1, FileCreatedSHA11, NamedPipeProcess1, DeviceName1, DeviceName2, FileCreatedSHA11
    | summarize NamedPipes = make_set(PipeName), StartedProcessTimestamps = make_set(StartedProcessTimestamp), NamedPipeTimeStamps = make_set(NamedPipeTimeStamp) by DeviceName, NamedPipeProcess, NamedPipeProcessId, NamedPipeProcessSHA1, FileCreated, FileCreatedSHA1, FileCreatedFolder, StartedProcessCommandLine, StartedProcessName, StartedProcessSHA1, StartedProcessParent
    

Moving on to the smbexec. It is less verbose when executed but essentially it is the same which is why I do not add a picture of the shell running the command. I am quite interested to see how much this differs from the RemCom based module though.  Defender was super unhappy with this one and immediately detected it as Impacket:

\[caption id="attachment\_515" align="aligncenter" width="1342"\]![]({{ site.baseurl }}/assets/images/hands_on_keyboard.png) Hands on keyboard activity as alerted by Defender when running smbexec\[/caption\]

Sooooo yeah, a lot of details also included. What is more interesting is that with default settings the Defender XDR started remediation already without asking me. It was stated that the user account was disabled (though I don't know how as it is an AD account and I have no Defender for Identity installed). Nevertheless, my RDP connection was dropped and denied shortly after. While browsing the GUI of Defender I found this:

_Contains the user account by enforcing a policy that prevents or terminates remote activity initiated by potentially compromised accounts through commonly used protocols associated with lateral movement. It might take a few minutes for this change to take effect. See Action Center for more information._

Cool! I am assuming that it would do the action for all the devices to which the agent is installed, however as this is the only device on my instance it is hard to verify. Love the feature though, I am all for automating response on the events which are very likely true positive like this. The next thing was to look for how to lift this. Took a while but then I found the undo button from the action center where the defender took action. So what about hunting?

To me this seems so so noisy that I can't be bothered with creating elaborate hunting rules against this. It is using cmd.exe to run the commands as a service. So basically it is creating a service with the ImagePath being set to something really obvious, like this: _%COMSPEC% /Q /c echo cd ^> \\\\%COMPUTERNAME%\\C$\\\_\_output 2^>^&1 > %SYSTEMROOT%\\gAIxopkL.bat & %COMSPEC% /Q /c %SYSTEMROOT%\\gAIxopkL.bat & del %SYSTEMROOT%\\gAIxopkL.bat_

Queries looking for service creation anomalies should spot this easily. They probably spot the psexec one too but it isn't as obvious especially if the binary name is being changed. [The rare service creation query](https://threathunt.blog/rare-process-launch-as-a-service/) which I posted earlier is able to catch this nicely and it immediately should raise red flags for the hunters.

I will stop here for now and continue on inspecting the Impacket modules on Part 2 - to be released another date. Happy hunting!

[Microsoft GitHub PR](https://github.com/Azure/Azure-Sentinel/pull/10290)

[My Github page](https://github.com/JouniMi/Threathunt.blog/blob/main/impacket_psexec)