---
layout: post
title:  "Impacket - Part 3"
tags: [threat hunting, defender for endpoint, kql, impacket]
author: jouni
image: assets/images/impacket3_logo.png
comments: false
categories: [ threat hunting ]
---

Continuing with Impacket
========================

I will do one more post on the series and that will be it. The first post was mostly about the different ways that Impacket can launch semi-interactive shells, the second one was revolving around using WMI based techniques. On the third one I will go through some of the modules which interest me and it may be a bit random.

![]({{ site.baseurl }}/assets/images/impacket3_logo.png)

Impacket-secretsdump
--------------------

Starting with the secretsdump which is performing a various of different techniques to dump secrets from the remote machine. It would be some sort of miracle if it wouldn't paint the Defender alert console red with alerts. No miracles there, we have a cool alert of the activity:

![]({{ site.baseurl }}/assets/images/Screenshot-2024-05-09-at-8.13.09.png)
Defender alerting about dumping the credentials.

As the picture shows the Defender also took some actions which I am fairly interested in. So I'll hop to the action center to see what did it do to disrupt the attack to find out that there actually wasn't anything else done than user containment, similar which was done on the first part of the Impacket series. So nothing new but maybe there would have been more activity if I had the full XDR stack deployed instead of a single component. Anyway, here is a cool pick of the activity taken.

![]({{ site.baseurl }}/assets/images/Screenshot-2024-05-09-at-8.16.55.png)
Defender containing a user account.

There are a lot of things happening here, the RemoteRegistry service is disabled on the target system so the Secretsdump feature first enables the service and then starts it, after which it proceeds to dump the secrets from the target machine. There are quite clear indicators left on the timeline of the activity, actually so clear indicators like "svchost.exe saved LSA Secrets to mrsdDEMR.tmp" that I am wondering if these can be found from the advanced hunt.

![]({{ site.baseurl }}/assets/images/Screenshot-2024-05-09-at-8.36.22.png)
Secretsdump activity shown on timeline.

Unfortunately for some reason the advanced hunting page is not working for me at the time of looking the alerts. It is only returning a white page so it is a bit hard to determine what I can see in the advanced hunt. I would assume that it will not be as clear as on the timeline though. One interesting question is though, is there anything to hunt here anyway? It is relatively noisy already - maybe the remote registry modifications could be something to hunt for as it may be something that is rare within the environments. Sounds a bit boring to me though.

So I waited a bit and the advanced hunting does not continue to work. However, it did work with secondary account so I was a bit baffled. After debugging a bit I noticed that it will always break if I click the "hunt for related events button" on Device Timeline. For some reason, after clicking that button the advanced hunting is loading only a white page so there potentially is a bit of a bug there currently. It will apparently try to load the query behind the hunt for related events button but can't and returns a white page.

![]({{ site.baseurl }}/assets/images/Screenshot-2024-05-11-at-8.42.45.png)
Clicking the hunt for related events breaks the advanced hunting feature for me. Boo.

I got this fixed by reloading the page for kazillion times and trying to close the query page which is trying to load the problematic query. I can click one or two times before the screen is going full white and after doing this for a bit it will work once more. Nevertheless after it works I was able to see that the interesting data is available in advanced hunting too, it is in the DeviceEvents table under the OtherAlertRelatedActivity ActionType.

![]({{ site.baseurl }}/assets/images/Screenshot-2024-05-11-at-9.05.39.png)
Cool information stored with the alert.

I don't necessarily want to create a query around this as it does not make much sense to me to hunt based on alerted events. I am not saying it would not make any sense, sometimes it can be a good idea.  There is an interesting NamedPipe being opened from the source device with a pipe name pointing to winreg. This could be quite rare:

    DeviceEvents
    | where ActionType == "NamedPipeEvent"
    | where isnotempty(RemoteIP)
    | where AdditionalFields contains "winreg"
    | project DeviceName, Timestamp, RemoteIP, PipeName = extractjson("$.PipeName", AdditionalFields, typeof(string)), RemoteClientsAccess = extractjson("$.RemoteClientsAccess", AdditionalFields, typeof(string)), ShareName = extractjson("$.ShareName", AdditionalFields, typeof(string)), AdditionalFields
    

This as of itself is probably not enough though it could provide to be so rare that no additions are actually needed. I did a join to the registry event where the remote registry is being enabled on the device. I am a little unsure if this makes any difference though.

    DeviceEvents
    | where ActionType == "NamedPipeEvent"
    | where isnotempty(RemoteIP)
    | where AdditionalFields contains "winreg"
    | project DeviceName, Timestamp, RemoteIP, PipeName = extractjson("$.PipeName", AdditionalFields, typeof(string)), RemoteClientsAccess = extractjson("$.RemoteClientsAccess", AdditionalFields, typeof(string)), ShareName = extractjson("$.ShareName", AdditionalFields, typeof(string)), AdditionalFields
    | join (
    DeviceRegistryEvents
    | where RegistryKey == @'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteRegistry'
    | where RegistryValueName == @"Start"
    | where RegistryValueData == @"3"
    | project DeviceName, RegEditTimestamp = Timestamp, ActionType, RegistryKey, RegistryValueData, RegistryValueName, RegistryValueType
    ) on DeviceName
    | where RegEditTimestamp < Timestamp
    | project-away DeviceName1
    

The query is looking for remote registry being set to manual, as at least on the device which I was running the tests on had it disabled when starting. It is not really touching the actual dumping activity. Hunting for actual dumping is actually kinda hard as the information is not available in elsewhere than the OtherAlertRelatedActivity action. The file creations by svchost.exe when the data is dumped to a file are not present in the DeviceFileEvents table. The following is one of the files created: \\Device\\HarddiskVolume3\\Windows\\Temp\\mrsbDEMR.tmp - maybe this is left out from the telemetry to reduce noise. Nevertheless, there isn't a good angle unless using the OtherAlertRelatedActivity which I presume is not available if there is no alert raised.

AtExec
------

There are very interesting  scripts in Impacket like GetNPUsers and GetUserSPNs which would be interesting to test out, however they are targeting the Active Directory domain and I do not have visibility with Defender for Identity to my Domain Controllers so it makes no sense to have a look at these at this time. Many of the others are quite limited to a certain specific situation which makes them less interesting to me to look through, which is why I decided to, as a final part to this series, have a look at atexec.

This was immediately noticed by the Defender and alerted about. The defender also reported this as Impacket.

![]({{ site.baseurl }}/assets/images/Screenshot-2024-06-01-at-10.20.32.png)
Alerts of AtExec usage.

This is actually quite interesting! The scheduled task is created with help of a named pipe called **\\Device\\NamedPipe\\atsvc.** A registry key is created: HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\**DfJZjSFJ** where the last, bolded, part is the name of the created service. Interestingly though the actual command launched as a service is not recorded anywhere in the telemetry. However, with the information we have here we can make a join to a child process of svchost.exe to correlate what the actual task does. This may not be 100% accurate though - beware. 

I created a query which looks for the named pipes first with name atsvc. Then it is joined to registry events, filtering to events which happen close to the named pipe event. Finally it is joined to a process started by the same svchost.exe process which creates the registry key, picking the processes started 2 minutes after the registry key has been created.

    let lookuptime = 30d;
    DeviceEvents
    | where Timestamp >ago(lookuptime)
    | where ActionType == 'NamedPipeEvent' 
    | where AdditionalFields contains "atsvc"
    | project DeviceName, Timestamp, DeviceId, RemoteIP, PipeName = extractjson("$.PipeName", AdditionalFields, typeof(string)), RemoteClientsAccess = extractjson("$.RemoteClientsAccess", AdditionalFields, typeof(string)), ShareName = extractjson("$.ShareName", AdditionalFields, typeof(string))
    | join (
    DeviceRegistryEvents
    | where Timestamp >ago(lookuptime)
    | where ActionType == 'RegistryKeyCreated' 
    | where RegistryKey contains @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\"
    | project RegTimestamp = Timestamp, DeviceName, DeviceId, RegistryKey, RegistryValueData, RegistryValueName, RegistryValueType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime
    ) on DeviceName, DeviceId
    | where RegTimestamp between ((Timestamp - 2m) .. (Timestamp + 2m))
    | join (
    DeviceProcessEvents
    | where Timestamp >ago(lookuptime)
    | where InitiatingProcessFileName =~ "svchost.exe"
    | where InitiatingProcessCommandLine contains "Schedule"
    | project DeviceId, DeviceName, FileName, ProcessCommandLine, ProcessId, ProcessStartTimestamp = Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime
    ) on DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime
    | where ProcessStartTimestamp between ( Timestamp .. (Timestamp +2m))
    | project DeviceName, Timestamp, StartedProcess = FileName, StartedProcessCommandLine = ProcessCommandLine, StartedProcessId = ProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime, RegistryKey, RemoteIP, PipeName
    

It works great in my testing environment:

![]({{ site.baseurl }}/assets/images/Screenshot-2024-06-01-at-16.59.41.png)
Results from the query.

And that is it for Impacket. I might revisit it if I decide to get the MDI license to my testing environment, there are cool modules which are targeted more against AD. Anyway, have a great day and happy hunting!

I decided to leave the first query out from MS repo. I don't think it creates enough value. The second one is better so:

[AtExec](https://github.com/Azure/Azure-Sentinel/pull/10563)

[My repo containing both queries](https://github.com/JouniMi/Threathunt.blog/blob/main/impacket_part3)