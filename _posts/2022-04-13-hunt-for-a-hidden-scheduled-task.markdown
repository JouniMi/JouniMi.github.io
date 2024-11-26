---
layout: post
title:  "(Trying to) hunt for a hidden scheduled task"
tags: [scheduled tasks, defender for endpoint, kql, mde, threat hunting]
author: jouni
image: assets/images/ps1.png
---

Microsoft DART released [an article](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/) yesterday of how the malware known as Tarrask has been using scheduled tasks for defense evasion. This malware has been in use by an APT group known as HAFNIUM, likely most notable known by leveraging the 0-day known as ProxyShell a year ago.

The article states that the malware has been able to hide the created scheduled tasks from being seen from the GUI by removing SD value under the registry from the created scheduled task. Removing the value requires SYSTEM level privileges and it should not be enough to run the command in elevated cmd. Because the EDR tools should also be saving the registry modifications this should be relatively easy to spot with the tools.

One of the problems is that when you create a new scheduled task with - lets say - PowerShell or schtasks.exe the actual reg keys are not created by these processes. Rather, the registry keys are being written by svchost.exe which makes detecting the actual process which initiated the creation of the scheduled task much harder. This might not be hugely relevant in this particular case, however when looking for anomalies in general from the newly created scheduled tasks this makes it hard.

I started testing this by creating a scheduled task with PowerShell.

\[caption id="attachment\_88" align="alignnone" width="974"\]![](assets/images/ps1.png) _Creating a new scheduled task with PowerShell._\[/caption\]

Running regedit and checking the registry location for the scheduled tasks it can be verified that the SD value is in-place.

\[caption id="attachment\_92" align="alignnone" width="1034"\]![](assets/images/sd_key.png) _SD -key in place for the newly created registry value._\[/caption\]

Finding the created task can be done in multiple ways with MDE, however here is a way to do it using the registry data.

    ```
    DeviceRegistryEvents
    | where Timestamp > ago(1h)
    | where ActionType == @"RegistryKeyCreated"
    | where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\"
    | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, RegistryKey
    ```
    

The last project line sets the fields that are being returned by the query. The actual process that creates this registry entry is noted in the InitiatingProcessFileName column. The following picture shows that it is recorded as svchost.exe.

\[caption id="attachment\_93" align="alignnone" width="1448"\]![](assets/images/reg_creation.png) _Reg key creation._\[/caption\]

Next, I tried to remove the SD value under the LaunchCalc task using elevated PowerShell. This did fail as stated in the article published by DART.

\[caption id="attachment\_94" align="alignnone" width="858"\]![](assets/images/removesdasadmin.png) _Failing to remove the key as admin._\[/caption\]

Running the same command as SYSTEM works fine.

\[caption id="attachment\_96" align="alignnone" width="1396"\]![](assets/images/assystem_notask.png) _Removing the SD key as system. No task left in task scheduler GUI._\[/caption\]

Looking for this event in Defender for Endpoint proved a little bit problematic. Going through all the removed registry keys and values did not yield results. It seems that this might be a decision from Microsoft where the data has been left out. It is understandable that not everything is actually being saved as the amount of data that Microsoft has to handle is absolutely huge. Could also be a mistake in my query of course, which is shared below.
    ```
    DeviceRegistryEvents
    | where Timestamp > ago(1h)
    | where PreviousRegistryKey contains "HKEY_LOCAL_MACHINE"
    | where ActionType == 'RegistryKeyDeleted' or ActionType == 'RegistryValueDeleted'
    ```
    

When logging back in to the device calc.exe is still being executed as to be expected. With a more mature threat hunting program this likely does not matter much as the anomalies in the scheduled tasks creations are likely being already monitored. There are some issues with this approach, mainly because the process that actually created the scheduled task is not revealed in the advanced hunting data, however this can be worked around with multiple methods.

I removed the scheduled task key created to registry using the PowerShell as a system. It seems that this was also not saved in MDE.I removed the GUID based registry key for the task using RegEdit.exe and it was recorded by MDE. Not sure if this could be somehow related to my testing environment but at least this time it seems that the reg mods done as a system did not get recorded.  For further investigation purposes, I also created a new scheduled task as a system. The registry key creation was not recorder from this either, however the creation was saved to the DeviceEvents table and could be found with the following query.
    ```
    DeviceEvents
    | where Timestamp > ago(1h)
    | where ActionType == 'ScheduledTaskCreated'
    ```
    

When I started to write this post about this little niche I thought that this would be quick and easy. I would have liked to present a query to find the events where the attackers might have been trying to evade the defenses by hiding the scheduled task based persistence. As often is, for some reason it wasn't as easy as thought and some hiccups were discovered while at it. It seems that either by testing environment is having issues or registry activity using system account is at least not always being saved.

Normally, my approach for hunting scheduled tasks (and other persistence for that matter) is divided in two. When hunting, I try to hunt for creation of persistence, however in my opinion it is much more interesting to hunt what the persistent binaries are actually doing after launched. That is more relevant and can reveal the actual activity after the creation, especially if for some reason the creation of a persistence is not being saved. With this kind of proactive threat hunting / monitoring it is possible to spot anomalies by the processes that have been launched as scheduled tasks even if the registry modifications are not always saved.