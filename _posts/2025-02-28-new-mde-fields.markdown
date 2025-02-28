---
layout: post
title:  "Having a look at a few new fields in MDE"
tags: [threat hunting, kql, mde, featured]
author: jouni
image: assets/images/new_mde_data/mde_data_logo.png
comments: false
categories: [ threat hunting ]
---

Having a look at a few new fields in MDE
=============================
I noticed that there has been a few new fields added to the Advanced hunt tables. These fields can be useful for threat hunting and incident response. There is especially one very interesting field which I have been missing for a long time. This is the ScriptContent ActionType which is now stored in the DeviceEvents table, at least in theory. I was able to see this in one environment, however unfortunately it is not available in my testing environment. I have no idea why, but I would assume that this may have something to do with some features being gradually added to different tenants. Could also maybe be related to versions, my testing devices is W10 and not 11.

Because I don't have this available it is kinda pointless to write about it. This should contain the executed script content which is saved by the amsi inspection feature. The amsi inspection feature is used to inspect scripts that are executed on the endpoint. It is also used to inspect scripts that are downloaded from the internet and thus it can be very useful feature to detect malicious code being executed. It has been available in the MDE for the long time, however it has historically been only available in the device timeline. It is absolutely amazing to see it coming to the Advanced Hunt too!

You can check if you have any hits with the following query:

    DeviceEvents 
    | where ActionType == 'ScriptContent'

I will revisit this topic with some queries utilizing this data when I have it available. I have a few ideas on how to utilize for hunting purposes.

Remote Session information
----------------------------------------------
Several different columns have been added to the tables representing the remote device from which the process is launched. Here is the Microsoft information related to these:

| Column name                              | Type   | Description                                                                                                              |
|------------------------------------------|--------|--------------------------------------------------------------------------------------------------------------------------|
| IsInitiatingProcessRemoteSession         | bool   | Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false) |
| InitiatingProcessRemoteSessionDeviceName | string | Device name of the remote device from which the initiating process's RDP session was initiated                           |
| InitiatingProcessRemoteSessionIP         | string | IP address of the remote device from which the initiating process's RDP session was initiated                            |
| IsProcessRemoteSession                   | bool   | Indicates whether the created process was run under a remote desktop protocol (RDP) session (true) or locally (false)    |
| ProcessRemoteSessionDeviceName           | string | Device name of the remote device from which the created process's RDP session was initiated                              |
| ProcessRemoteSessionIP                   | string | IP address of the remote device from which the created process's RDP session was initiated                               |


As stated within the documentation it indicates the RDP session from which the session was initiated. This can be very valuable information especially for incident response work so I would suggest keeping these in mind for future investigations!

This can be used for threat hunting purposes too. The first idea which came to my mind is to try to see what actions is done in a single RDP session. For example, if you see a lot of suspicious activities in a single RDP session, it might be a sign of an attack. The easiest way to do this would be if there would be a session id saved on the tables but that is not the case. So I just did a crude query grouping sessions by 1d. 

    search in (DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents)
    IsProcessRemoteSession == 1 or IsInitiatingProcessRemoteSession == 1
    | summarize Actions = make_set(ActionType), FileNames = make_set(FileName), CommandLines = make_set(ProcessCommandLine), InitiatingCommandLines = make_set(InitiatingProcessCommandLine), RegKeys = make_set(RegistryKey), RegName = make_set(RegistryValueName), RegData = make_set(RegistryValueData), Timestamps = make_set(Timestamp) by ProcessRemoteSessionIP, ProcessRemoteSessionDeviceName, IsProcessRemoteSession, InitiatingProcessRemoteSessionIP, InitiatingProcessRemoteSessionDeviceName, IsInitiatingProcessRemoteSession, bin(Timestamp, 1d)

This creates a lot of data as there is often a lot of things being done in a single RDP session. The following picture shows a snippet of one of the results.

![]({{ site.baseurl }}/assets/images/new_mde_data/data_example.png)

We could look at the data and spot something suspicious like this:

![]({{ site.baseurl }}/assets/images/new_mde_data/suspicious.png)


Not gonna lie, this isn't amazing. Requires a lot of analysis and is likely not runnable in real environment, but maybe something to get people thinking how to utilize these columns. I think there is just way too much data captured by this query and it should be more limited to a certain threat scenario, or at least to certain activities rather than everything. I don't think is runnable in any production environment like this, unless RDP is not used much at all.

There may be a lot more new information which I am unaware of. These are some new to me features which I have not seen before and I think they are very interesting. I will keep looking into the data that is present in MDE and hopefully will find further gems. I also add queries to this post regarding the new columns as I plan on working on this topic more. These two columns are so new that were failing KQL checks on MS repo when I posted last time as they were not added to the checks, so I will not even try to post this. Though, I wouldn't otherwise either as it is too broad.