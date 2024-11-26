---
layout: post
title:  "Rare process launch as a service"
tags: [threat hunting, defender for endpoint, kql, persistence, service]
author: jouni
image: assets/images/logo-300x233.png
comments: false
categories: [ threat hunting ]
---

Back after a long break
=======================

The last post on this blog was published on mid-September 2023 so it has been a while since I was able to update the blog. The main reason for this is that I have been too busy. I've had extremely busy season at work and on top of that I also have had a lot of things to do in my personal life. Also, I've run a little low on ideas of what to post about. I have a draft which is relating around using the API of OpenCTI to use IOCs on other platforms, which I may or may not finish in the future.

However, what inspired me to start blogging again is that I noticed that Microsoft is now offering directly the Defender for Endpoint P2 licenses which include the full defender for endpoint package, with advanced hunting. This gives me access to the platform with a relatively low price and as some of the readers may know I just absolutely love threat hunting with MDE / KQL. It is efficient and great language and the biggest limitation in my opinion is that the data is only available from the past 30 days. This should not be a problem for a continuous threat hunting program, however for those project based setups it can cause retention issues. That is however outside of the content of this post.

So, what now that I have access to MDE advanced hunting? Well I will most likely start posting a little query here and there. My idea is to also add them to the official Microsoft repo (available [here](https://github.com/Azure/Azure-Sentinel)), if the process is not adding too much of overhead. This way they would be easier for anyone to utilize in the future as they are available from the Advanced Hunting GUI. I am hoping that this will require a little less effort for each of the posts, making it easier to post more frequently. I also do think that these could prove value to others more directly, which is a great motivator for me.

I started by having a look at the older queries which I've been created and added the ones which I think can prove valuable to a single [PR](https://github.com/Azure/Azure-Sentinel/pull/9854).

The query of the day
====================

![]({{ site.baseurl }}/assets/images/logo-300x233.png)

The query which I'd like to introduce today is all about launching code through a Windows service. I will go through the query function by function first. The query itself will be explained a little better at the last stage of the post, also where the full query is available.

The first part of the query sets the lookup time. How long back do you want the query to go? The maximum is 30 days currently. Then we add the whitelisted processes to a pack\_array called WhiteList. Next, we will materialize the basis of the query, as we will use this as basis of the statistical filter and join back to it. With materialize the  query does not need to be executed twice, saving calculations.

    let LookupTime = 30d; 
    let WhiteList = pack_array(
    "svchost.exe",
    "mssense.exe",
    "msmpeng.exe",
    "searchindexer.exe",
    "microsoftedgeupdate.exe"
    );
    let GetServices = materialize (
    DeviceProcessEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, StartedChildProcess = FileName, StartedChildProcessSHA1 = SHA1, StartedChildProcessCmdline = ProcessCommandLine, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName
    );
    
The next part of the query calculates how many times each process on each of the endpoints have been launched as a child of services.exe. The data is then joined back to the original results from the query.

    | join kind = leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, NetworkAction = ActionType, RemoteIP, RemoteUrl
    ) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    | join kind = leftouter (
    DeviceFileEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, FileAction = ActionType, ModifiedFile = FileName, ModifiedFileSHA1 = SHA1, ModifiedFilePath = FolderPath
    ) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    | join kind = leftouter (
    DeviceImageLoadEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, LoadedDLL = FileName, LoadedDLLSHA1 = SHA1, LoadedDLLPath = FolderPath
    ) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    

The last part of the query uses summarize and make\_set function to gather information from all the tables to a single line on the resulted table. This makes analysis of each of the results much easier. I did not add all the projected fields to the final part, but they are easily added if needed. It just makes the output potentially hard to understand.

    | summarize ConnectedAddresses = make_set(RemoteIP), ConnectedUrls = make_set(RemoteUrl), FilesModified = make_set(ModifiedFile),FileModFolderPath = make_set(ModifiedFilePath),FileModHA1s = make_set(ModifiedFileSHA1), ChildProcesses = make_set(StartedChildProcess), ChildCommandlines = make_set(StartedChildProcessCmdline), DLLsLoaded = make_set(LoadedDLL), DLLSHA1 = make_set(LoadedDLLSHA1) by DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    

The final output should be something like this:

![](http://threathunt.blog/wp-content/uploads/2024/01/services.png)
_Example of the output._

The complete query
------------------

The idea of this query is to look for rarely seen processes which are launched as a service. This query will not likely hit a persistent malware being launched daily basis as a service, rather it hits the occurrences where Windows services are being used to launch malicious code. Cobalt Strike is one example of where the code is often being launched as a service and the service is removed after. The query then gathers more information of the process and shows the results in a single line, to make analysis a little bit easier.

A lot of tinkering may be needed for each of the individual environments. With this amount of joins it will be quite heavy to run and also it can provide way too many results. The count can be lowered to find those real anomalies. The beauty of the query in my opinion is in the collection of activities to a single line. The same approach is applicable on different situations which can prove a lot of value for the actual analysis of the data. This way it makes it easier to identify the potentially malicious instances from something legitimate with a quick glance.

That's it for now! Here is the final query, with Git links in the bottom.

    let LookupTime = 30d;
    let WhiteList = pack_array(
    "svchost.exe",
    "mssense.exe",
    "msmpeng.exe",
    "searchindexer.exe",
    "microsoftedgeupdate.exe"
    );
    let GetServices = materialize (
    DeviceProcessEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, StartedChildProcess = FileName, StartedChildProcessSHA1 = SHA1, StartedChildProcessCmdline = ProcessCommandLine, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName
    );
    GetServices
    | summarize count() by ServiceProcess, DeviceName
    | where count_ < 6 
    | join kind = inner GetServices on ServiceProcess, DeviceName 
    | join kind = leftouter ( DeviceNetworkEvents | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, NetworkAction = ActionType, RemoteIP, RemoteUrl
    ) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    | join kind = leftouter (
    DeviceFileEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, FileAction = ActionType, ModifiedFile = FileName, ModifiedFileSHA1 = SHA1, ModifiedFilePath = FolderPath
    ) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    | join kind = leftouter (
    DeviceImageLoadEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessParentFileName contains "services.exe"
    | where InitiatingProcessFileName !in~(WhiteList)
    | project Timestamp, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, LoadedDLL = FileName, LoadedDLLSHA1 = SHA1, LoadedDLLPath = FolderPath
    ) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    | summarize ConnectedAddresses = make_set(RemoteIP), ConnectedUrls = make_set(RemoteUrl), FilesModified = make_set(ModifiedFile),FileModFolderPath = make_set(ModifiedFilePath),FileModHA1s = make_set(ModifiedFileSHA1), ChildProcesses = make_set(StartedChildProcess), ChildCommandlines = make_set(StartedChildProcessCmdline), DLLsLoaded = make_set(LoadedDLL), DLLSHA1 = make_set(LoadedDLLSHA1) by DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
    

[PR](https://github.com/Azure/Azure-Sentinel/pull/9895) to MS hunting repo.

My [Git page](https://github.com/JouniMi/Threathunt.blog/blob/main/rare_process_as_a_service) storing the query.