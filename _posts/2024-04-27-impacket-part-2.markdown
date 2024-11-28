---
layout: post
title:  "Impacket - Part 2"
tags: [threat hunting, defender for endpoint, kql, impacket]
author: jouni
image: assets/images/impacket2_logo.png
comments: false
categories: [ threat hunting ]
---

Hello mr. Impacket – I am back!
========================

Today I will write about Impacket. Last time I wrote about the psexec and smbexec modules which I found to be the most logical start to the series (BTW I would like to remind that 2 posts can be series).  You know, it is a gift which keeps on giving.

![]({{ site.baseurl }}/assets/images/impacket2_logo.png)

WMI, I choose you
--------------------

Today, I would like to start with couple of the WMI based modules. I have some experience when it comes to WMI based attacks, especially the basics. However this is a good opportunity for me to learn more from the subject. Let’s start with wmiexec, another way to gain shell access to the target. This one should be more stealthy than the two which I was writing about in the part 1. So I decided to execute whoami with the silentcommand option. This means that there will be no output, however the actual whoami command will be executed. I tried to run this a bit more stealthy to see if Defender will alert about this with a Christmas tree similar to psexec and smbexec. It did not – there was no alert of this activity.

However this seems to be relatively straight forward to hunt for. It is just a command being executed through WMI so there is good telemetry available from this activity. The whoami.exe process is being executed as a child of wmiprvse.exe. Also the DeviceEvents table contains action ProcessCreatedUsingWmiQuery which straight up shows which process was launched with WMI. So maybe I turn the hunting to something which I think I did on the rare service hunts, find the rare processes started with WMI and find out what the processes are doing.

I included only the process events and network events to the query but you can follow the logic to add further data. File creations for example could work well. To test the query I ran the following command.

![]({{ site.baseurl }}/assets/images/example.png)

I started to create the query using the ProcessCreatedUsingWMIQuery ActionType from the DeviceEvents table. I started by filtering to rare processes started with WMI:

    let LookupTime = 30d; 
    let GetRareWMIProcessLaunches = materialize (
    DeviceEvents
    | where Timestamp > ago(LookupTime)
    | where ActionType == @"ProcessCreatedUsingWmiQuery"
    | where isnotempty(FileName)
    | summarize count() by SHA1, InitiatingProcessCommandLine
    | where count_ < 5
    | distinct SHA1);

The idea is to look for SHA1 + commandline combination which has been seen less than 5 times in the environment. I added CommandLine as the launched powershell.exe process was seen quite a few times in my testing environment – this is left up to you to tinker. The next parts of the query is then taking this filtered data and building results around the rare hits. First pulling the details out from the DeviceEvents table and then joining it to the Process and Network events.

    let LookupTime = 30d;
    let GetRareWMIProcessLaunches = materialize (
    DeviceEvents
    | where Timestamp > ago(LookupTime)
    | where ActionType == @"ProcessCreatedUsingWmiQuery"
    | where isnotempty(FileName)
    | summarize count() by SHA1, InitiatingProcessCommandLine
    | where count_ < 5 | distinct SHA1); 
    DeviceEvents 
    | where Timestamp > ago(LookupTime)
    | where ActionType == @"ProcessCreatedUsingWmiQuery"
    | where SHA1 in~ (GetRareWMIProcessLaunches)
    | where isnotempty(FileName)
    | project DeviceName, WMIProcessLaunchTimestmap = Timestamp, ProcessLaunchedByWMI = tolower(FileName), ProcessLaunchedByWMICommandLine = tolower(ProcessCommandLine), ProcessLaunchedByWMICreationTime =   ProcessCreationTime, ProcessLaunchedByWMISHA1 = tolower(SHA1), ProcessLaunchedByWMIID = ProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentCreationTime, InitiatingProcessParentFileName
    | join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessSHA1 in~ (GetRareWMIProcessLaunches)
    |project DeviceName, ChildProcessTimestamp = Timestamp, ProcessLaunchedByWMI = tolower(InitiatingProcessFileName), ProcessLaunchedByWMICommandLine = tolower(InitiatingProcessCommandLine), ProcessLaunchedByWMICreationTime = InitiatingProcessCreationTime, ProcessLaunchedByWMISHA1 = tolower(InitiatingProcessSHA1), ProcessLaunchedByWMIID = InitiatingProcessId, WMIchild = FileName, WMIChildCommandline = ProcessCommandLine
    ) on DeviceName, ProcessLaunchedByWMI, ProcessLaunchedByWMICommandLine, ProcessLaunchedByWMISHA1, ProcessLaunchedByWMIID
    join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessSHA1 in~ (GetRareWMIProcessLaunches)
    |project DeviceName, ChildProcessTimestamp = Timestamp, ProcessLaunchedByWMI = tolower(InitiatingProcessFileName), ProcessLaunchedByWMICommandLine = tolower(InitiatingProcessCommandLine), ProcessLaunchedByWMICreationTime = InitiatingProcessCreationTime, ProcessLaunchedByWMISHA1 = tolower(InitiatingProcessSHA1), ProcessLaunchedByWMIID = InitiatingProcessId, WMIProcessRemoteIP = RemoteIP, WMIProcessRemoteURL = RemoteUrl
    ) on DeviceName, ProcessLaunchedByWMI, ProcessLaunchedByWMICommandLine, ProcessLaunchedByWMISHA1, ProcessLaunchedByWMIID
    | where isnotempty(WMIProcessRemoteIP) or isnotempty(WMIchild)
    | summarize ConnectedAddresses = make_set(WMIProcessRemoteIP), ConnectedURLs = make_set(WMIProcessRemoteURL), LaunchedProcessNames = make_set(WMIchild), LaunchedProcessCmdlines = make_set(WMIChildCommandline) by DeviceName, ProcessLaunchedByWMI, ProcessLaunchedByWMICommandLine, ProcessLaunchedByWMICreationTime, ProcessLaunchedByWMISHA1, ProcessLaunchedByWMIID

You could potentially leave the let statement out and filter in the first DeviceEvents query, however it can be hard as you can’t use the process ID:s etc there as it would create only unique results in the end, which is why I decided to have the let statement in place. It also makes it easy to filter all the joins so it actually may be more efficient this way. I also included a filter which states that there has to be either a network connection or a child process otherwise the results are not shown.

WMIpersist
--------------------

The next WMI related tool I want to have a look at is wmipersist. This create a WMI event consumer/filter as a persistence method. It is one of the major ways to persist in Windows OS, however it is still much less used than the common three: services, scheduled tasks and runkeys. I’ve been hunting for WMI persistence for many times but I still want to have a look how this work when created with Impacket.

I used the example from the wmipersist documentation:

![]({{ site.baseurl }}/assets/images/Screenshot-2024-04-21-at-9.34.00.png)

This raised an alert in Defender with title “A WMI event filter was bound to a suspicious event consumer“. It is very easy to find the action from the DeviceEvents table with the ActionType “WMIBindEventFilterToConsumer”. The relevant data is stored in the AdditionalFields field, where you can find the name of the consumer created and the data what it does:

    Binding EventFilter:
    instance of __EventFilter
    {
    CreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0};
    EventNamespace = “root\\subscription”;
    Name = “EF_ASEC”;
    Query = “select * from __TimerEvent where TimerID = \”TI_ASEC\” “;
    QueryLanguage = “WQL”;
    };
    Perm. Consumer:
    instance of ActiveScriptEventConsumer
    {
    CreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0};
    KillTimeout = 0;
    MaximumQueueSize = 0;
    Name = “ASEC”;
    ScriptingEngine = “VBScript”;
    ScriptText = “Dim objFS, objFile\nSet objFS = CreateObject(\”Scripting.FileSystemObject\”)\nSet objFile = objFS.OpenTextFile(\”C:\\ASEC.log\”, 8, true)\nobjFile.WriteLine \”Hey There!\”\nobjFile.Close\n”;
    };

So this can be used as a basis for the hunt. This event is present in my testing environment only twice during the past 30 days, however in real environments it may be much more common. What sticks out from the second event is the Consumer type; it is ActiveScriptEventConsumer when running a script. So this is an easy filter. Other than that, it is pretty much looking at the name (which is available in the Consumer field), ScriptingEngine and the ScriptText – I ended up extracting those as their own fields with regex. It can still be a daunting task to state that yes this is malicious only from this information so further analysis is likely to be needed to determine if a hit is malicious.

However depending on the environment the events can be rare – if there are a lot of results a statistical approach can be added to this query. I did not do that because I have no indications of how often this happens in the noisier environments thus I leave that part to the reader.

    let LookupTime = 30d;
    DeviceEvents
    | where Timestamp > ago(LookupTime)
    | where ActionType == "WmiBindEventFilterToConsumer"
    | where AdditionalFields contains "ActiveScriptEventConsumer"
    | extend Consumer = extractjson("$.Consumer", AdditionalFields, typeof(string)),ESS = extractjson("$.ESS", AdditionalFields, typeof(string)), Namespace = extractjson("$.Namespace", AdditionalFields, typeof(string)), PossibleCause = extractjson("$.PossibleCause", AdditionalFields, typeof(string))
    | extend ScriptText = extract(@'\ScriptText = (.*;)',1,PossibleCause), ScriptingEngine = extract(@'\ScriptingEngine = (.*;)',1,PossibleCause)
    | project-reorder Timestamp, DeviceName, Consumer, Namespace, ScriptingEngine, ScriptText

Impacket also offers the wmiquery option for querying information but I will leave that one out as it is not very interesting to hunt for. With that we have reached the end of the line for the WMI based modules of the Impacket tool.

Bonus! Dcomexec
--------------------

(I think) that Dcomexec is the last interactive shell option with Impacket that I have not explored yet which is why I decided to add that to this post. I executed similar activity as with wmiexec (PowerShell invoking webrequest to google.com and running whoami after). This is quite interesting though as it seems a bit stealthy from hunting perspective.

I can see that first explorer is accepting connection from the KALI box on high ports (51823 -> 62995) after which the PowerShell.exe is launched under explorer.exe. This makes it in my opinion interesting as it is quite similar to a user launching PowerShell on their desktop. I created a query which looks for the network connections first towards explorer.exe though I left out the high port filter. Then I joined the data to all processes which were created by the particular explorer.exe process, filtering to instances where the process has been started within a minute after the inbound connection. This resulted in a single hit, which was initiated with Impacket.

After getting the wanted results I continued to enrich the data using the same methodology as with the first query within this post. I am looking into getting all the child processes & network connections of the spawned process – you could also add things like registry events if you’d like. Finally the results looked like this:

![]({{ site.baseurl }}/assets/images/Screenshot-2024-04-26-at-10.21.03-e1714116668331.png)
![]({{ site.baseurl }}/assets/images/Screenshot-2024-04-26-at-10.21.03-1-e1714116737867.png)

With the query a hunter is able to see all the remote IP addresses, Remote URLs, spawned process names and commandlines in a single line. This is to make the analysis faster and easier for the hunter as they do not have to analyze multiple lines to understand what the process has been doing.  Also this was a good reminder that the capitalization of the field contents are not constant within MDE so you need to use the tolower() function when joining using string fields. Without that I got no hits because the FolderPath was including capital letters on some tables. Also, no alert was raised of this activity – which was to be expected considering what the activity looks like on the endpoint.

The final query:

    let LookupTime = 30d;
    DeviceNetworkEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | where ActionType == 'InboundConnectionAccepted' 
    | project InboundConnTimestamp = Timestamp, DeviceName, InboundConnectionToExplorer = RemoteIP, InitiatingProcessFileName, InitiatingProcessCreationTime, InitiatingProcessId
    | join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | project ProcessStartTimestamp = Timestamp, DeviceName, StartedProcessCmdline = tolower(ProcessCommandLine), StartedProcessCreationTime = ProcessCreationTime, StartedProcessId = ProcessId, StartedProcessFileName = tolower(FileName), StartedProcessFolderPath = tolower(FolderPath), InitiatingProcessFileName, InitiatingProcessCreationTime, InitiatingProcessId
    ) on DeviceName, InitiatingProcessFileName, InitiatingProcessCreationTime, InitiatingProcessId
    | where ProcessStartTimestamp between (InboundConnTimestamp .. (InboundConnTimestamp + 1m))
    | join kind=leftouter ( 
    DeviceProcessEvents 
    | where Timestamp > ago(LookupTime) 
    | where InitiatingProcessParentFileName =~ "explorer.exe"
    |project DeviceName, ChildProcessTimestamp = Timestamp, StartedProcessCmdline = tolower(InitiatingProcessCommandLine), StartedProcessCreationTime = InitiatingProcessCreationTime, StartedProcessId = InitiatingProcessId, StartedProcessFileName = tolower(InitiatingProcessFileName), StartedProcessFolderPath = tolower(InitiatingProcessFolderPath), ChildProcessId= ProcessId, ChildProcessName = FileName, ChildProcessCommandLine = ProcessCommandLine 
    ) on DeviceName, StartedProcessCmdline, StartedProcessCreationTime, StartedProcessId, StartedProcessFileName, StartedProcessFolderPath
    | join kind=leftouter ( 
    DeviceNetworkEvents 
    | where Timestamp > ago(LookupTime) 
    | where InitiatingProcessParentFileName =~ "explorer.exe"
    |project DeviceName, ChildProcessTimestamp = Timestamp, StartedProcessCmdline = tolower(InitiatingProcessCommandLine), StartedProcessCreationTime = InitiatingProcessCreationTime, StartedProcessId = InitiatingProcessId, StartedProcessFileName = tolower(InitiatingProcessFileName), StartedProcessFolderPath = tolower(InitiatingProcessFolderPath), RemoteIP, RemoteUrl
    ) on DeviceName, StartedProcessCmdline, StartedProcessCreationTime, StartedProcessId, StartedProcessFileName, StartedProcessFolderPath
    | summarize ConnectedAddresses = make_set(RemoteIP), ConnectedUrl = make_set(RemoteUrl), ChildProcesses = make_set(ChildProcessName), ChildProcessCmdlines = make_set(ChildProcessCommandLine) by DeviceName, InitiatingSourceIP = InboundConnectionToExplorer, StartedProcessCmdline, StartedProcessCreationTime, StartedProcessId, StartedProcessFileName, StartedProcessFolderPath, Timestamp = InboundConnTimestamp

There we have couple more Impacket modules explored and hunting queries created in attempts to catch them. There is a lot more to Impacket and the options are quite broad on what you can achieve with it. I do still have some modules left which I may be interested in so there is a chance that the series will have a third part.

That’s it for now folks, happy hunting!

MS PRs:
[WmiExec](https://web.archive.org/web/20240530104736/https://github.com/Azure/Azure-Sentinel/pull/10399)

[WmiPersist](https://web.archive.org/web/20240530104736/https://github.com/Azure/Azure-Sentinel/pull/10400)

[DcomExec](https://web.archive.org/web/20240530104736/https://github.com/Azure/Azure-Sentinel/pull/10400)

[My GitHub page](https://web.archive.org/web/20240530104736/https://github.com/JouniMi/Threathunt.blog/blob/main/impacket_part2)
