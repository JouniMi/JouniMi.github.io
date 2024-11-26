---
layout: post
title:  "Hunting for malicious scheduled tasks"
tags: [threat hunting, kql, mde, scheduled tasks]
author: jouni
image: assets/images/IMG_0104-1024x807.png
comments: false
categories: [ threat hunting ]
---

Why?
====

![]({{ site.baseurl }}/assets/images/IMG_0104-1024x807.png)

Executing code & persistence through scheduled tasks is one of the most common techniques used by the threat actors to persist on a device. I also have noted that quite often the threat hunting is based on something like schtasks being used to create those tasks. This is fine as that is likely the most common way to create the task, but my methodology to threat hunting is to hunt for the underlining operations which the command executes. In this example, the way I like to hunt is by looking into the registry entries which needs to be created for a scheduled task.

As some may remember, I wrote a blog post about [hidden scheduled tasks](https://threathunt.blog/trying-to-hunt-for-a-hidden-scheduled-task/) some time ago which touches the same subject. However, it is far from complete so I am going to have another look. Also, there are different angles which to hunt for. For example, are you hunting for new task creation? What if the retention time has gone already, should you hunt for execution of scheduled task instead?

So let's get started by creating a scheduled task:

![]({{ site.baseurl }}/assets/images/Screenshot-2024-10-06-at-11.07.09.png)
Creating the task.

I created a task which launches notepad, as the picture shows. Don't mind my little brain fart with the naming :).

Hunting for creation
====================

Let's start with the creation of the task. The registry key is not created by the schtasks.exe process itself, rather it is created by svchost: svchost.exe -k netsvcs -p -s Schedule. Is this always the case independent of how the task is created? Very hard to say.

Nevertheless, it seems that the actual command which is launched as a scheduled task is not saved in any registry action at least with MDE - I seem to recollect that I've been able to see the actual launched command too. I had a look at the data and noticed that the event ScheduledTaskCreated in DeviceEvents table does have this information. I also seem to recollect that this wasn't the case always. 

I created a similar task with powershell to check if this is logged in similar fashion.

![]({{ site.baseurl }}/assets/images/Screenshot-2024-10-06-at-11.41.21.png)
Creating scheduled task with Powershell.

It is also saved as a similar entry so I will work with this ActionType. I created a simple query to extract information from the scheduled tasks and then calculate how many times a program & arguments is observed in the environment and show results where the combination has been shown less than 5 times.

    let ScheduledTasks = materialize (
    DeviceEvents
    | where ActionType contains "ScheduledTaskCreated"
    | extend TaskName = extractjson("$.TaskName", AdditionalFields, typeof(string))
    | extend TaskContent = extractjson("$.TaskContent", AdditionalFields, typeof(string))
    | extend SubjectUserName = extractjson("$.SubjectUserName", AdditionalFields, typeof(string))
    | extend Triggers = extractjson("$.Triggers", TaskContent, typeof(string))
    | extend Actions = extractjson("$.Actions", TaskContent, typeof(string))
    | extend Exec = extractjson("$.Exec", Actions, typeof(string))
    | extend Command = extractjson("$.Command", Exec, typeof(string))
    | extend Arguments = extractjson("$.Arguments", Exec, typeof(string))
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, TaskName, Command, Arguments, SubjectUserName, Triggers
    );
    ScheduledTasks
    | summarize count() by Command, Arguments
    | where count_ < 3
    | join ScheduledTasks on Command, Arguments
    | project-away Command1, Arguments1
    

BTW I am sure there is much better way of extracting the nested JSON. I tried to look for a better way for full 2 minutes but all the answers were not either working to this level of nesting or didn't really do it in much refined manner. The query works fine though - there of course is a bit of a chance that it provides way too much noise in your environment to be useful. I would suggest though not to filter based on task name unless you are quite sure what you are doing, given that the malicious code is often hidden under task names mimicing real sheculed tasks (hint. onedrive..).

Hunting for execution
---------------------

The approach for this is to see which process launches the scheduled tasks. As to be expected, it is svchost.exe. The commandline seems to be svchost.exe -k netsvcs -p -s Schedule, same for both of the tasks created here. So this makes it really easy to hunt for all processes which has been started by this specific parent.

The start is easy but as you may know there is ton of different applications being started as scheduled task in Windows. How to know what is malicious? This is quite challenging to filter out but I decided to start by including the usual suspects: cmd.exe, powershell.exe, rundll32.exe, regsvr32.exe and all the binaries not started from C:\\Windows\\System32\\. You probably need to filter to your own needs.

The first query looks for execution of a combination of a file name, command line and path for less than 10 times.

    let RunningScheduledTasks = materialize(
    DeviceProcessEvents
    | where InitiatingProcessFileName == @"svchost.exe"
    | where InitiatingProcessCommandLine == @"svchost.exe -k netsvcs -p -s Schedule"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessId, FolderPath
    | where FileName != @"MpCmdRun.exe"
    | where FolderPath !startswith @"C:\Windows\System32\" or FileName =~ "cmd.exe" or FileName =~ "powershell.exe" or FileName =~ "rundll32.exe" or FileName =~ "regsvr32.exe"
    );
    RunningScheduledTasks
    | summarize count() by FileName, ProcessCommandLine, FolderPath
    | where count_ < 10
    | join RunningScheduledTasks on FileName, ProcessCommandLine, FolderPath
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath, AccountName, count_
    

The second one is a bit more.. longer. I tried to look for a way to save several distinct values of a query to be used as filter within the next table. It wasn't as simple as a thought but I got it done in the end. The idea for this is to look what are the processes actually doing that we are interested in - beware though it can be resource heavy and if the spawned processes do not do anything it will produce no results.

Beware, I have not really used this method before. I see no reason why it wouldn't bring results but I have not tested it extensively. In the end this query makes sets of data to produce findings on a single line.

    let RunningScheduledTasks = materialize(
    DeviceProcessEvents
    | where InitiatingProcessFileName == @"svchost.exe"
    | where InitiatingProcessCommandLine == @"svchost.exe -k netsvcs -p -s Schedule"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessId, FolderPath
    | where FileName != @"MpCmdRun.exe"
    | where FolderPath !startswith @"C:\Windows\System32\" or FileName =~ "cmd.exe" or FileName =~ "powershell.exe" or FileName =~ "rundll32.exe" or FileName =~ "regsvr32.exe"
    | summarize count() by FileName, ProcessCommandLine, FolderPath
    | where count_ < 3
    | summarize
        Names = make_set(FileName),
        CommandLines = make_set(ProcessCommandLine),
        FolderPaths = make_set(FolderPath)
    );
    let Names = RunningScheduledTasks
    | project Names
    | mv-expand extended = Names
    | project asstring = tostring(extended)
    | distinct tolower(asstring);
    let CommandLines = RunningScheduledTasks
    | project CommandLines
    | mv-expand extended = CommandLines
    | project asstring = tostring(extended)
    | distinct tolower(asstring);
    let FolderPaths = RunningScheduledTasks
    | project FolderPaths
    | mv-expand extended = FolderPaths
    | project asstring = tostring(extended)
    | distinct tolower(asstring);
    union DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents
    | where tolower(InitiatingProcessFileName) in (Names)
    and tolower(InitiatingProcessCommandLine) in (CommandLines)
    and tolower(InitiatingProcessFolderPath) in (FolderPaths)
    | sort by Timestamp desc
    | summarize Actions = make_set(ActionType), FileNames = make_set(FileName), RemoteIPs = make_set(RemoteIP) by InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessCreationTime, DeviceName
    
    

And that is it for now! Hopefully these brings value to you.

[MS pull request.](https://github.com/Azure/Azure-Sentinel/pull/11224)

[My repo.](https://github.com/JouniMi/Threathunt.blog/blob/main/sch_tasks)

[Video walkthrough.](https://youtu.be/4aGiqVy9IUM)