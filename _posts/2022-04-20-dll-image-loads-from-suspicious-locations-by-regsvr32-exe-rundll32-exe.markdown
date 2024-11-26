---
layout: post
title:  "DLL image loads from suspicious locations by regsvr32.exe / rundll32.exe"
tags: [dll loads, defender for endpoint, kql, mde, threat hunting, rundll32, regsvr32]
author: jouni
image: assets/images/loading_dll.png
comments: false
categories: [ threat hunting ]
---

DLL images are being used quite a lot by the attackers to load their malicious code. I've done several different queries that are targeting this attack technique. I have been having an idea of taking a look at DLL files that are being loaded from abnormal locations and then building more information around this. This is probably a relatively hard thing to do because of the amounts of DLL being loaded in the Windows environments.

So, how to determine the suspicious locations? First things first, little bit of knowledge / research from the past shows that the attackers are often utilizing the same folders. Another approach which I am showing here is to look for the rare folders statistically with MDE. I am very bad at regex so there probably are typos in the regex used in the queries - sorry about that for all the regex lovers. The idea of the following query is to get the folder from the FolderPath column without the actual filename. This way it is relatively easy to spot the folders where there isn't much dll:s being loaded.

    DeviceImageLoadEvents
    | where Timestamp > ago(1h)
    | extend folder = extract(@".*\\", 0, FolderPath)
    | summarize count() by folder

Unfortunately, there are way too many of these folders. I tried to apply filtering only targeting ProgramData and users folders. This did not bring much luck and was still just absolutely ridiculously too noisy even in my testing environment with only couple of devices. 

    DeviceImageLoadEvents 
    | where FolderPath startswith @"C:\users" or
     FolderPath matches regex @".:\\ProgramData.[^\\\s]+.dll"
    | where Timestamp > ago(1h)
    | extend folder = extract(@".*\\", 0, FolderPath) 
    | summarize count() by folder

As this seemed to be once again those missions that seem just a little bit too much for my brains at least for now I decided to move on towards targeting only rundll32.exe and regsvr32.exe.

    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "regsvr32.exe" or InitiatingProcessFileName =~ "rundll32.exe"
    | where FolderPath startswith @"C:\users" or
     FolderPath matches regex @".:\\ProgramData.[^\\\s]+.dll" or
     FolderPath matches regex @".:\\Windows.[^\\\s]+.dll"
    | extend folder = extract(@".*\\", 0, FolderPath) 
    | summarize count() by folder

Even this can be a little bit too noisy. Checking the individual DLL files by file SHA1 hash shows that there is hope and most of the DLL files are being loaded quite often, more than 10 times. I am trying to look for the ones that are more rare so this can be a good place to get further.

    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "regsvr32.exe" or InitiatingProcessFileName =~ "rundll32.exe"
    | where FolderPath startswith @"C:\users" or
     FolderPath matches regex @".:\\ProgramData.[^\\\s]+.dll" or
     FolderPath matches regex @".:\\Windows.[^\\\s]+.dll"
    | extend folder = extract(@".*\\", 0, FolderPath) 
    | summarize count() by SHA1

At this stage I need to do a bit of filtering on the data. Because of this I will use the materialize operator which caches the results so I don't have to run the same query twice. Also, I only project the columns that I am interested of while also giving some of the columns more easy to understand names.

    let GenerateDLLloads = materialize (
    DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "regsvr32.exe" or InitiatingProcessFileName =~ "rundll32.exe"
    | where FolderPath startswith @"C:\users" or
     FolderPath matches regex @".:\\ProgramData.[^\\\s]+.dll" or
     FolderPath matches regex @".:\\Windows.[^\\\s]+.dll"
    | extend folder = extract(@".*\\", 0, FolderPath)
    | project LoadedDllSHA1 = SHA1, LoadedDllName = FileName, DllLoadTimestamp = Timestamp, DeviceId, DeviceName, folder, DllLoadProcessCommandLine = InitiatingProcessCommandLine, DllLoadProcessCreationTime = InitiatingProcessCreationTime, DllLoadProcessFileName = InitiatingProcessFileName, DllLoadProcessProcessId = InitiatingProcessId, DllLoadProcessSHA1 = InitiatingProcessSHA1, DllLoadProcessParentCreationTime = InitiatingProcessParentCreationTime, DllLoadProcessParentFileName = InitiatingProcessParentFileName, DllLoadProcessParentId=InitiatingProcessParentId
    );
    GenerateDLLloads
    | summarize count() by LoadedDllSHA1 
    | where count_ < 5 | join kind=inner GenerateDLLloads on LoadedDllSHA1 

Now it is time to look for file creations of the loaded DLL files - again renaming some of the fields to make them easier to follow. It is likely that this could be done with commandline based queries - but what is the fun in that? My idea often is to create queries around the actual events rather than the commandlines of the started processes. This way it can be actually proven that the event took place. Also, sometimes the commandlines are not to be trusted although in the case of rundll32.exe and regsvr32.exe they probably would work. The query will also only show results if the file creation has been recorder - if there is no event for this the results are dropped.

    let GenerateDLLloads = materialize (
    DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "regsvr32.exe" or InitiatingProcessFileName =~ "rundll32.exe"
    | where FolderPath startswith @"C:\users" or
     FolderPath matches regex @".:\\ProgramData.[^\\\s]+.dll" or
     FolderPath matches regex @".:\\Windows.[^\\\s]+.dll"
    | extend folder = extract(@".*\\", 0, FolderPath)
    | project LoadedDllSHA1 = SHA1, LoadedDllName = FileName, DllLoadTimestamp = Timestamp, DeviceId, DeviceName, folder, DllLoadProcessCommandLine = InitiatingProcessCommandLine, DllLoadProcessCreationTime = InitiatingProcessCreationTime, DllLoadProcessFileName = InitiatingProcessFileName, DllLoadProcessProcessId = InitiatingProcessId, DllLoadProcessSHA1 = InitiatingProcessSHA1, DllLoadProcessParentCreationTime = InitiatingProcessParentCreationTime, DllLoadProcessParentFileName = InitiatingProcessParentFileName, DllLoadProcessParentId=InitiatingProcessParentId
    );
    GenerateDLLloads
    | summarize count() by LoadedDllSHA1 
    | where count_ < 5 
    | join kind=inner GenerateDLLloads on LoadedDllSHA1 
    | join ( 
    DeviceFileEvents 
    | where Timestamp > ago(7d)
    | where ActionType == 'FileCreated' or ActionType == 'FileRenamed'
    | extend folder = extract(@".*\\", 0, FolderPath)
    | project LoadedDllSHA1 = SHA1, LoadedDllName = FileName, folder, DllCreationTimestamp = Timestamp, DeviceId, DeviceName, DllCreationProcessCommandLine = InitiatingProcessCommandLine, DllCreationProcessCreationTime = InitiatingProcessCreationTime, DllCreationProcessFileName = InitiatingProcessFileName, DllCreationProcessId = InitiatingProcessId, DllCreationProcessSHA1 = InitiatingProcessSHA1, DllCreationProcessParentCreationTime = InitiatingProcessParentCreationTime, DllCreationProcessParentFileName = InitiatingProcessParentFileName, DllCreationProcessParentId = InitiatingProcessParentId
    ) on LoadedDllName, LoadedDllSHA1, folder, DeviceName
    | project LoadedDllSHA1, LoadedDllName, DllLoadTimestamp, DllCreationTimestamp, DllLoadProcessCommandLine, DllLoadProcessFileName, DllLoadProcessParentFileName, DllCreationProcessCommandLine, DllCreationProcessFileName, DllCreationProcessParentFileName, DeviceName, DllLoadProcessSHA1, DllCreationProcessSHA1, folder, DllLoadProcessCreationTime, DllLoadProcessProcessId, DllLoadProcessParentCreationTime, DllLoadProcessParentId, DllCreationProcessCreationTime, DllCreationProcessId, DllCreationProcessParentCreationTime, DllCreationProcessParentId, DeviceId

The query is getting relatively CPU heavy at this stage and I am sure that it will be impossible to run in the very large environments, at least in any meaningful time frame. Next, I'd like to try it out so I downloaded a dll file with a normal browser. After downloading the file I launched it with rundll32.exe.

![]({{ site.baseurl }}/assets/images/loading_dll.png)
_Loading the DLL file to start calc._

The query should now return the results. And it does.

![]({{ site.baseurl }}/assets/images/hit_mde.png)
_DLL load and creation_

So the idea of the query is that it is looking for loaded DLL Files from c:\\users\\\*, c:\\windows\\ or c:\\programdata\\ folders by the rundll32.exe and regsvr32.exe processes. After the image has been loaded the query filters out all the dll files that have been loaded more than 5 times. Then the results are joined to the file events table, looking for the creation of the DLL file - to reveal the actual process which wrote the file to the disk. After getting the results it's possible to analyze the process which created the DLL which is helpful when determining if the activity was malicious or not.

It would be cool to get more information out of that process, however the query is already CPU heavy so I didn't want to add anything more to it. I am sure that this can be done more efficiently or that I am overthinking it. I tend to overthink on many of the queries that I create which causes unnecessary bloat. I do enjoy to revisit older queries sometimes and start to make them more efficient. This topic could be analyzed much further but I think this is it for now. Maybe I'll revisit this sometime in the future.

This is now the third post on my blog and so far it has been very enjoyable to write these. I will not be updating the blog once a week in the future, this is just too much fun when getting started. Hopefully someone gets something out of these, although I guess it is enough that I enjoy writing them. I might be moving the finished queries to Github at some stage as they are much easier to handle and copy from there. Especially if I will be continuing this blog for a longer period of time.