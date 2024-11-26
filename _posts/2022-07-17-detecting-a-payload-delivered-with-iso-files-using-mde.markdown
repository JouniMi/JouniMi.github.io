---
layout: post
title:  "Detecting a Payload delivered with ISO files with MDE"
tags: [defender for endpoint, kql, mde, threat hunting, rundll32, regsvr32, dll loads, ISO]
author: jouni
image: assets/images/image1.png
comments: false
categories: [ threat hunting ]
---

It's been a little quiet on my blog for a while now - reason being that I was on a holiday and rather did other things than sit in front of a computer. Just got back and have some free time to keep on blogging. While I was on a vacation I read an article that Microsoft reverted the change to the disabling macros on documents originating from the internet and once again allows the macros by default. This is interesting as the threat actors had been changing to the ISO files already. It is interesting to see what  happens before the macros will be systematically disabled once more.

It seems that the threat actors have adapted well to the ISO file based approach and there are quite a few examples of this activity. It is likely that the threat actors continue to utilize both attack vectors as long as they are available. One of the great examples of the threat actors using ISO files is the rather new write-up by the Palo Alto Unit 42 of the [Brute Ratel attack framework](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/). The Brute Ratel payload has been deliverer on an ISO file where there was a legitimate binary which then loaded malicious DLL image stored on the same file. Another way that I've seen the malicious payload being launched has been that the LNK file stored in the ISO has started CMD.EXE which then loaded a malicious DLL file from the ISO file using either regsvr32.exe or rundll32.exe.

The ISO files work so that the users have to open them first. When the file is opened it will be mounted as a drive to Windows operating system. First queries that I've created to  detect this were just filtering out everything starting with the letter C, but this approach is prone to noise. I started to investigate for a better way to detect this and I was thinking that there would be a registry entry saved to MDE which then would reveal the drive letter to which the ISO was mounted to, but this seems not to be the case.

However there is a **BrowserLaunchedToOpenUrl** event recorded in the **DeviceEvents** table when a LNK file is executed. This is not really what I was looking for but could still be helpful to detect potentially malicious LNK files being started. Unfortunately, this offers no way to detect the system drive - I am sure that this could be achieved but the ways that comes to my mind currently would require for additional joins which then would cause more overhead to the query so I am leaving that part out. Here is the query for getting the LNK related **BrowserLaunchedToOpenUrl** events, limiting to events where LNK files are being executed and leaving out anything starting with C:. At the end of the query, the drive letter is parsed to it's own column and then everything where there is no drive letter is left out (it's not always recorded). This is a good basis for further queries. 

    DeviceEvents 
    | where ActionType == 'BrowserLaunchedToOpenUrl' 
    | where RemoteUrl endswith ".lnk"
    | where RemoteUrl !startswith "C:"
    | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
    | parse RemoteUrl with Drive '\\' *
    | extend Drive = tostring(Drive)
    | where isnotempty(Drive)
    

The next query uses the first one as basis. Basically, I take the first query and join it to the **DeviceImageLoads** table from where I have removed all the DLL files that are being loaded from the C: drive. Again, there would probably maybe be a better way to do this so that the actual system drive is filtered out instead of the the C: drive, but my crude version does still work. The data is joined using the **DeviceName** and **Drive** column values. The Drive column is the parsed Drive letter from which the LNK file was launched.

DeviceEvents 
| where ActionType == 'BrowserLaunchedToOpenUrl' 
| where RemoteUrl endswith ".lnk"
| where RemoteUrl !startswith "C:"
| project LNKLaunchTimestamp = Timestamp, DeviceName, RemoteUrl
| parse RemoteUrl with Drive '\\\\' \*
| extend Drive= tostring(Drive)
| where isnotempty(Drive)
| join (
DeviceImageLoadEvents
| where FolderPath !startswith "C:"
| parse FolderPath with Drive '\\\\' \*
| project Drive= tostring(Drive), ImageLoadTimestamp = Timestamp, LoadedImageName = FileName, LoadedImageSHA1 = SHA1, LoadedImagePath = FolderPath, DeviceName, ImageLoadProcessName = InitiatingProcessFileName, ImageLoadProcessCmdline = InitiatingProcessCommandLine, ImageLoadProcessFolderPath = InitiatingProcessFolderPath, ImageLoadProcessParent = InitiatingProcessParentFileName
) on DeviceName, Drive
| where ImageLoadTimestamp between (LNKLaunchTimestamp ..(LNKLaunchTimestamp+1m))
| project-away Drive1, DeviceName1
| project-reorder LNKLaunchTimestamp, ImageLoadTimestamp, DeviceName, RemoteUrl, Drive, LoadedImageName, LoadedImageSHA1, LoadedImagePath, ImageLoadProcessName, ImageLoadProcessCmdline, ImageLoadProcessFolderPath, ImageLoadProcessParent

I did also add a filter where the image load timestamp should be at maximum one minute after the LNK file has been opened. This query might be too noisy in some environments and it might cause it be impossible to run, however it seems to work nicely in my testing environment. I created an ISO file where there is an LNK file named SuperLegit.Lnk. This file launches cmd.exe which then launches regsvr32.dll and launch a DLL file named calc.dll from the same ISO file. The query shown catches this very  nicely.

![]({{ site.baseurl }}/assets/images/image1.png)
_Query showing the loaded DLL nicely._

Next, I started to create a query to account for a process being launched from the ISO file. The query follows the same logic, however instead of looking for DLL loads I am chasing process starts. I created a secondary ISO file which had cmd.exe (a legitimate cmd.exe copied to the ISO file), calc.dll and the LNK file starting these in the root. The LNK launched the cmd.exe which then launch the regsvr32.exe and load the calc.dll file from the ISO. This was of course found with the image load based query, however I created the second query if there would be a case where there is no DLL being loaded from the ISO image.

DeviceEvents 
| where ActionType == 'BrowserLaunchedToOpenUrl' 
| where RemoteUrl endswith ".lnk"
| where RemoteUrl !startswith "C:"
| project LNKLaunchTimestamp = Timestamp, DeviceName, RemoteUrl
| parse RemoteUrl with Drive '\\\\' \*
| extend Drive= tostring(Drive)
| where isnotempty(Drive)
| join (
DeviceProcessEvents
| where FolderPath !startswith "C:"
| parse FolderPath with Drive '\\\\' \*
| project Drive= tostring(Drive), StartedProcessTimestamp = Timestamp, StartedProcessName = FileName, StartedProcessSHA1 = SHA1, StartedProcessCommandline = ProcessCommandLine, StartedProcessPath = FolderPath, DeviceName, StartedProcessParentName = InitiatingProcessFileName, StartedProcessParentCmdline = InitiatingProcessCommandLine, StartedParentProcessFolderPath = InitiatingProcessFolderPath, StartedProcessGrandParent = InitiatingProcessParentFileName, Timestamp
) on DeviceName, Drive
| where StartedProcessTimestamp between (LNKLaunchTimestamp ..(LNKLaunchTimestamp+1m))
| project-away Drive1, DeviceName1
| project-reorder LNKLaunchTimestamp, StartedProcessTimestamp, DeviceName, RemoteUrl, Drive, StartedProcessName, StartedProcessSHA1, StartedProcessPath,StartedProcessCommandline, StartedProcessParentName, StartedProcessParentCmdline, StartedParentProcessFolderPath, StartedProcessGrandParent, Timestamp

This also worked fine, and the launched process was returned.

![]({{ site.baseurl }}/assets/images/image2.png)
_Process launch recorded after the LNK file was opened._

And this finishes the current blog post. These are the scenarios that I've witnessed and should likely work relatively fine when hunting for the threat actors using the ISO files. The queries do not target explicitly malicious activity, rather they are trying to look for executions from ISO files. Depending on the environment, this can be legitimately happen quite often so your mileage may vary.