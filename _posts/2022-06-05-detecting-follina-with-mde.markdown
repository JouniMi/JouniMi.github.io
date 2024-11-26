---
layout: post
title:  "Detecting Follina with MDE"
tags: [defender for endpoint, kql, mde, threat hunting, follina]
author: jouni
image: assets/images/1.png
comments: false
categories: [ threat hunting ]
---

About a week ago there was a new zero-day office "zero-click" vulnerability noted. This vulnerability was dubbed as Follina by Kevin Beaumont who discovered it while investigating a document originating from Belarus. An article by Kevin is available [here](https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e).

This is very interesting approach to exploit the Office applications, which apparently also applies for powershell.exe when using invoke-webrequest, if using earlier PowerShell version than 6. Also, affecting the net.webclient in case you are wondering. There likely are quite a few queries to detect this stuff already out there, however the more the merrier!

I decided to run the available POC code myself to investigate how this looks like in Defender for Endpoint. The POC that I used is available [here](https://github.com/chvancooten/follina.py). I ran the POC in my lab to see how the execution actually looks like, with a throw-away machine. I only recently rebuilt this part of my home lab and it is interesting to see how well it works now.

Msdt.exe should be spawned as a child process after the vulnerability has been abused. The POC code launches msdt.exe and this is easy to catch.

    DeviceProcessEvents 
    | where InitiatingProcessFileName has_any ("winword.exe","excel.exe","outlook.exe","powershell.exe","powerpnt.exe")
    | where FileName =~ "msdt.exe"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
    

With the POC code, this is the result.

![]({{ site.baseurl }}/assets/images/1.png)
_Simple query to find exploitation of the vulnerability._

When the malicious file is being launched there I thought that there should be a network connection initiated either by msdt.exe or sdiagnhost.exe. The original query can be joined to this data from the same device. Rather interestingly, there was no network connection observed with MDE. I did run the POC on the localhost so maybe for some reason the network connection was not saved to the localhost or something.

I hosted the web server on another host and then the network connection was reported, however it was reported of being initiated by winword.exe and not msdt.exe/sdiagnhost.exe as I expected. Could be that I remember wrong how the exploit works, or there are differences depending on what is being done. This was also the reason why I did not pick-up the first connection - in reality it was made towards the localhost, I just thought that it was something else that Word was doing - silly of me as the remote port was 80. So even the locally ran exploitation **was** recorded as expected. Here is the query.

    DeviceProcessEvents 
    | where InitiatingProcessFileName has_any ("winword.exe","excel.exe","outlook.exe","powershell.exe")
    | where FileName =~ "msdt.exe"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime
    | join (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("winword.exe","excel.exe","outlook.exe","powershell.exe")
    | where RemoteUrl !endswith "microsoft.com"
    | where RemoteUrl !endswith "live.com"
    | project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime, RemoteIP, RemotePort, RemoteUrl, RemoteIPType
    ) on DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime
    | project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime, RemoteIP, RemotePort, RemoteUrl, RemoteIPType, FileName, ProcessCommandLine
    

So this basically looks for msdt.exe being spawned by office apps or powershell.exe and joins the data to a network connection made by the same process, filtering out some MS domains. Results shown below.

![]({{ site.baseurl }}/assets/images/2.png)
_The results, leaving out timestamp and device name._

It is likely that there are more domains that could be filtered out in the DeviceNetworkEvents. Also, another filter "_| where RemoteIPType == "Public"_" should probably be added as it is very unlikely that the attacker server would be running locally. At least with the POC this seems to work nicely, not sure of production though as I have not tested it yet. I would assume that it should be fine though.

I add the query which is looking for the network connection being made by msdt.exe or sdiagnhost.exe too, as the connection is reported in multiple articles of being made by these processes. This does not differ from the earlier query much though. 

    DeviceProcessEvents 
    | where InitiatingProcessFileName has_any ("winword.exe","excel.exe","outlook.exe","powershell.exe","powerpnt.exe")
    | where FileName =~ "msdt.exe"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
    | join (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("msdt.exe","sdiagnhost.exe")
    | project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime, RemoteIP, RemotePort, RemoteUrl, RemoteIPType
    ) on DeviceName
    | project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessCreationTime, RemoteIP, RemotePort, RemoteUrl, RemoteIPType, FileName, ProcessCommandLine
    

It seems that the activity that is started after the vulnerability is abused is launched as a child of svchost.exe. This could also be included in a query, where we take the timestamp of the action and then join in to the events done by svchost.exe shortly after, but this can cause quite a lot of false-positives depending on the filters. I think that these queries should be good to get started with in hunting the actual exploitation and thus I will not go further in the area.

Also, as a bonus, my new POC/MW lab works nicely and as expected. Yay me!