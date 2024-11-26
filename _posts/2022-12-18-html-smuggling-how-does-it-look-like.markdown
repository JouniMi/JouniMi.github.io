---
layout: post
title:  "HTML Smuggling - how does it look like?"
tags: [threat hunting, html smuggling, qbot, splunk, sysmon]
author: jouni
image: assets/images/logo-2.png
comments: false
categories: [ threat hunting ]
---

![]({{ site.baseurl }}/assets/images/logo-2.png)

HTML smuggling is a new technique to deliver malicious payload to the endpoints. The idea of the technique is to deliver the malicious code encoded in an image file that is embedded to a HTML attachment file. The reason for doing it this way is to pass the potential perimeter defenses as the malware is built on the local device. It is being reported on multiple different sites that the HTML smuggling technique is used to drop a ZIP file which contains a malicious JavaScript file. At least some of the most common loaders are reported of using the HTML smuggling technique already, Qbot and Trickbot at least.

I decided to launch the sample found from [here](https://www.malware-traffic-analysis.net/2022/12/09/index.html). ![]({{ site.baseurl }}/assets/images/Image-17.12.2022-at-8.30.jpeg) The contents of the file provided by Malware Traffic Analysis page is shown on the picture to right. It contains the malicious HTML file, PCAP and the Qakbot loader which is stored in the malicious HTML file. The original HTML file is to my interest, from which the infection starts.

I launched the HTML file and it looks as to be expected, similar to the malware-traffic-analysis.net where I acquired the sample.

The HTML page states that it is not able to show you the file correctly and you would need to use a locally downloaded file. This can be seen in the picture below.

![]({{ site.baseurl }}/assets/images/Image-17.12.2022-at-8.35.jpeg)

It automatically downloads a zip file. The zip file contains a **SCAN\_DT6281.img** file, which when clicked asks for the password. This reveals a LNK file which the target of the attack is expected to open. The shortcut points to the following location: _C:\\Windows\\System32\\cmd.exe /c IncomingPay\\Issues.cmd A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9_. Basically, it is starting a cmd -script from a subfolder stored in the img file.

![]({{ site.baseurl }}/assets/images/Image-17.12.2022-at-8.43.jpeg)

The CMD script contents can bee seen on the left. It is somewhat obfuscated, I don't really want to play around with it as I enjoy more running the actual malware an looking how the execution looks like from the endpoint protection perspective.

I started the lnk shortcut and it executed the cmd script. Not very subtle as the actual interactive cmd screen could be seen  for a while, which in some cases might indicate to a user that something funny is going on. Sometimes the users notice these kinds of things - like a mystery black window appearing after clicking something. However, I am sure that more often the user does not report these anomalies, as they often can pop-up in legitimate  means too. Like when running logon scripts.

Next, comes the analysis part. I am interested to see how this looks like from Sysmon. Looking at Splunk, the activity after clicking the shortcut is very normal for a loader like Qbot. **Regsvr32.exe** is launched and a malicious dll file is loaded by the process. Then it injects to **wermgr.exe** and continues to make a C2 connection to several different addresses. It runs some discovery commands while at it, like the loaders normally do.

That's it about the actual loader which was loaded from the malicious HTML file. Next, back to the HTML smuggling technique and especially how it could be hunted for.

Threat hunting
==============

HTML smuggling: Some seconds after the HTML page is launched in Chrome it creates the ZIP file. There isn't anything fancy here, although at the same time some JS files are being created to the temp folder. Someone more skilled with how the browser works would probably know if those are related. I tried to take a look at them they were already gone from the system so I couldn't take a look what they were doing.

![]({{ site.baseurl }}/assets/images/Image-17.12.2022-at-9.00.jpeg)The file creation as recorded by Sysmon is shown on left. There is nothing fancy to the event. It is just a zip file created by the Chrome process. There isn't much to catch on with threat hunting with this, ZIP files are constantly being downloaded by the users.

I decided to restore the snapshots at this stage as the malware still had active C2 communications. I wasn't that interested in seeing to where the infection leads so the data that was gathered already from the HTML smuggling was enough for me.

The next step was to start creating the threat hunting queries. It was a little limited in this case as there wasn't that much to it with the HTML smuggling technique. My initial idea was to look at the HTML file being opened with the browser and then join the data to the ZIP file creation. I know, it is a little lame but at least I couldn't pinpoint much anything else from it.

Maybe it could also be joined to the ISO/IMG based queries where the actual malicious code is launched from those files, however it goes beyond the actual HTML smuggling technique. I'd myself rather have those separated as they are much more broad than only relating to the actual HTML smuggling. Same goes for the regsvr32.exe based DLL loads, I'd rather hunt for those anomalies as on their own.

So, I started with looking for the process launch where the malicious HTML file is launched. I created the following query for this:

    index=sysmon 
    (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) AND EventCode=1 AND (CommandLine:*.html OR CommandLine:*.htm) AND CommandLine:"*--single-argument*" 
    | table _time,host,CommandLine, Image,ParentCommandLine, ProcessId
    

The browsers and the commandlines might change on different browsers, I used Chrome to test the technique. I did add some of the other browsers to the query but I wouldn't count that the cmdline based filter works for them. The next part was to create a query which returns the created zip file. This I did as follows:

    index=sysmon 
    (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) EventCode=15 TargetFilename:*.zip 
    | table _time,host,CommandLine,Image,ProcessId,TargetFilename
    

The interesting finding here is that the ProcessId changes. This probably relates to the way that Chrome handles the child processes but I don't really want to dwell into that as I am not very knowledgeable in that. Nevertheless, the ProcessId can't be used as basis for the join which makes this fairly tough. It can be done without the process id and it works fine in my test environment:

    index=sysmon (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) AND EventCode=1 AND (CommandLine:*.html OR CommandLine:*.htm) AND CommandLine:"*--single-argument*"
    | table _time,host,CommandLine, Image,ParentCommandLine, ProcessId
    | join type=inner host,Image [search index=sysmon (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) EventCode=15 TargetFileName:*.zip | table _time,host,Image,ProcessId, TargetFilename]
    

This is not likely going to work very well in a real environment as there is nothing to tie these two events close to each other. It is just two fairly common events joined to each other using only the process path and this is probably going to result in many benign findings. The only way that I can think of in improving this would be to make the join based on the proximity of the timestamps. I haven't played around the time based joining in SPL at all, so this might not be very sophisticated.

    index=sysmon (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) AND EventCode=1 AND (CommandLine:*.html OR CommandLine:*.htm) AND CommandLine:"*--single-argument*" 
    | table _time,host,CommandLine, Image,ParentCommandLine, ProcessId 
    | eval start_time = _time 
    | eval end_time = _time+60
    | map search="search index=sysmon (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) EventCode=15 TargetFileName:*.zip earliest=$start_time$ latest=$end_time$" | table _time,host,Image,ProcessId, TargetFilename
    

This seems to work, it returns the latter events if they happen 60 seconds after the first event. This potentially might still cause too much noise in a production environment - not sure. Also, this leaves out the data from the first search. Not ideal. I ended up with one more query, which is basically the same as the earlier join but with the usetime=true, earlier=false filter in the join command. This only verifies that the latter event happens after the first, but does not set any boundaries more than that. It is likely possible to do this based on time based join but my SPL skills are a little lacking.

    index=sysmon (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) AND EventCode=1 AND (CommandLine:*.html OR CommandLine:*.htm) AND CommandLine:"*--single-argument*"
    | table _time,host,CommandLine, Image,ParentCommandLine, ProcessId
    | join type=inner usetime=true earlier=false host image [search index=sysmon (image:*chrome.exe OR image:*firefox.exe OR image:*opera.exe OR image:*MicrosoftEdge.exe) EventCode=15 TargetFileName:*.zip | rename _time as FileCreationTime | table FileCreationTime,host,Image,ProcessId, TargetFilename,time]
    

Conclusion
==========

It seems that there isn't too many events to hunt for with the HTML smuggling technique. As interesting as the technique is it doesn't in my opinion open up many hunting opportunities. I would still rather hunt for the events that happen after the HTML smuggling technique. There are so many ways how to the malware can be delivered to the endpoints that targeting a single technique is probably not super effective.

However, targeting things like the regsvr32.exe and rundll32.exe loading malicious image files is much more broad. It doesn't really account for the initial access, however it is quite effective in finding the modern loaders. In my experience these are currently very commonly used although that is of course subject to change anytime in the future. Also, one of my favorite things is targeting the persistence's. I love hunting those!