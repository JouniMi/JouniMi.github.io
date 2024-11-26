---
layout: post
title:  "Hunting for msbuild based execution"
tags: [threat hunting, kql, splunk, msbuild]
author: jouni
image: assets/images/msbuild_logopng.png
comments: false
categories: [ threat hunting ]
---

Why?
====

There has been a new [Advanced Persistent Threat group, named Dark Pink](https://www.group-ib.com/media-center/press-releases/dark-pink-apt/) which have been using the msbuild.exe LOLBIN for doing their malicious deed. The group has been especially active in the APAC area, with some activity in Europe too - specifically in Bosnia and Herzegovina - weirdly enough. The group is mostly targeting military organizations so it is not a common threat for all the organizations. They have been reportedly using the **msbuild.exe** to launch the malicious code and this raised my interest. throughout my hunts and incident response investigations , I have not seen msbuild.exe being used that much. It is being used legitimately though, but not that commonly.

**Msbuild.exe** is the binary for the Microsoft Build Engine platform. This platform is used to build applications. It is being used by, for example, Visual Studio but my understanding is that it is included in .NET Framework starting from the version 4. It does not require for any IDE being installed on the system. Thus, this is a great lolbin for a threat actor as the .NET framework is commonly installed to most Windowses.

![]({{ site.baseurl }}/assets/images/msbuild_logopng.png)

Running  tests
==============

I thought that using [Atomic Red Team](https://atomicredteam.io/) would be a great start for this test. Atomic Red team is a collection of tests which can be ran in a bunch or individually to test, for example, if your monitoring solution is capable of detecting the techniques. It is mapped to Mitre ATT&CK - the tests (called Atomics) are used to test individual techniques from the Mitre ATT&CK Matrix. It does include [tests](https://atomicredteam.io/defense-evasion/T1127.001/) which use MSbuild.exe so it makes testing easy.

The first test is running C# and the second one Visual Basic. As they are otherwise completely the same there is no need to run both of them. I launched the first one and then started to look what that is like within Log analytics. There are a few actions taken but from these, there is nothing to exactly hunt for, except the actual **commandline** of the **msbuild.exe** process which shows from which folder the file has been launched. These tests are then not ideal for hunting for activity which happens after.

I tried to look for a little more information how the actual malicious usage works within the attack conducted by the Dark Pink group. Unfortunately at the time of the writing the information was very hazy. Looking elsewhere, I found a [great article by Cisco Talos](https://blog.talosintelligence.com/building-bypass-with-msbuild/) about how the **msbuild.exe** has been used in different scenarios. There is great amount of information of how abusing the msbuild.exe can show with many tips on hunting the said activity too.

The intake from the article is that there are many ways how it has been used.  These seem to be based more or less on spawning a child process and then launching further badness with those child processes, or further injecting to the spawned child processes. These offer some scenarios for threat hunting. It seems that looking at the child processes is a good idea, especially after ruling out false-positives.

As the article lists few different potential child processes I added them all to the query. This is not very complex query, I know.

    sysmon
    | where ParentImage endswith "msbuild.exe"
    | where Image has_any ("iexpolore.exe","powershell.exe","cmd.exe","pwsh.exe","wscript.exe")
    | project TimeGenerated, Computer, Image, CommandLine, ParentImage, ParentCommandLine

One option would be to only show results which  are rare. In the query below it will only show results if the child process has been seen less than 5 times. This could be also done by percentage, however that might not work that well within most environments as using msbuild.exe is relatively rare. Also I'd play with the actual child processes and potentially even remove the whole filter - only filtering out csc.exe which (I think) is spawned every time that the msbuild.exe is being launched.

    let processes = materialize (
    sysmon
    | where ParentImage endswith "msbuild.exe"
    | where Image has_any ("iexpolore.exe","powershell.exe","cmd.exe","pwsh.exe","wscript.exe")
    | project TimeGenerated, Computer, Image, CommandLine, ParentImage, ParentCommandLine
    );
    processes
    | summarize count() by Image
    | where count_ < 5
    | join kind=inner processes on Image

Not really that interesting or special still though, but could prove to be fruitful. Event id 8 (create remote thread) and event id 10 (process access) would likely be great at detecting malicious usage of the msbuild.exe tool.

    sysmon
    | where EventID == 10 or EventID == 8
    | where SourceImage endswith "msbuild.exe"
    | project TimeGenerated, Computer, TargetImage, SourceImage, EventID, CallTrace

And similarly to the child processes, these instances could be counted and then only the ones which don't occur often shown as the results.

    let processes = materialize (
    sysmon
    | where EventID == 10 or EventID == 8
    | where SourceImage endswith "msbuild.exe"
    | project TimeGenerated, Computer, TargetImage, SourceImage, EventID, CallTrace
    );
    processes
    | summarize count() by TargetImage
    | where count_ < 5
    | join kind=inner processes on TargetImage

These queries are not anything fancy. Or to be more fair, these are quite boring low hanging fruit type of things. I was looking around for samples for malicious **msbuild project files** that could be used to verify what the actual badness looks like to no avail. I did find some samples from VirusTotal but unfortunately, I do not have an account which could be used to download the samples there for personal usage.

Maybe one more thing - the parent processes of the **msbuild.exe**. One option would be to look for the execution by processes that are often associated to attacks, like powershell, wscript or cmd, however there shouldn't be to many different parent processes. So, I'd take the statistical approach from the queries above - look for rarer parent processes. As there isn't likely too many parent processes the easiest? approach would probably just to sort by the count of the parent process. Still, I left the materialize and join in as I'd like to see all the details from the get-go and not have to run multiple queries.

    let processes = materialize (
    sysmon
    | where Image endswith "msbuild.exe"
    | project TimeGenerated, Computer, Image, CommandLine, ParentImage, ParentCommandLine
    );
    processes
    | summarize count() by ParentImage
    | join kind=inner processes on ParentImage
    | sort by count_ asc

And this seems to work fine. It does get all the details for all the results as there are no limitation by count so this might just be unusable if **mbsuild.exe** is being used a lot within your environment.

Conclusion
==========

I was hoping to get a little more to write about the msbuild.exe lolbin but unfortunately there actually aren't too many samples available which would be using it for malicious purposes. This made the investigation towards the subject quite a lot harder than I originally thought and the post didn't go as deep as I would have liked.

I am not particularly happy with the queries within this post. I think these are very simplistic and all of them follow the same pattern so there is a lot to improve. For me, it is much easier to create the queries if I can verify it against actual data (and I throw out a wild guess that this is the same for all the others too) so not being able to verify much made this quite a lot harder. Thus, I only hunted for the scenarios which I could verify to produce hits. I did not create theoretical queries as I believe that there is too high chance of having a mistake in the query and thus it would provide zero value.

Anyway, thanks for reading this far and see you next time.

[Github](https://github.com/JouniMi/Threathunt.blog/blob/main/msbuild)