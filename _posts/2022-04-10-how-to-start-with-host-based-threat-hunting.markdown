---
layout: post
title:  "How to start with host based threat hunting?"
tags: [crowdstrike, defender for endpoint, kql, mde, spl, threat hunting]
author: jouni
image: assets/images/mitre_attack-1024x293.png
comments: false
---

# How to start with host based threat hunting?

When I was first introduced to the threat hunting years back it was somewhat hard for me to grasp all the theory which was available in the internet. I did not have at the time any colleagues who would have had extensive experience from the threat hunting so I was struggling a bit to figure out what should be the concrete hunting steps. Back then, there wasn't as many github repositories available having such a large number of pre-made queries.

I was trying to think how to actually start hunting. First, I started to investigate the capabilities of the tools at hand. At the time, I was working with different kind of EDR tools that did save the important data that could be used to conduct hunts. Almost all the EDR tools did offer at least a basic query feature which allowed to hunt for signs of an attacker. When getting better at hunting I noticed that some of the tools didn't offer that great query language which started to limit the hunting possibilities.

However, many of the EDR tools especially now offers a great query language to be used in hunts. In my experience, both Crowdstrike and Microsoft's Defender for Endpoint offer GREAT query language - I have been using KQL from Microsoft a lot lately. Crowdstrike is saving the data to Splunk and offers SPL query language. Both are awesome for host based threat hunting. Sysmon is also a GREAT option, if saving the data centrally to an efficient solution like Log Analytics or Splunk - for example.

## Getting started with Defender for Endpoint

Getting started with the actual query languages can be a daunting task. However, there is a lot of examples in the internet that can be used to get started with the language. Start with easy queries: learn how to query for different kind of cmdlines for example. This is easy and can help you to find the potential adversaries. The following example shows a VERY simple query to look for encoded Power Shell being launched. Keep in mind that this simple query can also return false-positives. Even MDE runs some encoded commands from time to time.

    DeviceProcessEvents 
    // Set the query lookup time. I like to do this in the queries rather than in the GUI
    | where Timestamp > ago(14d) 
    // Filter to powershell processes. Use ~ for case-insensitive approach.
    | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
    // Filter to processes where the launched processes commandline contains letters "enc". This is to 
    | where ProcessCommandLine contains @"-enc"

Get familiar with the simpler queries first. The KQL language offers a ton of different ways to query the data and supports great statistical filtering of the data. Continuing with the first example. Get the same data but count how many times an encoded command has been launched on each device.

    DeviceProcessEvents 
    | where Timestamp > ago(14d) 
    | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
    | where ProcessCommandLine contains @"-enc"
    | summarize count() by DeviceName

# After the basics

Many blog posts are discussing different methodology that can be used within threat hunting and those are GREAT resources for generating the threat hunting process and methodology. However, more concrete data helped me to get started before moving on to more hypotheses driven approach.

I love the Mitre [ATT&CK matrix](https://attack.mitre.org/). It offers details on many relevant techniques that are being used in the real world by many attackers. It also offers examples of how different APT groups might have been using different techniques in the past. To me, Mitre ATT&CK has been a basis of many hunting queries targeting the techniques used by the actual attackers.

![]({{ site.baseurl }}/assets/images/mitre_attack-1024x293.png)
_Image from Mitre ATT&CK website,_ https://attack.mitre.org/.

    DeviceProcessEvents 
    | where Timestamp > ago(14d) 
    | where ProcessCommandLine contains "/add"

MDE does also save the account creation event to the DeviceEvents -table (which includes a ton of interesting events proving additional value - like named pipes). This can be queried with the following query:

    DeviceEvents 
    | where Timestamp > ago(14d) 
    | where ActionType == 'UserAccountCreated'

This example has been extremely simple, only stating how you can get started with creating usable queries targeting a Mitre technique. When understanding the KQL better it makes it much easier to create more elaborate queries and to target "the harder to catch" -techniques. In the end, the focus should be on the techniques that are hard to catch with SIEM / MDE detection rules - if the created query is not very noisy then it should likely be turned into detection rule instead.

Although I am often creating hunting queries for more comprehensive hypothesis, I am still using Mitre ATT&CK on almost a daily basis to investigate which techniques are relevant and should be hunted for. I am almost always mapping the queries that I ran against Mitre ATT&CK.

In the future, the blog will likely contain a lot more complex and interesting queries. It's likely that I will at some stage open up my method of creating queries and testing them out little more. I might be also writing about the methodology that I use in the hunting - or not. That subject is quite well covered already. Also, my background in incident response so I ight post some tidbits of information from that front as well.