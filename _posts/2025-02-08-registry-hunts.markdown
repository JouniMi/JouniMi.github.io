---
layout: post
title:  "Look into couple of potential registry based maliciousness"
tags: [threat hunting, kql, mde, featured]
author: jouni
image: assets/images/registry/reg_target.png
comments: false
categories: [ threat hunting ]
---

Look into couple of potential registry based maliciousness
=============================

t has been a long time since the last post I made. Since then you may see that I have upgrad... changed the look and feel of this blog. The reason for that is I got fed-up with Wordpress and hosting it and decided to see if it would be easy enough to migrate to Github Pages. It was as you may guess. Github pages seems to work great.

I haven't really had any ideas of what to blog about which is why it has been a bit.. quiet. I got an idea of looking into the registry and trying to find malicious powershell/whatever based keys being created. So that is how I am going start this blog post, look into suspicious ..stuff.. being created in more general level to registry. I may dabble into runkeys but likely will leave that for another time.

Encoded commands
=======
Encoded commands in registry entries can be a sign of potential malicious activity. This post will explore some KQL queries that can help detect such activity. The first query I did is really simple. I am just trying to find encoded commands, nothing else. 

    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType has_any ('RegistryValueSet','RegistryKeyCreated')
    | where isnotempty(RegistryValueData)
    | where RegistryValueData matches regex @'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$'
    | extend DecodedCommand = replace(@'\x00','', base64_decode_tostring(extract("[A-Za-z0-9+/]{50,}[=]{0,2}",0 , RegistryValueData)))
    | where isnotempty(DecodedCommand)
    | project Timestamp, DeviceName, DecodedCommand, RegistryValueData, RegistryKey, RegistryValueName, RegistryValueType, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName


The reason for looking broadly into encoded commands is that this value could be read with powershell and then executed as encoded command. This could have other purposes but I remember a few incidents where I have seen encoded powershell being saved to registry.

The problem with this query is that it is very broad. It is looking into all the registry additions and changes (well the ones which are recorded by MDE anyway) and thus it may not be runnable in this format in large environments.  The best way to limit would be to limit the time/devices we are looking at, for example only look into past day or few and potentially automate launching the query through the API.

Running a command to create a matching key:
![]({{ site.baseurl }}/assets/images//registry/create_item.png)

This was not unfortunately logged with MDE. Seems this path is not logged at all. So I created the same key to a location where it should be logged:

![]({{ site.baseurl }}/assets/images//registry/create_item2.png)

Seems like even with this command the second commandlet was not saved. And it was not, I tried several other ways, I created a HKCU runkey and mimiced running powershell.exe with encoded command and it did not save it. I did they same for HKLM runkey and still nothing. I am a bit baffled to say the least, I can see the values in registry but it seems MDE is for some reason, not saving this telemetry.

When I finally found way to get the data saved to registry the query worked. So this query is able to find base64 encoded strings but it is far from perfect. It also only matches if the full key value matches base64 encoded string, which is why I started creating version which matches if there are padded whitespace. Again of course this was a whole another adventure with my lacking regex skills and eded up being reaaaally complicated especially as the regex flavour used by KQL does not support lookbehinds or lookaheads, which makes it difficult to match if there is a whitespace before or after the padding. I ended up with the following query:

    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType has_any ('RegistryValueSet','RegistryKeyCreated')
    | where isnotempty(RegistryValueData)
    | where RegistryValueData matches regex @'\s+([A-Za-z0-9+/]{4,}(?:[A-Za-z0-9+/]{2}[=]{2}|[A-Za-z0-9+/]{3}=)?)\s+' or RegistryValueData matches regex @'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$'
    | extend ExtractedB64 = trim(" ",extract(@'(?:\s+)[A-Za-z0-9+\/=]+(?:\s+)',0,RegistryValueData))
    | extend DecodedCommand = replace(@'\x00','', base64_decode_tostring(RegistryValueData))
    | extend ExtractedDecodedCommand = base64_decode_tostring(ExtractedB64)
    | where isnotempty(DecodedCommand) or isnotempty(ExtractedDecodedCommand)
    | project Timestamp, DeviceName, DecodedCommand, ExtractedDecodedCommand, RegistryValueData, RegistryKey, RegistryValueName, RegistryValueType, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP

The query provided above is used to extract and decode command interpreter paths present in registry values. However, it can produce false-positive matches due to the complexity of the regular expression used. Talk about ugly queries.. I could not figure out to fix that issue unfortunately and here is a screenshot showing some of the matches:

![]({{ site.baseurl }}/assets/images//registry/matches.png)

Maybe the question is why to hunt this? The reason is that a threat actor can store these commands in registry and load them as part of a powershell command/script. I've seen this in multiple occasions and it may be useful to detect such activities.

Also I think that I may understand why some of the telemetry was not captured by MDE. I think that it depends on the value name, at least partly. The reason why I think that to be the case is:
- Creating a new value with name Publisher to key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VeryBad including the base64 encoded string was recorded by MDE
- Creating a new value with the name Version to the same key was NOT captured

I think MDE might be filtering what telemetry is saved based on the value name. I don't necessarily see this as a huge problem, goes to the same bucket I've discussed before; essentially Microsoft can't save all the data. They need to have more granular approach to be able to support the vast amount of data generated by the tool. I would assume the logic is that the Evilness would likely be alerted based on other telemetry, which I think is fair. MDE is quite capable in detecting Evilness even if not capturing 100% of telemetry. 

Hunt for command interpreter present in registry values
----------------------------------------------
The next one is a lot more simpler. I am looking for things like powershell.exe and cmd.exe being added to registry. Most likely these would be runkeys but there are more creative ways to utilize this. Here is an example of what I am looking for:

![]({{ site.baseurl }}/assets/images//registry/runkey.png)

This is a simple hunt that can be done with the following query:

    DeviceRegistryEvents
    // Filter out events initiated by OneDriveSetup.exe to reduce noise
    | where InitiatingProcessVersionInfoInternalFileName != @"OneDriveSetup.exe"
    // Look at events from the last 30 days
    | where Timestamp > ago(30d)
     // Consider only key set and key created actions
    | where ActionType has_any ('RegistryValueSet','RegistryKeyCreated')
    // Search for registry values containing 'powershell' or 'cmd'
    | where RegistryValueData has_any('powershell','cmd')
    // Project relevant fields for analysis
    | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, InitiatingProcessParentFileName

I removed the results where the InitiatingProcessVersionInfoInternalFileName is pointing to onedrive setup. This causes a lot of FP and I didn't want to whitelist the filename completely as some threat actors could use that filename too. 

This is really simple but could provide useful. It may be too noisy so more whitelisting may be required. Also, you can filter down to runkey locations given that those are most likely to contain these. Not a super elaborate query but should work.

Hunt for keywords being set to registry
----------------------------------------------
There are multiple ways how the bad guys could hide malicious code to registry. One way to look for this would be to do a keyword search on the items created. This is a bit lackluster with MDE given that it does not really save all the telemetry but as that is my weapon of choice in this blog lets get started. The query could be something as simple as this:

    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType has_any ('RegistryValueSet','RegistryKeyCreated')
    | where RegistryValueData has_any('xor','new-item','invoke-expression','iex','sleep','invoke-','System.Net.HttpWebRequest','webclient','iwr','curl')  // Look for common obfuscation techniques or commands used in malicious scripts
    | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, InitiatingProcessParentFileName  // Project relevant fields for analysis

This query will look for any registry value set or key created in the last 30 days that contains any of the keywords listed. The keywords are common in PowerShell scripts used for malicious purposes. The results will include the timestamp, device name, registry key, registry value name, registry value data, initiating process account name, initiating process file name, initiating process command line, initiating process remote session device name, initiating process remote session IP, and initiating process parent file name. This can help in identifying potential malicious activities, without having excessive information present.

Here is a hit from the query:
![]({{ site.baseurl }}/assets/images//registry/keywordhit.png)

To conclude this blog post I want to thank everyone for reading and I hope this information is helpful. A little insight to hunting with the registry can go a long way in identifying malicious activities

Queries in GUI
----------------------------------------------
I also noticed that the queries I've been submitting to the MS repo have been now added to the hunting GUI which is great to see! Here is a picture of one of the queries. Love the easy accessibility.

![]({{ site.baseurl }}/assets/images//registry/queryingui.png)
