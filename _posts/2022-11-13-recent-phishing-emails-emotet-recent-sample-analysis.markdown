---
layout: post
title:  "Recent phishing emails + Emotet recent sample analysis"
tags: [emotet, phishing, sysmon, splunk, threat hunting]
author: jouni
image: assets/images/phishing_Example.png
comments: false
categories: [ threat hunting ]
---

Phishing emails
===============

It's been a little quiet on the blog for a while now. I've been busy with other things and haven't had the time to find any feasible topics to write about. Now it sort of landed to my lap. I've been receiving phishing messages for a ~week now to my personal mailbox. The messages are coming from 'Google Notifications' or gmail addresses and they contain a link to a domain "script.google.com", mostly. Seems like this really isn't anything new while googling for it, as there is a [an article](https://www.kaspersky.com/blog/google-script-phishing/40795/) from Kaspersky detailing this.

Nevertheless this is new to me and especially active currently. So here is one of the messages that I've received.

![]({{ site.baseurl }}/assets/images/phishing_Example.png)

The headers verified that this is from Gmail, but I don't add the header here as it is a little bit boring. Some of the similar emails came from actual gmail addresses too, this one was the notify thing. I have no idea how that notification is generated and didn't bother to google more about it. I am, however, very much interested in what happens if I access these links. Some of the mails actually included an attachment too so that of course is interesting too.

This time, I am going to use Detection Labs instead of MDE. Detection Lab is ready made collection of easily deployable virtual machines that are automatically installed with monitoring tools like Sysmon which are then gathered to Splunk. This is made to deploy a testing environment easily which can be, for example, used to rule development within SOC. The Detection Lab is available [here](https://www.detectionlab.network).

I'll browsed to the first URL and was welcomed with a CAPTCHA. Then, the browser was redirected to another site, https://bonusbtc\[.\]online/offbitbonus\_1120/?u=4403&s=44#5d8ymdgg8e9aogu4i4dy6646769fvrls. This was already picked up by Chrome as deceptive.  I browsed to the site still and was welcomed with the following view:

![]({{ site.baseurl }}/assets/images/link1_view1.png)

Clicking next couple of times and the site is finally requesting for me to log in to an account.

![]({{ site.baseurl }}/assets/images/link1_view2.png)

Of course, I have no idea which account this would be. The next screen likely though reveals the mystery as there is the "Login with Google" button, and also the "credentials" are already present on the logon screen.

![]({{ site.baseurl }}/assets/images/link1_view3.png)

When logging in it actually does "work". So you actually get somewhere, my assumption was that the site would announce that the password is not working and would force to login with google and then steal your credentials but seems not to be the case. Well, while I am "logged" to the site I was browsing around to see what happens next. This led me finally to a "chat" as I tried to withdraw the funds. In reality, there were just some premade answers from which I had to choose, probably always leading to same output.

![]({{ site.baseurl }}/assets/images/link1_view4.png)![]({{ site.baseurl }}/assets/images/link1_view5.png)

                   

Next, this returned to the chat and I had to "convert the currency" through and pay 0.00381228 BTC to finalize the transaction. This was using a service called MoonPay.com. I am not very knowledgeable of Bitcoin world so I have no idea how legit this service is, but the actual payment itself looks quite legitimate. Unfortunately, It seems that this is very boring, basically scamming money from the recipients. I was hoping for something more elaborate but meh. I also checked the PDF attachment that I've received and all of them point out to the same thing so this was just super boring. Analyzing the device with the sysmon data doesn't show much anything happening.

I did check couple of other messages that I've received and one was pointing to google forms: https://forms\[.\]gle/2Fb1augjpPFJDGMa6#wse6qe0vda21ar8il8. This asked details like email address, name etc. After filling with garbage, the form pointed to a link:

![]({{ site.baseurl }}/assets/images/link2_view1.png)

The link then pointed to the same malicious domain, bonusbtc\[.\]online. Nothing special really, just another way to try to fool the people.

Emotet - the second coming
==========================

Emotet has been fairly active recently and I decided to grab a sample of it in and run it in the lab. Looking at the recent reports in tria.ge, there is no shortage of emotet samples. I decided to [grab one](https://tria.ge/221113-ea1jpadd7w) amongst the all. Why this? Well, it was an excel file and not only the dll, makes it much more easy to analyze. The excel had the macros enabled as per usual with Emotet. The articles stating the second coming of it have stated that it is using the old tricks so this was to be expected. Also, as to be expected, it creates a DLL file, or actually several DLL files which it then loads with regsvr32.exe.

![]({{ site.baseurl }}/assets/images/emotet_1.png)

![]({{ site.baseurl }}/assets/images/emotet_2.png)

The DLL files are created at least partly by the regsvr32.exe process, which could be potentially used within threat hunting, maybe joined to some other event too. I would assume that regsvr32.exe doesn't actually create files in c:\\windows\\system32\\ that often legitimately. The sample also connects to 53 distinct IP-addresses, mostly on port 8080. It is possible that not all of this traffic is to malicious servers though, most of it seem to be.

![]({{ site.baseurl }}/assets/images/emotet_3.png)

The persistence is handled by runkeys. This sample creates a new key which then launches the malicious DLL using regsvr32.exe. This is also great for threat hunting purposes although it goes very much back to the basics.

![]({{ site.baseurl }}/assets/images/emotet_4.png)

The sample also drops different exe files. All of the files are randomly named and are created in the users temp folder: c:\\users\\username\\AppData\\Local\\Temp\\. The filenames dropped by this sample were utdfnjnpqkecvxvn.exe, oialmuujnim.exe, fwbm.exe and zbtkqcoguhdnmjk.exe. These were all removed after created.  The sample also launched **systeminfo** and **ipconfig /all** commands to learn more about the device.

So that's that. Now it seems to be idling and calling home from time to time, but I don't like to keep the environment exposed too long even if it has been completely isolated from everything else that I have. Then to the threat hunting queries. The simple ones first, I'll add couple of them to the same code block. Not the best with SPL so these queries are a little basic.

*   The first one looks for regsvr32.exe process creating files to the C:\\windows\\system32\\ -folder.
*   The second one looks for exe file creation to the c:\\users\\ folder
*   Connection towards public IP-addresses from regsvr32.exe
*   The last one joins dll creation by the regsvr32.exe to a network connection event towards public IP-addresses with a inner join. Could also maybe include the exe creation, but the idea of this is simple and potentially maybe works fine. Could also be made more strict by joining to dll creations to c:\\windows\\system32\\  but in my opinion that makes it a little limited.

    ---- Query 1 ----
    index=sysmon Image="C:\\Windows\\System32\\regsvr32.exe" EventCode=11 TargetFilename="C:\\Windows\\System32\\*"
    
    ---- Query 2 ----
    index=sysmon Image="C:\\Windows\\System32\\regsvr32.exe" EventCode=11 TargetFilename="*.exe" TargetFilename=C:\\Users\\*
    
    ---- Query 3 ----
    index=sysmon Image="C:\\Windows\\System32\\regsvr32.exe" EventCode=3 NOT (DestinationIp="10.0.0.0/8" OR DestinationIp="172.16.0.0/12" OR DestinationIp="192.168.0.0/16") | table _time, host, EventCode, Image, ProcessId, DestinationPort, DestinationIp
    
    ---- Query 4 ----
    index=sysmon Image="C:\\Windows\\System32\\regsvr32.exe" EventCode=11 TargetFilename="*.dll" | table _time User ComputerName Image ProcessId ProcessGuid TargetFileName | join type=inner ComputerName ProcessId ProcessGuid [search index=sysmon Image="C:\\Windows\\System32\\regsvr32.exe" EventCode=3 NOT (DestinationIp="10.0.0.0/8" OR DestinationIp="172.16.0.0/12" OR DestinationIp="192.168.0.0/16") | table _time, ComputerName, Image, ProcessId, ProcessGuid, DestinationPort, DestinationIp]
    
And that's it for now. The queries can also be found from Github: https://github.com/JouniMi/Threathunt.blog/blob/main/emotet\_queries. Cheers to reading to this stage. I am hoping to be a little more active with the blog in the future - but no promises!