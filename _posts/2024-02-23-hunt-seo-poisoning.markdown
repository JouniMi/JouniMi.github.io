---
layout: post
title:  "Hunting for signs of SEO poisoning"
tags: [threat hunting, defender for endpoint, kql, SEO poisoning]
author: jouni
image: assets/images/logo-1-1024x796.png
comments: false
categories: [ threat hunting ]
---

How to hunt for SEO poisoning?
==============================

![]({{ site.baseurl }}/assets/images/logo-1-1024x796.png)

Well this is a good question to which I don't have a good answer. This query is going to go through the very basics of how this can be started but it is not really that easy to do. I've had several different ideas of how to hunt for signs of SEO poisoning and the one in this post is the one that I think is most usable in the hunting scenarios. I have played around with a query which joins the file creation events to network events based on time - it does work but it is so opportunistic and causes a lot of noise from the network connections that I didn't want to share that with you.

So what is the idea of this query? It basically will look at all the certain files created by Browser processes, namely .exe, .msi and .zip. Then the files are  counted by SHA1 hash, FileOriginReferrerUrl and FileOriginUrl. The results are only shown if this combination is seen less than 4 times. The line 16 of the query is removing FileNames which contain "ChromeSetup" as this is causing noise as for some reason the SHA1 hash of legitimate Chrome installer is changing for each download. Some other applications are behaving similarly, which may be added to the query - a good to note is that for example TeamViewer seems to work in a similar fashion. Rare hash does not mean it would be malicious!

There is an option to limit the FileNames to apps (line 18) which are often being mimicked by the SEO poisoning attacks but this is such a huge number of applications that I wouldn't do it unless the noise is unbearable otherwise. Finally the FileProfile function is used to pull more information with the SHA1 hash. Good to note that the maximum number of results for this function is 1000.

    let LookupTime = 30d;
    let BrowserApps = pack_array(
    "opera.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe"
    );
    DeviceFileEvents 
    | where isnotempty(FileOriginUrl)
    | where Timestamp > ago(LookupTime)
    | where InitiatingProcessFileName in~ (BrowserApps)
    | where FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".zip"
    // Remove noise by removing FileNames containing ChromeSetup.
    // Some apps (like Chrome installer) seems to have a "polymorphic" installers where the SHA1 hash is always different when the app is installed. Some Adobe products seem to behave similarly.
    | where FileName !contains "ChromeSetup"
    // The following filter can be used to look for files with certain names. However, this can be hard as there is such a large number of files being mimicked in SEO poisoning attacks.
    //| where FileName contains "teamview" or FileName contains "windirstat"
    | project DeviceName, Timestamp, ActionType, FileName, SHA1, FileOriginReferrerUrl, FileOriginUrl
    | summarize count() by FileName, SHA1, FileOriginReferrerUrl, FileOriginUrl
    | where count_ < 4
    | invoke FileProfile(SHA1, 1000) 
    | project-reorder  FileName, SHA1, FileOriginReferrerUrl, FileOriginUrl, count_, GlobalPrevalence, GlobalFirstSeen, GlobalLastSeen
    

Analysis
========

The analysis should be based on the URL values combined to the file which has been downloaded. The hashes can be useful, especially if they are determined to be malicious. However, as explained before the hashes can't be really determine to be abnormal based on the rarity. For some reason vendors have been changing to a model where the installer is unique for each of the downloads meaning that it always changes. This makes the analysis of this technique much harder.

One way to remove noise from the query if its proven to be too noisy is to remove the SHA1 from the summarize altogether. A good note here is though, that the FileProfile function can't be used anymore after removing the hash. However, a join back to the data could be used to get all the hashes back after counting but this is up for the reader to do. This query is far from perfect and the referrer values are not always present so the success may vary. However, this can still be used to look for signs of SEO poisoning attacks and can also find true-positives. Cheerio!

[Microsoft GitHub PR](https://github.com/Azure/Azure-Sentinel/pull/10034)

[My Github page](https://github.com/JouniMi/Threathunt.blog/blob/main/seo-poisoning)