---
layout: post
title:  "OpenCTI RSS feed support"
tags: [opencti, threat intelligence, threat hunting, featured]
author: jouni
image: assets/images/Screenshot-2023-09-16-at-12.27.12.png
comments: false
categories: [ threat intelligence ]
---

RSS feed support in OpenCTI
===========================

I haven't been playing with the OpenCTI platform a lot since I first deployed it. I have a look at the data from time to time but haven't had the time to create integrations. I just got back to this and started to look if the RSS feed ingestion has been added to the platform and it indeed seems to be the case. The RSS reader feature was added in 5.10.0 release which was released on 27.8.2023.

 I updated the docker-compose.yml file to include the latest versions and pulled the images. After that the RSS feed ingestion magically appeared!

![]({{ site.baseurl }}/assets/images/Screenshot-2023-09-16-at-12.27.12.png)

Then it is more or less about adding those RSS feeds and to see how that looks like. I'll start with Bleeping Computer. The integration is super easy and does not really require any sort of instructions on how to do it. You mostly just need the feed address, name and not much else. I decided to create new users for all the feeds though to keep it clear which feed comes where. Not sure if it is really required though.

When the feed has been created it needs to be started. I started the integration and it seems that nothing is happening and nothing is actually being ingested to the system which is a little weird. I created a second one for [The DFIR report](https://thedfirreport.com/). That didn't work either, but then I realized that the account responsible for the feeds probably needs more permissions. I added the account(s) to the Connectors group after which I updated the feeds an The DFIR Report was immediately working.

Same cannot be said of the Bleeping Computer feed though. I proceeded to recreate it and now we are talking - the import started. I added some of the RSS feeds I am using and it looked like this:

![]({{ site.baseurl }}/assets/images/Screenshot-2023-09-16-at-13.26.31.png)

I had added some of my favorite feeds. Here is a list of the feeds which I added in no particular order.

Name

URL

Trend Micro Research, News, Perspectives
http://feeds.trendmicro.com/Anti-MalwareBlog/

Trend Micro Research, News and Perspectives
http://feeds.trendmicro.com/TrendMicroSimplySecurity

The Register – Security
http://www.theregister.co.uk/security/headlines.atom

The Hacker News
http://thehackernews.com/feeds/posts/default

The DFIR Report
https://thedfirreport.com/feed/

SecurityWeek
http://feeds.feedburner.com/Securityweek

Security Affairs
http://securityaffairs.co/wordpress/feed

Securelist
https://securelist.com/feed/

SANS Blog
https://blogs.sans.org/computer-forensics/feed/

Palo Alto Networks Blog
http://researchcenter.paloaltonetworks.com/feed/

Packet Storm Security
http://packetstormsecurity.org/headlines.xml

Microsoft Security Response Center
http://blogs.technet.com/msrc/rss.xml

Microsoft Security Blog
http://blogs.technet.com/mmpc/rss.xml

Malwarebytes Labs
http://blog.malwarebytes.org/feed/

Lenny Zeltser
http://blog.zeltser.com/rss

Krebs on Security
http://krebsonsecurity.com/feed/

Hexacorn
http://www.hexacorn.com/blog/feed/

Hackread – Latest Cybersecurity News, Press Releases & Technology Today
http://feeds.feedburner.com/hackread

Darknet – Hacking Tools, Hacker News & Cyber Security
http://feeds.feedburner.com/darknethackers

Dark Reading
http://www.darkreading.com/rss/all.xml

Cisco Talos Blog
http://vrt-sourcefire.blogspot.com/feeds/posts/default

CISA Cybersecurity Advisories
https://www.us-cert.gov/ncas/alerts.xml

Bleeping computer
http://www.bleepingcomputer.com/feed/

Okay you have feeds.. what now?
-------------------------------

Not much I guess. It is just a simple RSS reader. It would be cool if it would go through the article and add IOCs and all that but it does not. However, this can be useful if you are collecting this information centrally for your team to use. Then the same platform can be used to do further digging, linking between of the items.

Someone could for example find an interesting article and then turn that into a Threat Hunt which could then be documented in the OpenCTI platform. If you have a CTI team they can go through the same material and use status so that the others know who have gone through what. It is just more information in the central platform to help the security operations. Also, you are not relying on a single individual following the right feeds - you can integrate what you would like all the people to follow.

I am sure that there are plenty of use cases for this sort of functionality which I can't think of. What I do know is that this was one of the features which I really missed when I was looking into the platform and I am glad to see that it has been implemented!

Here is an example of what the ingested report looks like in the platform:

![]({{ site.baseurl }}/assets/images/Screenshot-2023-09-16-at-13.50.17.png)

So it does add the labels which is great. It is a great feature to bring more data to the platform in an easy manner. By all means it is not the most sophisticated way of bringing in the data - if comparing to the AlienVault integration it is is much less elaborate, however it is easy to and nice addition.

I do have some further use cases for the platform which I will likely blog about on a later date. It will be more about integrating the data from the platform to other security tools to automate certain capabilities. A little shorter post this time - thanks for reading!