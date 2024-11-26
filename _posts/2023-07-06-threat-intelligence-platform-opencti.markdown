---
layout: post
title:  "Threat Intelligence Platform - OpenCTI"
tags: [opencti, threat intelligence, threat hunting, featured]
author: jouni
image: assets/images/CTI.png
comments: false
categories: [ threat intelligence ]
---

What?
=====

I've been thinking of implementing some sort of Threat Intelligence Platform for my personal usage. The original idea has been to run [MISP](https://www.misp-project.org/) as it is quite well known to be very good at this sort of thing, however I've been hearing a lot of good things about [OpenCTI](https://github.com/OpenCTI-Platform/opencti) lately. It is by far less mature and less used than MISP, so it is likely to be less polished at this stage. It offers, however, good amounts of eye candy and seems to be a cool platform. Another option would be [YETI](https://yeti-platform.github.io/), butI didn't really even have a look at it.

![]({{ site.baseurl }}/assets/images/CTI.png)

Why?
====

This is a much better question. I like to keep up with the current threat activity and I have been doing that mostly by following RSS feeds. I have been toying with the idea of having CTI platform to see if I can use it for the same purpose with more information readily available. Additionally, I like to learn. I have not been super into TI but have had a raising interest towards the subject. I'd like to understand better how the platform(s) function and what I can do with them. Ultimately though, I think that the Threat Intelligence Platform is just that - a platform to ingest your threat intelligence. I most likely will not have access to any of the cool data sources, relying on open source which might mean that the feeds are just so late that they provide no use to me. Or maybe they are only providing IoCs and no real intel which can be great for security operations, but of limited use for an individual.

It might be actually faster to just keep on reading those news throughout RSS feeds. One option would be to integrate the RSS feeds to the CTI platform which can be done (at least with MISP) but if it is all about the RSS feeds why bother. I can keep up to them with the current solution. In the end it is still quite possible that this will prove to be pointless exercise but we shall see.

Installation
============

I will be installing the OpenCTI to my good ol' unraid box as a docker. Docker because of simplicity and my ever increasing love towards the product. There are instructions available on the OpenCTI documentation on how to handle the [installation](https://docs.opencti.io/5.8.X/deployment/installation/#using-docker). There wasn't much issues with the installation with the docker approach. And in couple of minutes we have it. A clean CTI platform. 

![]({{ site.baseurl }}/assets/images/Screenshot-2023-07-04-at-22.35.11.png)
There we have it. A clean OpenCTI.

Now the real work begins. So what to actually integrate to the product? What can I even integrate and does it make any sense?

Integrations
============

To get started I clicked through the GUI and noticed the lack of creating integrations there. I did find a link to this [page](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76). So there we have a list of different CTI sources I guess and we can filter down to the community editions. They have been categorized to different categories:

*   OpenCTI Live Streams
*   TAXII Collections
*   Connectors - Data Import
*   Connectors - Enrichment
*   Stream Consumers
*   Files Import
*   Files export
*   Third-party native integrations

Some of these were more clear than the others. The OpenCTI Live Streams and TAXII collections had only three additions in total so it seemed to be quite lackluster. Under the Data Import and Enrichment there are a good few though, even on the community edition front.

![]({{ site.baseurl }}/assets/images/community_connectors.png)
List of the community connectors.

Some of these are more interesting than others.  Apparently most of these have a ready made docker images which I need to run and this was the point where I decided to create a dedicated VM for the OpenCTI. The Unraid container management isn't really that amazing so this decision made it easier for me to have all the relevant containers categorized to a single VM. I know, it is not very optimal solution.

I sort of love the approach. I like tinkering with docker and this approach might actually make it easier for me to build my own integrations too as there are plenty of examples. Anyway, many of the feeds still do require a paid access so even if the connectors are community editions the actual feeds are not. For example, the Valhalla feed can be acquired only through a paid subscription - so actually it seems that the community support feeds are more or less created by community but they do not mean that the content would be free. Later to be examined if the "partner and filigran support" connectors actually are free or not. The IOC feeds are not really my top interest as I don't really have anything to do with those, unless there would be metadata included. Most of the feeds seem to be all about IOCs so not sure if this actually will work out or not for my purposes. Nevertheless I decided to start integrating a little bit randomly. The more the better am-I-right? (No, not really).

AlienVault
----------

The configuration of the connector is super easy. All the things you need are basically the OpenCTI API key, OpenCTI address (remember to add the IP + port) and then add your own API key from AlienVault. All the changes are made to the docker-compose.yml file and the container can be then started with docker-compose. It is pulling the image from the Docker Hub so even though the source code and docker image are included in GitHub they are not really used here. This is good news as then I can most likely consolidate all the connectors as a single docker-compose file, which I like. They could be added to the docker-compose file launching the actual OpenCTI as well, but I am keeping that clean from the actual connectors.

![]({{ site.baseurl }}/assets/images/Alienvault.png)
The AlienVault connector is importing pulses. This can take a while.

Now that the AlienVault connector has been built I am eagerly waiting for the ingestion to finish and to see what kind of data there will be present on the OpenCTI platform. I am especially interested to see how the data is being structured on the platform. It seems that the connector is crashing though. I didn't fancy much debugging so I just stopped it and changed to initial date to the start of 2023. Maybe it could be related to API timeouts. 

This didn't fix it. I looked at the errors and got very generic "Errorno 3 - try again" type of error. No luck on Github either. However, it was stated that all the connectors need access to Rabbitmq hosted as part of the OpenCTI platform. So I exposed the ports of the Rabbitmq container and this didn't do anything. Annoyingly, the Malware Bazaar connector worked fine so this was a bit of a mystery. 

Just for sake of debugging I added the configuration as part of the base OpenCTI docker-compose.yml configuration as additional container. This seemed to do the trick. It started working after this. Maybe access to the RabbitMQ wasn't working nicely after all. The likely reason is that my limited docker skills were limiting the RabbitMQ to not to be available to the other containers. Could also be my lazyness to reboot the secondary containers after making the original changes. Nevertheless, I decided to go with this as it worked now.

![]({{ site.baseurl }}/assets/images/alienvault_dash-1024x796.png)
The dashboard after adding some data.

The dashboard is a lot cooler now. The data ingestion seems to take some time though, likely cause it is being parsed and then ingested to elasticsearch.  The analysis reports, IoCs, Threats, Vulnerabilities etc are starting to flow in from the AlienVault feeds.

![]({{ site.baseurl }}/assets/images/avthreat-1024x697.png)
Example Analysis Report ingested from AlienVault.

I think this is cool with all the relations. Actually I think it is really cool and love the GUI and the possibilities so far. The views to the data and the correlation between of it is quite nice.

Further integrations
--------------------

I noted that making the platform usable for me it likely requires quite a lot of additional custom connectors. Before going to that route I continued to explore some of the ready made connectors. While enabling stuff I stumbled across something called Obstracts Connector. This seemed very cool, you could intake RSS feeds with the Obstracts service and then use the connector to ingest them to OpenCTI through an API. Unfortunately the API enabled access costs a bit much so this wasn't really an option. I did enable the following though in addition to AlienVault:

*   OpenCTI Datasets - These are more or less datasets feeded to the platform. Includes basic information like industry sectors.
*   OpenCTI Mitre - Same with this one, imports basic information from Mitre ATT&CK.
*   CISA known exploited vulnerabilities - This is cool and the name tells it all.
*   NVD Common Vulnerabilities and Exposures  - Love those vulns.
*   Malpedia - IOCs etc. Unfortunately I don't have an account so only TLP:WHITE stuff.
*   Maltiverse - IOCs etc. free tier, not sure if this will be at all useful.
*   Abuse.ch Threat Fox - IOCs.
*   Abuse.ch UrlHaus - URL IOCs.

Maybe later:

*   TweetFeed - this is interesting and new to me. Gathers IoCs from tweets.
*   TAXII2 - generic Taxii2 collector.
*   Urlscan

I am assuming that for my general interest the AlienVault, NVD CVE and the CISA known exploited vulnerabilities would bring most value. The IOC bases feeds are a little meh unless you can technically integrate your CTI platform to technical solutions. However, there is some potential in delivering malware statistics from the feeds which I find interesting. You know, I did build ELK based solution for those purposes before and it is still running. Maybe I can retire that thing if the OpenCTI works well.

The lack of the threat intelligence reports is a bit annoying. AlienVault is offering them but that is pretty much it from the sources integrated. Rest are either supportive or offering more technical IOCs. [Pulsedive](https://pulsedive.com/) is offering very interesting free CTI. I've been using it before for some of my projects. Unfortunately there is no ready made connector created for Pulsedive. There are couple of options how this can be one but unfortunately most if not all of them require the paid PRO license. The price for the pro license when not used for commercial purposes is quite cheap, 29€ a month. I don't know though what would be included in the data. Still the connectors needs to be built as there is no ready made option.

At this stage it seems that the further integrations needs a lot of tinkering. I am very interested in turning RSS feeds to reports in OpenCTI and make cool reports about them automatically. However as this requires a lot of time to do I will explore that option at a later date. There is a development guide available for creating the connectors, [here](https://docs.opencti.io/5.8.X/development/connectors/).

![]({{ site.baseurl }}/assets/images/connectors.png)
Current connectors.

Oh and the last thing before moving on - this thing is quite memory hungry. I gave the VM 8 gigs of memory and it ate it all up and is having some hiccups within the gui likely because all the memory is consumed. I'll up that to 12GB and will see if that is enough.

Enrichment integrations
=======================

Then to the enrichment. These can be used to, well, enrich the data. There are quite a few options offered out of the box. This is cool for any production CTI platform, however for my purposes the enrichment is less relevant most of the time. More out of interest of testing this stuff out I decided to give it a go with couple of integrations.

I started with the following:

*   Hatching Triage
*   Crowdsec
*   Shodan InternetDB

I opted for the Shodan InternetDB instead of the normal Shodan just so that I don't accidentally use my limited Shodan quota which I might need for other purposes.

\[caption id="attachment\_434" align="aligncenter" width="821"\]![]({{ site.baseurl }}/assets/images/enrich_ip-1024x718.png) Shodan InternetDB Enrichment on-going.\[/caption\]

This is quite cool in my opinion. The CrowdSec integration seems to not work though, error given about the usage of v1 API. The Hatching Triage Sandbox is working and is enriching the artifacts nicely when they are sent to the sandbox. 

When the Hatching Triage enrichment is used the analysis results are added as comments to the artifacts. The relations are also added to other relevant techniques. This I appreciate a lot and find to be really cool. It seems to work nicely too.

![]({{ site.baseurl }}/assets/images/htriage_analysis-1024x692.png)
Example of the Hatching Triage enriching an artifact.

Exploring more enriching integrations I decided to go with VirusTotal and Sophos. The Sophos Intelix offers a good quota even for a free tier account. The only annoying thing about that is the need for an AWS account.

Even though the SophosLabs Intelix has a very high requests on free tier, I still didn't enable the automatic enrichment as I don't want to end up with any surprises. I did also add a "Zero-Spend" budget to AWS so if there would be money spent on AWS it hopefully alerts me.I wish this could be limited in a way which allows you to not go above certain threshold and would just suspend all the things that cost money at that point. 

Anyway, this enabled me to add the Sophos support and I also added the two VirusTotal connectors too even if the API is limited on free tier. Unfortunately it seems that the VirusTotal integration is currently completely broken. There is a [PR](https://github.com/OpenCTI-Platform/connectors/pull/1276) for a simple fix but the docker-compose file was set to use a certain image version. I changed it to the latest. Didn't fix it as the 5.8.7 was already latest, changed it to rolling. It works!

The Sophos connector isn't working either but it might be in a beta or something. No luck with this one though, there wasn't an easy fix and I didn't feel like debugging much currently.

Using the platform
==================

There are plenty of use cases for such a platform from integrating to SIEMs and other security tools for automated ingestion of IOCs, blocking, allowing, analyzing threats, analyzing IOCs and many others. I am no pro on the platforms themselves and I build it to get more information of the current threats that the organizations could be facing. For this use case I face the issue of having too little data when I am trusting the free sources. There is plenty of technical IOC data which can be acquired from the free sources but the actual meaningful reports there are less of. Though I have to add that the IOCs might not be the best either. I am sure that many security vendors whom gather their own IOCs are better and the platform(s) need ingestion by the SOC to be useful.

I would really like to have data added from blog posts, news articles and similar sources correlated to the mentioned threat actors, malware, techniques and all that fun stuff. AlienVault data is great for the purposes but it is just a single source. The other free sources do not really seem to help in this, unfortunately.

So to the actual usage. The first thing is that I want to look at are any recent reports. These are listed under the Analysis -> Reports section of the tool.

![]({{ site.baseurl }}/assets/images/reports-1024x310.png)
The reports view.

I drilled down to a single randomly chosen report to see how that looks like. There was one picture of this view before but hey, have another!

![]({{ site.baseurl }}/assets/images/report_example-1024x493.png)
General view of a report.

This is quite generic view of the report so you can decide if you are interested of knowing more. There are usually additional links to external sources about articles from which you can find more information. Also, there is additional information in the others tabs, looking at the Knowledge tab next:

![]({{ site.baseurl }}/assets/images/example_knowledge-1024x813.png)
The Knowledge tab from a report.

This is a cool looking graph which you can interact with. It shows the relation of the observables and entities. I have seen similar graphs many times before but the actual usage for this has been quite limited in my experience. This is one of the best usages for this sort of visualizations that I have seen though, you can easily see the relations between of for example one IOC and techniques.

Looking into other tabs you have entities and observables. There also is a Content tab which have been so far always empty  and Data which also have been empty.

![]({{ site.baseurl }}/assets/images/obs_ent-1024x682.png)
The entities and observables shown on the image.

These are cool. You get more information of what kind of techniques have been observed to be used in this particular attack and the actual indicators matched to it. When you are looking for high level information this might not be that interesting but it could be then hunted for easily within your chosen technical solution. Of course when jumping to TTP based threat hunting you need to analyze the articles a little more.

One good addition is the enrichment. If you want to have more information from a file you could enrich it with other integrations. Let's take one of the hashes as an example.

![]({{ site.baseurl }}/assets/images/vtenriched.png) VirusTotal enriched sample on the right side.
The full JSON output from VT API is available as a comment too if needed. Also link to VT is added as external reference.

This is nice data. It could also be enriched automatically in production if need be which would then add good amount of labels. These are great when looking for  information. Unfortunately, I don't have a license which would allow me to download the sample from the VT api. This would turn this as artifacts which could be analyzed in a sandbox. This could reveal cool TTPs of the malware used and then could be used in more general way to conduct threat hunting. In enterprise environment this would likely be possible.

In this particular example the original report proves some information which could be turned to hunting queries:

*   The malware is using double extensions - .xls.exe and .pdf.exe.
*   The malware is stated to run discovery commands and establishing a C2 connection.
*   Custom web request header: Cookie: 3rd\_eye=\[client\_hash value\]

 Investigating a particular threat
----------------------------------

Another use case which interests me is to investigate a particular threat. Let's take Qbot as an example. Running a query for qakbot results in 13 results from which the first one is the QakBot malware page. This page should at least in theory contain all the other information to which the previous search resulted in. The page contains information of the QakBot malware although the main page is mostly just general information and statistics.

![]({{ site.baseurl }}/assets/images/qbotgeneral-1024x835.png)
Qakbot general page.

The Knowledge page contains quite some information of the qakbot. It contains an overview of the data, information about the victims if available, vulnerabilities observed to be linked to qakbot, mitre att&ck graph of the techniques used by it, observables and a lot of other information. Not all of this is present for all the threats and especially as the data sources in my implementation are limited there is only so much data.

There is a ton of observables available though. In total there are 3.83k observables found related to Qakbot. I don't know how these are mapped but my guess would be that by the label used. Could be something more fancy but I am a bit too lazy to find that information out, sorry.

![]({{ site.baseurl }}/assets/images/qakbotinfo.png)
Combination of some of the views under the Knowledge tab.

The Analysis tab contains the reports about Qakbot. These include different kind of articles/reports where the qakbot has been discussed in one way or another. This can be a goldmine of information when creating detection capabilities or threat hunting queries against something. Of course you still need to analyze the articles but if you have great data sources maybe you can at least have a single place from where to investigate.

The Indicators tab contains, well, indicators. My understanding is that these are more the IOCs as observables are sort of "unverified IOCs". So the Indicators are less FP prone. Could be wrong though. This is it for this example.

Conclusion
==========

The OpenCTI platform seems to be very cool CTI platform. It has a great and beautiful GUI which works very well (after you give it enough memory to run). The links between of different objects is great and ingesting at least some of the data is made quite easy. I like the idea of connectors, just wish that there were a fair bit more of those available.

For my usage this would be a great platform if I could ingest more of the reports. That is the biggest issue which I have with it currently for my own personal purposes. I would love to have more information ingested to the product.

When it comes to actual usage of the tool I think it can be very nice addition to an organization. Maybe you are looking for a platform to store Cyber Threat Intelligence and don't want to pay the huge price for a commercial solution. Maybe you could use the money to ingest some of the commercial feeds to the platform instead of paying for the actual platform itself. For that purpose I think this is very very nice - easy to use - easy to understand and easy to look information from. You can easily add your own data through the GUI. If you would have an incident you could store information relating to that particular incident in the tool. You can add a lot of information which is then searchable later on.

I think this can be a good solution for at least a smaller organization. Although if looking for open source CTI platform I think MISP is still the first option unless it would be somehow proven to be worse. It is a lot more complicated though but also offers a lot more options out of the box. For a lazy person like me, I think the OpenCTI could be the better option (unless I really can't get RSS feeds into the thing).

What about the criticism then? Well it is quite poorly documented. The documentation could be improved on many levels, actually on almost all the levels. The deployment guide works relatively well but even there are little things which could be improved. The integrations and the functions of different connectors are not documented mostly at all. If they are documented the documentation is all over the place. There should be clear labeling of what you can achieve with each of the things. Some documentation is still completely missing, only referring that it will be there sometime in the future.

Then there is only limited amount of said connectors. Many useful things are missing from the connectors but of course you can develop your own. It doesn't seem to be that simple task though. I think having the RSS feeds ingested should be quite easy to do and for this kind of tool it would add huge value, especially for the smaller teams which might not have the budget for those cool commercial feeds. 

I will most likely continue blogging about the platform later on as I am hoping to add more stuff to it and gather more experience using it. Thanks for reading!