---
layout: post
title:  "Why Your Threat Hunting Program Is Working (Even When It Finds Nothing)"
tags: [threat hunting, featured]
author: jouni
image: assets/images/thnovelty/logo.png
comments: false
categories: [ threat hunting ]
---

# Why Your Threat Hunting Program Is Working (Even When It Finds Nothing)

Those who’ve worked with me know: I love threat hunting (honestly, I love data analytics!). I’ve done it for years, conducted hundreds of hunts. Built programs from scratch for MSPs and clients alike. When I first started hunting, I loved the term. Threat hunting sounds like something out of a cyber movie: thrunters finding the key threat and saving the day. In reality? 

Most hunts end like this:   
    "No suspicious activity found."

And for the organization, that's good. It means your defenses are working. But often, people treat no findings as a failure, not sign of maturity. Threat hunters can be seen as failure as they did not find the bad guys. Heck, I used to *feel* like a failure as I was not able to find the evilness. But that mentality is not helping anyone, so every aspiring hunters should not feel like that.

Since I started, I’ve worked with hunters of all levels, hunters just starting and hunters who have hunted for years. I’ve seen tools used well, tools used badly, and tools gathering dust because the process wasn’t designed for these tools and hunters not able to adapt.

I’ve used SIEMs, XDRs and even data science tools. I've used the directly from the user interface, I've used them through the API:s. I've built lots and lots of tools around the topic, though most of them have not been released to the public. I've enjoyed creating automations and flows using the tools and enable advanced hunting operations.

And I’ve learned one hard truth: The tool is rarely the bottleneck (yes there are exceptions). The design or the lack of experience of using them are.

# Just finding the "bad stuff"

Threat hunters often chase active exploitation, the attacker in the network. It feels urgent, even heroic. But in continuous hunting, this is uncommon: malicious findings are rare, and that’s actually a good sign.

The real goal isn’t to catch bad guys today, it is to know you would see them if they were here.

## Hunting the coolest and most evil APT groups?

I’ve seen teams build detections for exotic cool zero-days, only to discover the targeted app has been patched already. I've commonly observed hunters targeting these cool APT groups because they are "likely to target the organization" while it may be far from the truth.

Most breaches come from financially motivated actors using the same old tricks: credential theft, lateral movement, exfiltration via familiar tools. Hunt for your risk, not the coolest news. That doesn’t mean ignoring innovation. Look beyond endpoints:

* Public-facing apps (misconfigured APIs, leaked creds, rogue portals)
* Identity hygiene (unused service accounts, excessive rights)
* Cloud config drift (S3 buckets going public)

Expanding the scope to vulnerabilities or hygiene closes gaps before the breach happens. Thinking outside of the box can lead to new innovation.

# Not adapting to tools available, safety of the current tools

Hunters often default to their favorite tool. Defender XDR, Splunk, etc, and stick with it, even when better options exist right inside their stack.

Example: I’ve seen teams hunt extensively in Defender XDR, only to realize at the end that all that telemetry is also in Sentinel with longer retention, richer context, and integration with Azure AD, Microsoft 365, and cloud logs. The extra juicy data was there all along.

Don’t underestimate Python. It’s not replacing your tools, it’s augmenting them:  

* Orchestrating APIs across tools  
* Processing logs with Pandas/Spark  
* Generating visuals with Matplotlib  
* Even experimenting with AI to score hypotheses or surface anomalies

But it’s not just about the technical tools. Reporting is often an afterthought. Long PDF reports? Rarely needed. What works better:  

* A concise finding
* A reusable hypothesis template
* A live dashboard or notebook

That’s the valuable deliverable: actionable, shareable knowledge, not a story so long no one is reading it.

Tools change. Data sources evolve. The best hunters don’t just use tech but enrich it which is especially true for MSP based hunters.

# Threat hunting and AI

AI is transforming threat hunting as it is other procedures. Not by reducing the hunters but rather adding efficiency to the operations.

**Use case 1: Query assistance**
LLMs are surprisingly good at turning natural language into working queries, though quality varies by tool. Some security tool query languages (like KQL or SPL) have strong examples in training data; others need more guidance. Either way, it can be faster to draft, review, and refine than to start from scratch. That said, I am yet to find an LLM which would be as good as experienced human hunters when it comes to complex queries. I have drafted elaborate schemas for LLM:s to write better queries, which have sometimes worked quite well.

**Use case 2: Hypothesis generation**
I built a system that ingests cyber security news via RSS, enriches it with LLM, and uses an LLM to generate actionable hunting hypotheses. It’s not perfect but it is rather reliable enough to surface promising leads I might miss. 

**Use case 3: Automation & augmentation**
Python and other tools can enable AI assisted hunting 

* Orchestrate APIs across tools
* Process and analyze logs with Pandas or Spark  
* Enrich, create queries and analyze with GenAI models  
* Use ML and DL models to flag unusual patterns, for hypotheses hard to catch with query languages only

Use the AI it to write the boring parts (docs, queries, code), not the strategic ones (scope, validation, response). AI is brilliant at execution, but needs someone to point it in the right direction. Not everything can be solved with AI though.

P.S. My MBA thesis explored ML-assisted threat hunting and the results were promising enough to remind me why I love working with data in the first place. More on that later.

# The real values of threat hunting aren't just the malicious findings

While all hunters wish to hit big game, it's quite rare, fortunately. Hunters should remember that there are other good performance indicators for threat hunting:

* **Coverage**: Coverage growth
* **Maturity**: How quickly we're able to turn threat intelligence into hypotheses?
* **Feedback**: Do findings improve detection logic, data quality, and training?
* **Findings**: While we may not have found a malicious actor, did we find hygiene or configuration issues?
* **Hunting-driven false negative reduction**: Did the hunts find gaps in detection?
* **Feedback loop**: Did the hunts lead to improvements?

What are NOT very good KPIs?

* **Number of malicious findings**
* **Number of hunts created**
* **Average hunt time** (though this is often mandatory on consulting work)

Efficiency is good. Kill long reports. Replace them with:  

* Live dashboards (showing coverage, active hypotheses, closed loops, findings)  
* Shared query libraries (reusable, versioned, searchable)  
* Short status meetings

The goal isn’t a hunting program. It’s a capability that updates itself, scales with the team, and keeps improving even when you’re not looking.

# SecOps <3 data

Security Ops runs on data but the data usage efficiency varies. The traditional tools like SIEM do not always allow for efficient data analytics, which could provide more statistics but also better detection capability. Fortunately the world is changing, the data lakes are more approachable which enable cool detection use cases. Good example of this is the Sentinel Data Lake which makes using data lake rather easy. Simplicity comes with a cost though, as it can be more expensive than other data lakes.

The data lakes are enabling fast processing of data. The data is often stored in formats like parquet files which are optimized for data analytics. The data can be queried with tools like Spark which enables advanced analytic capabilities. While it may not replace active monitoring rules directly it provides future use cases (and enables cost saving or at least shifting the cost as not all the data needs to be in SIEM active layer). Also increasingly available GenAI enable not only threat hunting but better Security Engineering, especially as companies can run their own models so that they don't have to worry about privacy concerns.

In the (near) future threat hunting could look something like this: An automated agent spots a telemetry gap → instantly generates:  
1. A refined hypothesis  
2. Ready-to-run detection logic
3. Telemetry validation test  
4. Detection pipeline deployment  
5. Clear verification instructions for the hunters

All tracked, versioned, and measurable like any production feature. This is changing the threat hunting to be more part of the security engineering, deeply integrated in the SOC. One off hunts can still be useful but they’re becoming the exception.

1. Detection logic that evolves with threat intel  
2. Feedback loops that auto-update coverage  
3. Hunters shifting from hunters to data scientists, designers and validators

The threat hunting will be more deeply integrated to security engineering disciplines where hunting is just part of how they build, test, and improve. Being able to utilize the data and the AI tools is a must to keep up with the threats.