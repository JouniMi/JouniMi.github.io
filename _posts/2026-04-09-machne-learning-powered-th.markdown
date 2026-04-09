---
layout: post
title:  "Machine Learning for Threat Hunting"
tags: [ TH, ML, featured]
author: jouni
image: assets/images/mlth/mlthlogo.jpeg
comments: false
categories: [ Threat Hunting ]
---

# Machine Learning for Threat Hunting: What I Learned Building ML-Powered Detection Pipelines

As part of my master's thesis I explored an answer to the following questions: Can machine learning help threat hunters? Can it genuinely assist a threat hunter doing hypothesis-driven hunting on real endpoint telemetry?

The answer turned out to be yes, but with caveats. This post documents what I built, what worked, what didn't, and what I'd tell someone looking to do the same.

The full thesis report is available [here](https://www.theseus.fi/handle/10024/913789).

## WHY BOTHER WITH ML IN THREAT HUNTING?

Traditional threat hunting relies heavily on query-driven approaches. You write a KQL query, a SPL search, or a SQL statement to test a hypothesis. It works well for known patterns.

**But what about the unknown?**

What if you're hunting for:
- Slow, low-and-slow Active Directory enumeration that doesn't trigger thresholds?
- C2 beaconing with jitter that looks "normal" at first glance?
- Lateral movement patterns that span multiple hosts and days?
- Process chains that are technically valid but contextually suspicious?

Query languages may struggle here. They're great for show me X where Y equals Z but less effective at show me what doesn't fit the pattern. That's where unsupervised machine learning comes in. I wanted to explore how well machine learning can be used to spot the anomalies from the data.

## WHAT I BUILT

I developed five ML-powered threat hunting pipelines, each targeting a specific hypothesis:

1. **AD Enumeration Detection (K-Means + Deep Learning)**
- Hypothesis: Adversaries enumerating Active Directory will produce anomalous query patterns over prolonged period of time.
- Approach: TF-IDF feature extraction from LDAP query strings, followed by K-Means clustering and autoencoder-based anomaly detection.
- Result: The deep learning autoencoder achieved perfect F-Score (1.0) on simulated data, while the shallow K-Means approach struggled (0.18 F-Score). Deep learning won, hands down. Both of the models, however, were absolutely amazing in pinpointing the anomaly where the LDAP queries were ran over 5 days.

2. **C2 Beaconing Detection (Hybrid K-Means + Autoencoder)**
- Hypothesis: Command & Control traffic exhibits periodic timing patterns distinguishable from normal traffic.
- Approach: Timing analysis using K-Means clustering on inter-arrival times, combined with autoencoder scoring on network features.
- Result: Successfully identified beaconing patterns with clear timing signatures. The hybrid approach (clustering + deep learning) provided better context than either method alone.

3. **Process Anomaly Detection (Seq2Seq Autoencoder + Isolation Forest)**
- Hypothesis: Malicious process execution chains deviate from normal process sequences.
- Approach: Sequence-to-sequence autoencoder trained on normal process chains, with Isolation Forest for additional anomaly scoring.
- Result: Detected anomalous process sequences effectively. However, it is very noisy and may miss True Positives.

4. **Widespread Attack Detection (Autoencoder)**
- Hypothesis: Multi-host attacks create correlated anomalies across the environment.
- Approach: Four-phase pipeline: windowing, blast radius analysis, correlation, and deep learning anomaly detection.
- Result: Identified coordinated attack patterns spanning multiple hosts. The phased approach was critical—trying to detect this in one pass would have failed. This took lots of efforts to built but I was relatively happy with the results.


## THE NUMBERS

Here's the performance across all models (simulated environment with 20M events):

| Metric | Mean Value |
|--------|------------|
| Recall (Detection Rate) | 0.9565 |
| F-Score | 0.5862 |
| False Positive Rate | 0.4758 |

What this means:
- **Recall of 0.9565** = excellent detection capability. The models found the threats.
- **F-Score of 0.5862** = decent overall performance, but there's room for improvement.
- **FPR of 0.4758** = high, but expected for threat hunting. False positives are the cost of doing business.

The key insight: These aren't detection use cases. They're threat hunting assistance tools. The output isn't "this is malicious" but "this is anomalous and worth investigating."

## WHAT WORKED

1. **Multimodal Approaches Beat Single Models**
Every pipeline that combined multiple techniques outperformed single-model approaches. Different models catch different things.

2. **Deep Learning Outperformed Shallow Models**
The H1_Deep autoencoder (F-Score: 1.0) crushed the H1_Shallow K-Means (F-Score: 0.18) on the same hypothesis.

3. **Feature Engineering is Still King**
No amount of model tuning replaces good feature engineering. The pipelines with the most thought put into preprocessing and feature selection performed best. It is of utmost importance to ensure the pipeline is performant.

4. **Spark Scales**
Processing 20M events would have been more complicated without PySpark. The distributed architecture was essential. I tried using Pandas too but the data was too much for it.


## WHAT DIDN'T WORK

1. **Broad Hypotheses Fail**
Hypothesis 3 (the broadest one) was the only pipeline with False Negatives (FNR: 0.2174). Narrow your hunting hypothesis before building the pipeline.

2. **Overcomplicating Breaks Things**
The H4 pipeline initially had complex scoring logic that produced negative results. Simplifying it made it better.


## THE ARCHITECTURE

The architecture is explained in the [GitHub repo](https://github.com/JouniMi/MLPipelinesForTH).

**Why the chosen architecture works:**
- Parquet format = efficient column-based querying
- Object storage = scalable, S3-compatible
- Spark = distributed processing for large datasets
- Jupyter = iterative, documented, reproducible

## THE CHALLENGES

**Expertise Gap**
This is the biggest blocker. Threat hunters typically work with SIEM/XDR query languages. Machine learning requires Python, data preprocessing, model tuning, and statistical understanding. Many hunting teams lack this background.

**Integration Complexity**
Existing security operations have established workflows. Introducing ML pipelines requires:
- Infrastructure changes
- Workflow modifications
- Team training
- Management buy-in

Currently many of the SIEM vendors are moving more to Data Lake supported approaches. This is very good for ML fueled threat hunting purposes.

**Interpretability**
Deep learning models are black boxes. When an autoencoder flags something as anomalous, Threat hunters need to understand the why to act on findings. This lack of transparency requires senior analysts who can interpret model outputs.

**Data Access**
Most security data lives in SIEM/XDR platforms with API rate limits. Pulling enough data for ML analysis can be:
- Slow (API throttling)
- Expensive (query costs)
- Limited (retention policies)

## PRACTICAL GAINS

Despite the challenges, ML-assisted hunting delivers real benefits:

**Speed and Scalability**
Spark-based ingestion reduced query latency significantly. Analysts can explore large datasets quickly instead of waiting hours for complex queries.

**Complex Hypothesis Testing**
Some hunts are nearly impossible with queries alone. ML enables:
- Multi-dimensional anomaly detection
- Non-linear relationship discovery
- Pattern recognition across massive datasets

**Continuous Experimentation**
Documented notebooks make it trivial to:
- Swap feature sets
- Try new models
- Iterate based on results

This encourages an evidence-based hunting culture.

## ADVICE FOR THREAT HUNTERS

If you're exploring ML-assisted hunting, here's what I'd emphasize:

**Build a Solid Data Foundation**
Identify the exact columns and events you need. Create reproducible code to pull the data. Transform it into a DataFrame before feeding it to models.

Garbage in, garbage out applies doubly to ML.

**Learn Python Basics**
You don't need to be a data scientist, but understanding Python and data analytics is mandatory. Use public datasets to build your understanding. Again though, you don't have to be a data scientist. 

I had lots of experience with Pandas before starting but no experience from ML before my studies. When I started with Machine Learning it felt like I had a massive learning curve especially as I did not understand the mathematics behind the models. I adapted code first mentality and it worked well for me. I am far from an ML engineer/expert but I do feel like I learned a lot while studying and especially as I was experimenting.

That said, I read multiple books on machine learning, Spark/PySpark and data analytics as I was studying the topic. However, I struggled with the mathematics part even if the code was logical to me. I have always learned in practice so for me the key was to move on to testing the implemnentation after reading the books. I am sure it's still not prettiest or most effective approach but hey if it works..

**Leverage Existing Expertise**
If your organization has a data science team, involve them. Co-develop pipelines rather than going it alone. Also, use your AI tools. Understand the code but get the assistant do the heavy lifting.

**Iterate and Document**
Keep detailed records of:
- Hypotheses tested
- Parameter settings
- Outcomes

This makes it easy to reproduce successful detections and discard dead ends.

**Reflect on Results**
Analyze both successful and unsuccessful hunts. Continuous learning and adaptation are essential.

## THIS ISN'T A SILVER BULLET

Let me be clear: ML pipelines don't replace threat hunters. Neither do they replace the current query-oriented approaches.

They're assistance tools. The models surface anomalies, but humans must:
- Validate findings
- Understand context
- Determine malicious intent
- Take action

## THE OPEN-SOURCE RELEASE

To help the cybersecurity community, I'm releasing all five Jupyter notebooks to GitHub:

**Repository:** https://github.com/JouniMi/MLPipelinesForTH

**What's included:**
- README with data flow and configuration guidance
- Five annotated notebooks 
- Reproducibility ideas for alternative data sources

**What it's NOT:**
- A production-ready system
- A complete detection solution
- Plug-and-play (you'll need to adapt it)

It's a reference implementation. Clone it, modify it, extend it for your environment. Main purpose is to help getting started with ML based threat hunting. It is to raise interests and ideas, not to provide full working pipeline.

## KEY TAKEAWAYS

1. **ML can enhance threat hunting** when applied to the right hypotheses
2. **Deep learning outperforms shallow models** for complex pattern detection
3. **Multimodal approaches work best**
4. **Feature engineering matters at least as much as the model selection**
5. **Specific hypotheses beat broad ones**
6. **Expertise is the limiting factor**
7. **False positives are expected**
8. **Documentation and iteration are critical**

## FUTURE WORK

Several areas need exploration:

- **Detection use cases:** Can these models work for continuous monitoring, not just hunting?
- **Algorithm efficiency:** Which algorithms perform best for specific threat types?
- **Broader TTP coverage:** Only a few techniques were tested. Hundreds remain.
- **Generative AI:** Could GenAI tools detect anomalies in pre-processed datasets?

## FINAL THOUGHTS

Machine learning for threat hunting isn't about replacing the current query-based hypotheses. It's about giving hunters better tools to test hypotheses, explore data, and find what queries alone can't.

The technology works. The challenge is adoption—building the expertise, infrastructure, and workflows to make it practical. If you're curious, start small. Pick one hypothesis. Build one pipeline. Learn from it. Iterate.

**Code:** https://github.com/JouniMi/MLPipelinesForTH

**Questions?** Reach out on LinkedIn. I don't use much of any other social media.