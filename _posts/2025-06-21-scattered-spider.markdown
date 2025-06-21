---
layout: post
title:  "WScattered Spider: When Social Engineering Meets Supply Chain Risk"
tags: [threat intelligence, scattered spider, incident preparation, featured]
author: jouni
image: assets/images/scatteredspider/scattered_logo.png
comments: false
categories: [ incident preparation ]
---

# Scattered Spider: When Social Engineering Meets Supply Chain Risk
=============================

I have been following recent acvitiy by Scattered Spider which led me to write about this topic. Lately, the group has been very active in attacking several different retailers in UK. The most notable one has been Mark & Spencers. The attack against M&S according to the news originally started somewhere around February-March where the threat actor was able to exfiltrate the Active Directory database, also known as ntds.dit. This resulted in a further attack as the threat actor was able to crack the usernames and passwords stored in the ntds.dit database.

According to the public information the initial access method for this attack was a supply chain, not social engineering as initially suggested. Allegedly, the attack may have been started by compromising an employee of TCS, a service provider for Mark & Spencers. This initial foothold allowed attackers to deploy DragonForce ransomware, encrypting critical systems leading to disruptions in the business. This has had massive financial impact to M&S, where the market value is down 700 million pounds and they were losing 4 million pounds worth of online sales daily before able to recover back to normal. There is some information available in public of the attack, however it is relatively limited in technical details.

The Scattered Spider group is known from their sophisticated social engineering attacks and they are known to target the help desks of companies. They are very good at impersonating employees and gaining access to systems through the help desk. There have been several articles stating how they are able to gain a lot of information from their targets before conducting the call to the help desk, like gaining personal information about the targets family and things like employee IDs which are sometimes required to reset passwords. The group is also known from targeting disgruntled employees and using their credentials to gain access to the target company. 

The Scattered Spider group has also been attacking the Supply Chain, as within the Mark & Spencers attacks. This emphasizes the importance of ensuring safe supply chain and also monitoring what is happening outside of your own network. The supply chain can be a very intereting target for the threat actors as by gaining access to a supplier, they can gain access to potentially tens or hundreds of organizations. I’ve seen several successful attacks originate through supply chain compromises in the past, and unfortunately, I am seeing these incidents becoming increasingly frequent.

# Defending against the attacks
=============================

So what can a company do to defend agains these attacks? I think it is not a simple answer, given that they are using the human element to gain access. This makes 
technical controls alone not enough, though they help a lot. I have had some ideas which could help to prepare for this type of attacks, either by trying to ensure that the attacks would not be successful or trying to limit the scope.

## Help Desk
The threat actor could start the attack by searching for information about an employee they may want to target. They could for example analyze the social media of the target person to gain information of the subject. They could potentially find out what kind of role the person has within the company, information about the family and interests. With this information they could start crafing more personal story giving details which are true and make the help desk more likely to trust them. They could also acquire information through other means like LinkedIn, company websites and even other breaches, which could lead the threat actor to have a bunch of information from the person.

They can call the help desk with all this information and they may have all the relevant information needed to get the password reset. They could also for example first compromise the account of a manager of their actual target (like sysadmin) and then use this compromised account to confirm account reset requests for the actual target. The attempts are very     and they are also able to create a sense of urgency to make the help desk employee to act quickly.

While MFA is a critical security layer, it's not a silver bullet. In my experience, attackers may target the help desk to reset MFA, often claiming a lost or stolen device. This highlights the importance of robust identity verification procedures beyond just MFA. One of the strongest technical controls is to disallow all access from devices which are not managed by the company and ensuring tight controls for the managed devices before giving access. This way even if an account is compromised the threat actor should have no access to the account as they do not have such a device. However, this may not be an option for many companies as it is quite normal that data is being used from wide range of different devices.

One of the critical factors when defending against this kind of attack is to ensure the help desk procedures and verifications. Have a look at your companys procedures, verify how the help desk is verifying the identity of the caller.
- Are they asking enough questions?
- Are they checking enough information?
- Are they following the procedures?
- What would they do in case of a very sophisticated and convinvcing caller? 
- Are they making exceptions to the process?
- Does the process have weaknesses?
- Do they report suspicious activity?
- How does the process work for admin accounts?

The next step would be to test out if the help desk is vulnerable to social engineering. This could be performed as an excercise where the caller is given enough details to convince the help desk to reset the password. Verify if this kind of information is something that can be acquired (remember, it could be also publicly available from previous breach). Then, have a convincing person call the help desk with a plan in mind to test out how they function. Based on the learnings the procedure can be improved, training can be offered for the help desk personnel to spot social engineering attacks and potential issues corrected.

## Supply chain
I think this is fairly more complicated matter to solve. Many companies are doing a lot of work to ensure that their supply chain remains secure. I know that many companies are monitoring the dark web and similar sources for any signs of their suppliers being compromised. This is important given that how common the attacks are getting.

The other good thing to understand is what kind of access the suppliers have. A register of suppliers should be created containing the details from the different suppliers where the access is quite clearly documented. This register should be reviewed from time to time to ensure it is up-to-date.Here are some of the items I feel like would be important to include in the register from security perspective. With the following details I feel like it would be much easier to control the risk levels for the suppliers.

### Supplier information

- **Supplier Name**
- **Security contact person:** Security contact for the supplier
- **Services provided:** What services does the supplier provide
- **Relationship:** Direct, supplier of supplier, etc
- **Business criticality:** How important are they for the business 

### Access details

- **Systems accessed:** A detailed list of systems the supplier has access to.
- **Access type:** Read, read/write, admin
- **Access method:** VPN, Direct, company provided laptops, API, etc..
- **Justification:** Reason why the supplier needs access
- **Date granted**
- **Expiration date**
- **MFA requirements:** Is MFA required, how it is implemented?
- **Cutting access:** How can we cut the supplier access at the time of an emergency?

### Security Posture
This goes a bit further and at least some of these may be hard to get access to. However, I feel this could prove valuable from risk management perspective to have this information for key supplier.

- **Security Certifications:** (ISO 27001, SOC 2, etc.) 
- **Data Handling Practices:** How do they handle your data? (Encryption, data residency, etc.). Reference to a Data Processing Agreement (DPA) is good here. This is a must for all the suppliers.
- **Incident Response Plan:** Do they have a documented incident response plan? Have you reviewed it?
- **Dark Web Monitoring:** Are they actively monitoring for compromised credentials related to your organization? Have you added them to your own dark web monitoring?

### Review

- **Date of Last Access Review:** When was the access reviewed to ensure it's still necessary and appropriate?
- **Reviewer Name/Role:** Who performed the review?
- **Review Findings:** Any issues identified during the review?
- **Remediation Actions:** What actions were taken to address any issues?

# Conclusion
=============================

The attacks perpetrated by Scattered Spider, and groups like them, represent a significant and evolving threat landscape. They demonstrate a clear preference for exploiting the human element, skillfully blending social engineering with technical prowess to bypass traditional security measures. While technical controls like MFA and device restrictions are important layers of defense, they are not perfect. 

Ultimately, a robust defense requires a holistic approach that prioritizes people, processes, *and* technology. Strengthening help desk procedures through rigorous verification protocols, continuous training, and regular testing is paramount. Equally critical is a proactive understanding and management of supply chain risks, underpinned by a detailed access register and ongoing monitoring. 

By embracing a layered security posture, fostering a culture of security awareness, and proactively addressing these threats, organizations can significantly reduce their risk of becoming the next victim of Scattered Spider or similar actor. Given the success by the group and the availability of AI Tools capable of working through language barriers I think these kinds of attacks are very likely to be more common in the future. The financial impact for M&S was huge - this is a very good example of how much a 
successful attack can cost.

That's it, hope you enjoyed reading.