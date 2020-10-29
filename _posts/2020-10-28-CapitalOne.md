---
layout: single
title: CaptailOne Data Breach - SSRF due to WAF Misconfiguration to PII leakage of 100M customers.
date: 2020-10-27
classes: wide
header:
  teaser: /images/logo_capitalone.jpg
tags:

  -BugBounty
--- 

**CaptailOne Data Breach - SSRF due to WAF Misconfiguration to PII leakage of 100M customers.**

![preview](/images/logo_capitalone.jpg)

## Analysing the data breach 

### CapitalOne official Statement

<https://www.capitalone.com/facts2019/>

As per the official website of CapitalOne, 
On July 19, 2019 the company determined that an outside individual gained unauthorized access and obtained certain types of personal information about Capital One credit card customers and individuals who had applied for their credit card products.

In the company statement they declare that an immediate action had been taken to fix the issue and on the same time began working with federal law enforcement. The outside individual who took the data was captured by the FBI. The government has stated they believe the data has been recovered and that there is no evidence the data was used for fraud or shared by this individual.

The impact that has been stated on the offical statement is detailed on the image below, and is evolving a large PII information breach from their cloud service (AWS)

![captone_impact](/images/captoneimpact.PNG)

As we can infer from the official statement, the impact has been significant and critical to the company, yet no technical explaination or PoC of the attack has been provided from offical source of CapitalOne.

### Digging to the technical prespective - KrebsOnSecurity

<https://krebsonsecurity.com/tag/capital-one-breach/>

![digging](/images/digging.jpg)

As we can infer from the first lines, it was deemed at first a "Mystery" the form of which the attack had occurred, some speculating zero-days being involed and a thought of it being an inside job.

Later on, we are being introdocued to the details and the attack chain.

The attack has been executed by a former Amazon employee named Paige “erratic” Thompson, who had leveraged a misconfiguration of the WAF which had been in use by CapitalOne and was hosted on their AWS cloud instance, by utilizing SSRF attack and stealing the EC2 credentials of the WAF cloud instance at AWS, which turned out to have over-premissive rights, and led to the ability to read and list the entire buckets in possession of CapitalOne in the cloud.

**SSRF**

![ssrf](/images/ssrf.PNG)

SSRF stands for Server Side Request Forgery, and is a  web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing (Portswigger <https://portswigger.net/web-security/ssrf>)

In more simple words, SSRF vulnerability on a web server gives a malicious actor the ability to reach internal systems of the web asset by issuing the request from the behalf of the Web application.

There are two main types of SSRF,
- [ ] Blind SSRF (the response is not being shown to the malicious actor) which could lead to attacks such as internal port scanning
- [ ] Ful SSRF - when the response initiated by the server is being sent back to the malicious actor, which gives the ability to access internal assets data.

This being said, utilizing SSRF attack on a componet which is being hosted on AWS could be proved to be far more critical vulnerability, this is due to the "Magic IP" - 169.254.169.254 which is being issued internally by AWS, and holds the instance metadata 

## Miscellaneous Checks

![Checks](/images/Checks.png)

### Check for DOM-Based Attacks

### Check for Local Privacy Vulnerabilities

### Check for Weak SSL Ciphers

### Check Same-Origin Policy Confi guration

## Follow Up Any Information Leakage

# Thanks for Reading!

## References
1. The Web Application Hackers Handbook 2 - <https://www.oreilly.com/library/view/the-web-application/9781118026472/>


