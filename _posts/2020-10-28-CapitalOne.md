---
layout: single
title: CapitalOne Data Breach - SSRF due to WAF Misconfiguration to PII leakage of 100M customers.
date: 2020-10-27
classes: wide
header:
  teaser: /images/logo_capitalone.jpg
tags:

  -BugBounty
--- 

**CapitalOne Data Breach - SSRF due to WAF Misconfiguration to PII leakage of 100M customers.**

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

### Digging to the technical prespective

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
- [ ] Full SSRF - when the response initiated by the server is being sent back to the malicious actor, which gives the ability to access internal assets data.

This being said, utilizing SSRF attack on a componet which is being hosted on AWS could be proved to be far more critical vulnerability, this is due to the "Magic IP" - 169.254.169.254 which is being issued internally by AWS, and holds the instance metadata.

![aws_ssrf](/images/amazon_ssrf.jpeg)

When the attacker managed to utilize the SSRF into the WAF instance metadata, she grabbed the credentials to the cloud, utilized the over-premissive premissions of the WAF on the AWS to dump the PII information from their cloud data to the malicious actor VPS.

The WAF which had been used and had been compormised is the ModSecurity, is an open-source web application firewall (WAF). 
Originally designed as a module for the Apache HTTP Server.

erratic was arrested on July 29th with allegedly 30GB of credit application data from Capitalone AWS instances.

The attack was first discovered on July 17th by CapitalOne from a responsible disclosure letter which had been sent to the company, indicating that there is leaked s3 data of the company inside a Github repository which belonged to the user "Netcrave" and had been found associated with a resume and the name of Paige A. Thompson.

![repsonsible_disclosure](/images/responsible.png)

On the github repo it wasn't clearly stated from which cloud instance the information had been dumped, although learning from Paige C.V <https://gitlab.com/netcrave/Resume/blob/master/cv/experience.tex>, it had been found out that she had worked on Amazon Inc.

later on, by using her handle "erratic" on twitter, it had been found out that she had posted publicly about accessing and dumping huge amount of data from companies by accessing their s3 buckets.

![tweets](/images/tweets.png)

While CapitalOne examined the files on the github repo, they found within the "April 21 file" that it contained the IP address for the specific WAF server.

It had been found out that the connection from erratic to the CapitalOne infstrucature had been done by VPN connection from the 46.246 subnet (IPredator) and from TOR connections, limiting or creating an alert for suspicious and continuos activity from VPN and TOR identified IP addresses could have alerted CapitalOne that there might be something fishy going on.

![evidence](/images/evidence.png)

The PoC of reaching the EC2 credentials looked like:
GET /?caponeurl=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: redacted.captialone.com

The premissions:
```javascript
- Effect: Allow
 Action:
 - s3:GetObject
 - s3:ListBucket
 Resource: <*/Capitalone s3 bucket resources>
 ```
 
 Executing the following on the 700 buckets:
 ```javascript
 s3_capital_one_breach = boto3.client(
 ‘s3’,
 aws_access_key_id=access_key,
 aws_secret_access_key=secret_key,
 aws_session_token=session_token )
resource = boto3.resource(‘s3’)
s3_capital_one_breach.get_object( Bucket=’capitalone-bucket’, Key=’/tmp/’,
‘[axed].snappy.parquet’ )
 ```
# Thanks for Reading!

## References
1. The Web Application Hackers Handbook 2 - <https://www.oreilly.com/library/view/the-web-application/9781118026472/>


