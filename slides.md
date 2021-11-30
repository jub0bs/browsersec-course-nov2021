# Security in browser

---

## Introduction

---

### Who I am

* Julien Cretel (a.k.a. [jub0bs][twitter-jub0bs])
* security researcher and consultant
* bug bounty hunter
* developer (Go, mostly)
* occasional blogger at [jub0bs.com][myblog]

---

### Prerequisites

Some familiarity with

* HTTP fundamentals
* HTML/JS/CSS
* browser devtools
* cryptography

---

### What to expect from this course

* an overview of browser security mechanisms
* cover of the fundamentals rather than specific libraries/frameworks
* case studies of third-party systems
* emphasis on interaction and dialogue
* few slides!
* collaborative security review of your Web applications
* frequent breaks

---

### Web security matters

A security breach can result in all of the following:

* theft of sensitive user data
* theft of intellectual property
* downtime
* ransomware
* reputation damage
* fines from data-protection regulators

---

### You _are_ a target

Don't believe your organisation is uninteresting to attackers.

You may be [lost in the crowd][waldo], but you remain a potential target.

People [automatically scan the Internet for vulnerabilities][shodan] and exploit them, regardless of the target.

It's not personal; it's opportunistic.

---

### Security isn't just about the server

* Web security is a vast topic!
* Securing the server is very important, but only one aspect of Web security.
* Most users interact with your server first and foremost through their browser (API security is out of scope for this course).
* The server can instruct browsers to tighten or relax security aspects in a controlled manner.

---

### Always in motion is the Web

The Web security landscape is becoming more complex:

* browser behaviour evolves over time
* implementation differ from one browser to another
* specifications evolve over time
* new attacks are discovered all the time

And [where there's complexity, people take shortcuts and things go wrong][albinowax-about-complexity].

---

### Popular browsers

* Chromium (Chrome, Edge, Opera)
* Firefox
* Safari
* Internet Explorer (end of life June 2022)

Market share: https://gs.statcounter.com/browser-market-share

---

### Libraries/frameworks help, but only to an extent

* insecure defaults
* possible misuse of dangerous escape hatches (e.g. React's `dangerouslySetInnerHTML`)
* tools are not business-aware (e.g. access control in Ruby on Rails)

---

### Some good practices

#### Defence in depth

The [practice][defence-in-depth] of having **multiple**, possibly redundant lines of defence.

A good metaphor for defence in depth: [a fortified castle][helms-deep]: you have to [dig ditches in front of your walls][dig-ditches] to slow attackers down!
 
Defence in depth contributes to keeping a system secure in the face of 

* developer mistakes
* browser security bugs/regressions ([example][chromium-referer-spoofing])

---

#### Least privilege

> [...] in a particular abstraction layer of a computing environment, every module
> (such as a process, a user, or a program, depending on the subject) must be able to
> access only the information and resources that are necessary for its legitimate purpose.

([Wikipedia][least-privilege])

Can you think of (bad) counterexamples?

---

#### Adversarial thinking

When developing a component, put yourselves in the attacker's shoes.

Ask yourselves:

* Who could want to abuse this component?
* How would they do it?
* What trust relationships does that component have with other parts of the system?
* Are the dependencies used secure?

---

#### Trust relationship between server and client

Servers should be reasonably distrustful of the requests sent by clients, because requests can be tampered with by an attacker.

Conversely, clients should be reasonably distrustful of the responses sent by servers, because responses can be tampered with by an attacker.

How? Via an _intercepting proxy_, such as [Burp Suite][burp] (demo).

---

## HTTPS

---

### Crash course on HTTP (in Burp)

---

### HTTP is not encrypted by default

This is what should happen:

```txt
browser                                       server
   |                   request                  |
   | -----------------------------------------> |
   |                                            |
   |                                            |
   |                                            |
   |                   response                 |
   | <----------------------------------------- |
   |                                            |
```

However, because HTTP traffic isn't encrypted, there can be a man in the middle!

The attacker may simply observe traffic...

```txt
browser          passive attacker             server

   |        request       |        request      |
   | ------------------>  | ------------------> |
   |                      |                     |
   |                      |                     |
   |                      |                     |
   |        response      |        response     |
   | <------------------  | <------------------ |
   |                      |                     |
```

... or may also be tamper with it:

```txt
browser            active attacker            server

   |   normal request     |  modified request   |
   | ------------------>  | ------------------> |
   |                      |                     |
   |                      |                     |
   |                      |                     |
   |   modified response  |  normal response    |
   | <------------------  | <------------------ |
   |                      |                     |
```

---

### HTTPS to the rescue

HTTPS (HyperText Transfer Protocol Secure) consists in HTTP encrypted over SSL/TLS over a TCP connection (HTTP/1.1).

HTTPS guarantees

* confidentiality (your traffic cannot be observed)
* integrity (your traffic cannot be tampered with)
* non-repudiation (you can be sure you're talking to the right server)

<details>
 <summary>

  Does your site need HTTPS?
 </summary>
 
 [Yes][doesmysiteneedhttps], [even if it's just a static site][troyhunt-https-youtube].
</details>

---

### TLS certificates

To serve your site over HTTPS, you must obtain a certificate and its associated private key for your domain(s) from a _certificate authority_ (CA).

A certificate is essentially a _public key_ signed by the CA; it's this cryptographic signature that guarantees non-repudiation.

See https://en.wikipedia.org/wiki/Public_key_infrastructure

Browsers embark a list of trusted CAs and, by default, won't trust a certificate issued by anyone else.

You can obtain a certificate by solving a challenge meant to prove that you control

* the DNS zone of your domain (DNS-01), or
* the Web content served by your domain (HTTP-01).

Certificates have an expiry date and must be renewed.

---

### Certificate transparency logs

For audit purposes, [all certificates issued by official CAs are logged in transparency logs][transparency-logs].

Examine the certificate of your domain and look for it in the [transparency logs][transparency-logs-search].

---

### TLS in a nutshell

The successor to SSL, which was found to be vulnerable.

TLS 1.3 is the current version. PCI recommends at least TLS 1.2.

The TLS handshake occurs at the start of a new HTTPS connection. It consists in

* negotiating algorithms/ciphers
* exchanging symmetric keys to be used for the remainder of the connection.

Audit the TLS setup of your website on [Qualys SSL Labs][ssllabs].

---

### HTTPS quiz: true or false?

<details>
 <summary>

  Using HTTPS on sensitive pages (login, payment, etc.) is sufficient.
 </summary>
 
 False. Why?
</details>

<details>
 <summary>

  HTTPS guarantees that the website on the other end is trustworthy.
 </summary>
 
 False. Despite this kind of statement
 
 > The address of this payment website prefixed with https indicates that you are on a secure page and can safely proceed to your payment.
 
 HTTPS only guarantees that the connection is secure. It's not a good indicator of the website's trustworthiness.
</details>

<details>
 <summary>
  
  When I visit `https://sub.microsoft.com` in my browser, I can be assured that I'm talking to server controlled by Microsoft.
 </summary>
 
	Not exactly: [subdomain takeover][subdomain-takeover] makes things [more complicated][subdomain-xir]!
</details>

---

## HTTP Strict Transport Security (HSTS)

---

### Forcing browsers to use `https` on your website

Most modern browsers still default to `http` if you enter a domain without a protocol in the address bar
(with [the notable exception of Chrome][chrome-defaults-to-https]).
However, users can still visit `http://yourdomain.com`.

How could you force browsers to access your `yourdomain.com` (and to its subdomains) over HTTPS?

<details>
  <summary>
  
  Tell your users to install the [HTTPS Everywhere][https-everywhere] browser extension?
  </summary>
 
  You cannot compel all of them to install that extension.
</details>

<details>
  <summary>
   
   How about redirecting from `http` to `https`?
 </summary>
 
  Such a redirect
 
  * is not guaranteed to be cached for any extended time,
  * only covers a specific page and not a full domain,
  * is lost if the user purges her browser cache.
 
  Moreover, such a redirect [wouldn't stop a network attacker][hsts-network-attack].
  The server doesn't even have to be up for such a MitM attack to be viable!
</details>

<details>
  <summary>
   
   How about disabling `http` altogether on the server?
 </summary>
 
  The [ACME protocol][acme-wiki]'s [HTTP-01 challenge][http-01] may require `http` for you to obtain your TLS certificate.
</details>

---

### HSTS to the rescue

> HTTP Strict Transport Security (also named HSTS) is an opt-in security enhancement
> that is specified by a web application through the use of a special response header.
> Once a supported browser receives this header that browser will prevent any communications
> from being sent over HTTP to the specified domain and will instead send all communications over HTTPS.
> It also prevents HTTPS click through prompts on browsers.

([OWASP's HTTP Strict Transport Security Cheat Sheet][owasp-hsts])

Added benefits of dropping that initial `http`-to-`https` roundtrip:

* lower latency for users
* lower load on the server

---

### Preliminary questions before implementing HSTS

1. Must some people access your domain or its subdomains via HTTP rather than HTTPS?
2. Do you expect all present and future subdomains to be served over HTTPS?
3. Do you have certificate renewal in place for those domains?

If the response to either of those questions is "no", don't implement HSTS right away.

<details>
  <summary>Why?</summary>
 
  1. Those people will no longer be able to access your domain over `http` in their browser.
  2. People won't be able to access those subdomains otherwise.
  3. People will be locked out when if you run out of valid certificates.
</details>

---

### Setting a HSTS policy for your domain

1. Redirect `http://yourdomain.com` (TLD) to `https://yourdomain.com` with a `301` status code.
2. Add the following header to the response to `https://yourdomain.com`.
   ```lang-http
   Strict-Transport-Security: max-age=300; includeSubDomains
   ```
3. Check that nothing broke for your users.
4. Repeat step 2 and 3 by gradually increasing `max-age`, e.g.:
  * `3600` (an hour)
  * `86400` (a day)
  * `604800` (a week)
  * `2592000` (a month)
  * `63072000` (two years)

<details>
 <summary>
   
  Why is [this iterative approach][hstspreload-iterative] prudent?
 </summary>
 
 If your assumptions are incorrect, you will lock users out for as long as `max-age`.
</details>

---

### Closing the attack window

After a browser sees your domain's HSTS policy, it will remember to access your domain and subdomains over HTTPS.

<details>
  <summary>
  
   But is the attack window completely closed? What if the very first request is made over HTTP?
  </summary>
 
  That request is still vulnerable to a man-in-the-middle attack!
 
  How can we prevent that?
</details> 
 
---

### HSTS preload to the rescue

You can [ask to be added to the HSTS-preload list][hstspreload], which gets embedded in the browser at build time.

After that, browsers will _know_ to only ever access your domain and all its subdomains over HTTPS.

HSTS preload is not part of [RFC 6797][rfc-6797], but supported by all major browsers.

The list itself is available on [Chromium's GitHub repo][hstspreload-chromium-github].

---

### HSTS quiz: true or false?

<details>
  <summary>
   
   `http://yourdomain.com` should also responds with the HSTS header.
 </summary>
 
 False. See [MDN's page about HSTS][hsts-mdn]:
 
 >  The `Strict-Transport-Security` header is **ignored** by the browser when your site is accessed using HTTP;
 > this is because an attacker may intercept HTTP connections and inject the header or remove it.
 > When your site is accessed over HTTPS with no certificate errors, the browser knows your site is HTTPS capable
 > and will honor the `Strict-Transport-Security` header.
</details>

<details>
  <summary>
   
   My domain must serve a single wildcard certificate to use HSTS.
 </summary>
 
 False. You can use multiple certificates.
 What matters is that your domain and all its subdomains serve valid TLS certificates.
</details>

<details>
  <summary>
   
   HSTS applies to all user agents, even to non-browsers like `curl` and [Postman][postman].
  </summary>
 
  False. HSTS is a browser mechanism.
</details>

<details>
  <summary>

   No possible harm can come to me if my domain use the `preload` directive without actually being on the HSTS-preload list.
  </summary>
 
  False: if your domain fulfil the requirements to get HSTS-preloaded, [anybody can add to the HSTS preload list][scott-helme-copypaste].
  This would result in a client-side denial of service to subdomains that cannot serve a valid certificate. 
</details>

<details>
  <summary>
   
   Once I've satisfied the conditions for my domain to be added to the HSTS preload list,
   I must continue to satisfy those conditions or my domain runs the risk of being removed from the list.
 </summary>
 
  True. See [`hstspreload.org`'s continued requirements][hstspreload-continued-requirements].
</details>

<details>
  <summary>
   
   I can quickly remove my domain from the preload list at any stage, with immediate effect.
  </summary>
 
  False. Removal from the list is possible, but [can take time][hstspreload-removal], and browsers don't even guarantee they will honour this removal quickly:
 
  > Please note that a preload list domain removal may take 6-12 weeks to reach most Chrome users, and may take longer for other browsers.
</details>

---

### HSTS case studies

* Review `jub0bs.com`'s HSTS policy.
* Does your domain already have a HSTS policy? If not, could it? Discuss.

---

### Resources about HSTS

* [MDN's page on HSTS][hsts-mdn]
* [OWASP's HTTP Strict Transport Security Cheat Sheet][owasp-hsts]
* [Scott Helme - HSTS cheat sheet][scott-helme-hsts]
* [Scott Helme - Death by copy/paste][scott-helme-copypaste]
* [hstspreload.org][hstspreload]
* [RFC 6797: HTTP Strict Transport Security (HSTS)][rfc-6797]

[acme-wiki]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
[albinowax-about-complexity]: https://www.youtube.com/watch?v=gAnDUoq1NzQ&t=20s
[burp]: https://portswigger.net/burp
[chromium-referer-spoofing]: https://bugs.chromium.org/p/chromium/issues/detail?id=1233375
[defence-in-depth]: https://en.wikipedia.org/wiki/Defense_in_depth_(computing)
[dig-ditches]: https://www.youtube.com/watch?v=xPGdOXstSyk&t=180s
[doesmysiteneedhttps]: https://doesmysiteneedhttps.com/
[helms-deep]: https://cdnb.artstation.com/p/assets/images/images/006/318/889/large/adam-middleton-lotr-helms-deep-01-am.jpg
[html-spec-noopener]: https://github.com/whatwg/html/issues/4078
[https-everywhere]: https://www.eff.org/https-everywhere
[hstspreload]: https://hstspreload.org
[hstspreload-continued-requirements]: https://hstspreload.org/#continued-requirements
[hstspreload-iterative]: https://hstspreload.org/#deployment-recommendations
[hsts-network-attack]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#an_example_scenario
[hstspreload-removal]: https://hstspreload.org/removal/
[hstspreload-chromium-github]: https://github.com/chromium/chromium/blob/master/net/http/transport_security_state_static.json
[hsts-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
[http-01]: https://letsencrypt.org/docs/challenge-types/#http-01-challenge
[least-privilege]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
[myblog]: https://jub0bs.com/posts
[noopener-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types/noopener
[noopenerbydefault-compat-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#browser_compatibility
[owasp-hsts]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
[postman]: https://www.postman.com/
[rfc-6797]: https://datatracker.ietf.org/doc/html/rfc6797
[sca-owasp]: https://owasp.org/www-community/Component_Analysis
[scott-helme-copypaste]: https://scotthelme.co.uk/death-by-copy-paste/
[scott-helme-hsts]: https://scotthelme.co.uk/hsts-cheat-sheet/
[shodan]: https://www.shodan.io/
[snyk]: https://snyk.io/
[subdomain-takeover]: https://www.honeybadger.io/blog/subdomain-takeover/
[subdomain-xir]: 	https://twitter.com/jub0bs/status/1139927828370210817
[supply-chain-attack-wiki]: https://en.wikipedia.org/wiki/Supply_chain_attack
[tabnabbing-honeybadger]: https://www.honeybadger.io/blog/link-vulnerabilities/#reverse-tabnabbing
[ticketmaster-fined]: https://ico.org.uk/about-the-ico/news-and-events/news-and-blogs/2020/11/ico-fines-ticketmaster-uk-limited-125million-for-failing-to-protect-customers-payment-details/
[tofu-wiki]: https://en.wikipedia.org/wiki/Trust_on_first_use
[transparency-logs]: https://certificate.transparency.dev
[transparency-logs-search]: https://transparencyreport.google.com/https/certificates?hl=en
[troyhunt-https-youtube]: https://www.youtube.com/watch?v=_BNIkw4Ao9w
[twitter-jub0bs]: https://twitter.com/jub0bs
[waldo]: https://images.firstpost.com/wp-content/uploads/2018/04/Wheres-waldo-wally-google-maps-380.png
[web-skimming-wiki]: https://en.wikipedia.org/wiki/Web_skimming
