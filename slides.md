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

---

## Cookies

---

### The concept of Web origin

See https://developer.mozilla.org/en-US/docs/Glossary/Origin

---

### The public-suffix list and the concept of site

See

* https://publicsuffix.org/
* https://developer.mozilla.org/en-US/docs/Glossary/Site

"Site" is a painfully generic term behind such a technical concept!

---

### Cookies in a nutshell

HTTP itself is a stateless protocol. Cookies allow some persistence.

Cookies are set via [the `Set-Cookie` response header][set-cookie-mdn].

Cookies are a form of _ambient authority_:
the browser automatically attaches them to requests via the [`Cookie` request header][cookie-mdn].

Cookies are unique per (name, domain, path).

The source of many vulnerabilities...

---

### Cookie security attributes

See MDN's page about the [`Set-Cookie` header][set-cookie-mdn].

---

#### `Domain`

<details>
 <summary>
  
  What dangers are associated with a broadly scoped cookie e.g. `Domain=efl.fr`?
 </summary>
  
 It's sent to all subdomains of `efl.fr`, including those controlled by third parties.
 What if some subdomain is vulnerable to takeover?
</details>

---

#### `HttpOnly`

* Prevents JavaScript code from reading/setting the cookie
* Useful defence against session hijacking
* Useful for process-isolation purposes (more on that later)

<details>
 <summary>
  
  `HttpOnly` is not that useful as a defence against cross-site scripting (XSS). Why?
 </summary>
  
  [It only prevents session hijacking, not forged requests.][portswigger-httponly]
</details>

---

#### `Secure`

* Tells the browser not to attach the cookie to `http` requests
* Disallows JavaScript code served from `http` origins from reading/setting the cookie

---

#### `SameSite`

* Defence mechanism against cross-site request forgery (CSRF)
* Governs "from which domains" cookies can come from
* Cookies marked `SameSite=None` must also be marked `Secure`.
* Now defaults to `Lax` in Chromium and Firefox

<details>
 <summary>
  
  Can you rely solely on the `SameSite` attribute to protect users against CSRF>
 </summary>
  
 [Not if you cannot trust your subdomains or sibling domains][samesite-jub0bs]. 
</details> 

---

### Cookie prefixes

Problem: the browser doesn't send the attributes that a cookie was set with to the server.

Solution: [cookie prefixes][set-cookie-mdn].

* sort of in-band metadata
* provides more guarantees about cookies

---

## `noopener`

### Reverse tabnabbing

What is a potential issue with a user sharing the following link on your website?

```html
<a href="https://foobar.com" target="_blank">Click me!</a>
```

<details>
  <summary>
   
    Any ideas?
  </summary>
  
  The new window retains a reference to its opener (i.e. the window that opened it).
  The new window can modify its opener's `location`, a phenomenon known as [reverse tabnabbing][tabnabbing-honeybadger].
  It could, for instance, redirect visitors to a phishing site looking just like your website.
</details>

---
 
### `noopener` to the rescue

```html
<a href="https://foobar.com" target="_blank" rel="noopener">Click me!</a>
```

The [link type `noopener`][noopener-mdn] instructs browsers not to grant retain a reference to the window that opened the new one.
 
Update (2021): [the HTML spec has changed][html-spec-noopener];
windows opened via `<a target=_blank>` now don't have an opener by default [in all major browsers][noopenerbydefault-compat-mdn].

---

### `noopener` Case study

Is your website vulnerable to reverse tabnabbing? Why or why not?

---

## Referrer Policy

### The `Referer` header

Note the typo from the HTTP spec: the proper spelling is "referrer".

> The `Referer` HTTP request header contains an absolute or partial address of
> the page that makes the request. The `Referer` header allows a server to identify
> a page where people are visiting it from. This data can be used for analytics,
> logging, optimized caching, and more.

This request header is set by the browser automatically.

The `Origin` request header is a spiritual (and better-behaved) successor to `Referer`.

Because a URL, through its path and/or querystring, often contains sensitive data,
the `Referer` header can inadvertently leak sensitive data to third parties.

Case study: `Referer` header leaks password-reset links to third parties

---

### Referrer Policy

A mechanism for instructing in which situations and how much information
(either the full URL or only the URL's origin) the `Referer` header should contain.

A page's Referrer Policy can be specified

* either via the [`Referrer-Policy` response header][referrer-policy-mdn],
* or via a `<meta>` element.

You can also override the Referrer Policy in effect on specific HTML elements
via the `referrerpolicy` attribute.

---

### Referrer Policy recommendations

Because most modern browsers
[now default to `strict-origin-when-cross-origin`][referrer-policy-default-mdn]
the `Referer` header is less of a problem.

But you may want to adopt the even stricter `no-referrer` value:

```http
Referrer-Policy: no-referrer
```

That way, third-party origins won't know that people came from your website.

Case study: review your website's Referrer Policy.

---

## Cross-origin resource sharing (CORS)

### Same-origin policy

Arguably the cornerstone of browser security:

> The same-origin policy is a critical security mechanism that restricts
> how a document or script loaded by one origin can interact with a resource
> from another origin.

([MDN Web Docs][sop-mdn])

In particular, if origin B sends a request to a different origin A, and
origin B cannot read the response from origin A. Demo in the browser.

---

### The need for relaxing the SOP

The SOP is what keeps people secure, but it stands somewhat in the way of
modern Web practices:

* mashups
* single-page applications
* REST or GraphQL APIs

---

### Dangerous SOP workarounds

Before the advent of CORS, people had ingenious but dangerous techniques
for working around the SOP:

* [domain relaxation][domain-relaxation-html-spec]
* [JSONP][jsonp-wiki]

Avoid at all cost!

---

### CORS to the rescue

A mechanism for selectively _relaxing_ some of the restrictions imposed
by the SOP in browsers.

More specifically, CORS is

> an HTTP-header based mechanism that allows a server to indicate any origins
> (domain, scheme, or port) other than its own from which a browser should
> permit loading resources.

([MDN Web Docs][cors-mdn])

CORS is [a frequent source of frustration and misunderstanding for developers][cors-stackoverflow].
As a result, many take shortcuts and end up compromising the security of their users.

Don't be like them!

---

### CORS in a nutshell

The [MDN Web Docs][cors-mdn] on the topic is essential reading!

See also [Jake Archibald's CORS playground][cors-playground].

---

### Common misconceptions about CORS

<details>
 <summary>

 I can rely on CORS as the primary defence against cross-site request forgery.
 </summary>

 No, that's too dangerous. Developers make wrong assumptions and things go wrong.
</details>

<details>
 <summary>

 I can solve a CORS error I don't fully understand just by copying & pasting
 code from a highly upvoted answer on Stack Overflow.
 </summary>

 [Most definitely not!][cors-terrible-so-answer]
</details>

<details>
 <summary>

 CORS is a way to prevent random people from consuming my API.
 </summary>

 No. Those people can hit your API with a user agent other than a browser.
</details>

---

### CORS misconfiguration

Because CORS relaxes the browser's default security,
it's important to understand what can go wrong.

If you misconfigure CORS on your server,

* at best, things simply won't work,
* at worst, you will expose your users to cross-origin attacks meant to steal data.

---

### Common CORS misconfigurations

#### Arbitrary origin

```http
Access-Control-Allow-Origin: <origin>
Access-Control-Allow-Credentials: true
```

<details>
 <summary>

 How can this be abused?
 </summary>

 All origins are allowed. Game over!
</details>

---

#### Failed suffix check

The server allows (with credentials) any origin that matches the following regex:

```txt
^https://.*example\.com$
```

<details>
 <summary>

 How can this be abused?
 </summary>

 Origin `https://notexample.com` matches!
 See [a report of this problem to Zomato][cors-zomato-h1].
</details>

---

#### Failed prefix check

The server allows (with credentials) any origin that matches the following regex:

```txt
^https://.*\.example\.com
```

<details>
 <summary>

 How can this be abused?
 </summary>

 Origin `https://example.com.attacker.com` matches!
</details>

---

#### Failed regex escape

The server allows (with credentials) any origin that matches the following regex:

```txt
^https://.*\.example.co\.uk$
```

<details>
 <summary>

 How can this be abused?
 </summary>

 Origin `https://examplezco.uk` matches!
</details>
---

#### Null origin

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

<details>
 <summary>

 How can this be abused?
 </summary>

 Any sandbox iframe has the `null` origin!
</details>

---

#### Trusting insecure origins

```http
Access-Control-Allow-Origin: http://example.com
Access-Control-Allow-Credentials: true
```

<details>
 <summary>

 How can this be abused?
 </summary>

 It's [complicated][cors-insecure-origin]... but it defeats the server's use of HTTPS!
</details>

---

#### Arbitrary origin without credentials

```http
Access-Control-Allow-Origin: *
```

or 

```http
Access-Control-Allow-Origin: <request-origin>
```

<details>
 <summary>

 Can you think of situations in which this could be dangerous?
 </summary>

 What if the server is bound to an inaccessible network interface (like `localhost`)?
 
 Case study: [WebStorm][cors-webstorm]
</details>

Audit your website for CORS usage. Is it well configured? Can it be abused?

---

### Good CORS practices

* make sure you understand CORS
* use strong origin validation
* think about the trust relationship between your server and allowed origins
* don't rely on your CORS policy as the primary defence against CSRF
* validate requests' `Content-Type`
* don't implement CORS yourself: use a dependable library/middleware
* any changes to your CORS policy should be subject to review

---

### Resources about CORS

* [MDN Web Docs about CORS][cors-mdn]
* [PortSwigger - Exploiting CORS misconfigurations for Bitcoins and bounties][cors-portswigger]
* [Fetch standard][fetch-standard]
 
---

## Subresource integrity

### Problems with scripts hosted by third parties

Assume that some frontend HTML contains the following piece of code:

```html
<script src="https://somethirdparty.com/foobar.js"></script>
```

Domain `somethirdparty.com` is a domain you do not own.

Let's assume that you've audited `foobar.js` and determined that executing that code in the context of your app is secure...

<details>
  <summary>What could possibly go wrong?</summary>
  
How can you be sure that `foobar.js` will remain safe? The hosting third party may
  
1. make well-intentioned but dangerous changes to `foobar.js`,
2. get bought by some malicious actor,
3. get compromised by some malicious actor.
  
</details>

What about the following?

```html
<script src="https://cdn.yourdomain.com/foobar.js"></script>
```

<details>
  <summary>What could possibly go wrong?</summary>
  
* Is `cdn.yourdomain.com` pointing to a third-party service via a CNAME DNS record?
* If so, can you trust that third party?
  
</details>

What about the following?

```html
<script src="https://yourbucket.s3.us-west-2.amazonaws.com/foobar.js"></script>
```

<details>
  <summary>What could possibly go wrong?</summary>
  
* Does the bucket in question have a strict ACL?
* Can objects within it be overwritten?
  
</details>

---

### Supply-chain attacks & Web skimming

> [...] a cyber-attack that seeks to damage an organization by targeting less-secure elements in the supply chain.

([Wikipedia][supply-chain-attack-wiki])

Many supply-chain attacks against websites consist in _Web skimming_:

> [...] an attack where the attacker injects malicious code into a website and extracts data from an HTML form that the user has filled in.

([Wikipedia][web-skimming-wiki])

How? In many cases, by compromising a third party that hosts JavaScript loaded by the targeted website.

---

#### Case study: Ticketmaster

Ticketmaster was later [fined £125 million by the ICO][ticketmaster-fined] (the UK's CNIL):

> The Information Commissioner’s Office (ICO) has fined Ticketmaster UK Limited £1.25million for failing to keep its customers’ personal data secure.
>
> The ICO found that the company failed to put appropriate security measures in place to prevent a cyber-attack on a chat-bot installed on its online payment page.
>
> Ticketmaster’s failure to protect customer information is a breach of the General Data Protection Regulation (GDPR).
 
---
 
### Subresource integrity to the rescue
 
See https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
 
Does your site use subresource integrity for scripts/styles served by third parties?
 
---

## X-Content-Type-Options

### MIME-type sniffing

When a response lacks a `Content-Type` header,
browsers inspect the response body to try to [guess the content type][sniffing-standard].

This is problematic because browsers may be tricked into
interpreting user-generated content as something executable.

Moreover, sniffing has a performance cost.

---

### The `X-Content-Type-Options` header

This [response header][x-content-type-options-mdn] accepts only one value, `nosniff`,
which instructs browsers

* not to guess the content type, and
* simply default to a harmless, non-executable content type.

---

### Don't leave browsers in doubt!

Systematically add a `Content-Type` header to responses and use

```http
X-Content-Type-Options: nosniff
```

---

## `X-Frame-Options`

This response header that restricts which origins can frame the page.

Useful to protect users against attacks like [clickjacking][clickjacking-owasp].

Superseded by the `frame-ancestors` CSP directive in modern browsers, but
still useful for older browsers (IE) that do not support CSP.

---

## The `X-XSS-Protection` response header

### XSS Auditor

A set of heuristics to detect (and possibly remove) malicious script
injected in the page by an attacker.

The XSS Auditor is [problematic][x-xss-protection-filedescriptor] because

* false positives can be abused by attackers,
* false negatives (bypasses) exist.

For these reasons,

* Chromium no longer has an XSS Auditor,
* Firefox never had and never will have one.

However, Internet Explorer and Safari still have an XSS Auditor, which is on by default.

Content Security Policy is a modern alternative to the XSS Auditor.

---

### `X-XSS-Protection`

This response header allows you to configure the XSS Auditor for the page.

A recommended setting, for the benefit of IE users, is

```http
X-XSS-Protection: 1; mode=block
```

which causes the browser not to render the page if the XSS Auditor detects
something suspicious.

---

## Content Security Policy (CSP)

### A defence-in-depth mechanism

* places restrictions on sources of the page's Web content
* creates additional obstacles for attackers
* helps mitigate attacks like XSS and clickjacking
* not a licence to drop other defence mechanisms!

---

### CSP complexity

* a powerful, but complex beast
* the Swiss Army knife of browser security!
* features and best practices are still evolving

---

### The `Content-Security-Policy` headers

See [MDN Web Docs][csp-mdn] about it.

A page's CSP can alternatively be set via a `<meta>` HTML element.

Any CSP violation results in an error in the browser console.

---

### Notable CSP directives

* `default-src`
* `script-src`
* `style-src`
* `connect-src`
* `object-src`
* `form-action`
*  `base-uri`
* `frame-ancestors` and `frame-src`
* `report-to`

---

### CSP in reporting mode only

The `report-to` directive allows you to specify where CSP violation reports will be sent by your users's browsers.

It's best to point `report-to` to a dedicated server
or third-party service (e.g. [Report URI][report-uri]). Why?

The [MDN Web Docs about the `Content-Security-Policy-Report-Only` header][cspro-mdn]
allows you to test a CSP in production without actually raising errors.

---

### Audit your CSP

Some CSPs can give you a [false sense of security][cheeto-lock],
but can easily be bypassed.

[Google's CSP evaluator][csp-evaluator] allows you to audit your CSP
and gives you guidance for improving it.

---

### Case study: Twitter's CSP

Visit https://twitter.com and inspect the response `Content-Security-Policy` header.

Use [Google's CSP evaluator][csp-evaluator] to an audit of that CSP.

---

### Setting up a CSP for your website

You can adopt an iterative approach locally at first:

1. choose a very strict CSP
2. set up your intercepting proxy to inject the `Content-Security-Policy` header in responses
3. navigate your website
4. take note of all the CSP errors raised in your browser's console
5. relax your CSP to correct those errors
6. repeat steps 3-5 until all CSP errors are gone
7. audit your CSP on [Google's CSP evaluator][csp-evaluator]
8. fix issues

Once you're happy,

1. enable your CSP in report-only mode
2. monitor and fix any errors by your users's browsers

Once you're confident that your CSP is solid,

1. enable your CSP for real
2. keep monitoring and fixing any errors by your users's browsers

---

### When CSP backfires

CSP implementation varies from one browser to another.

Security researchers have found that CSP can be abused to leak data across origins:

* [crbug 1259077: form-action's blocking of redirects allows top-navigation XSLeak][crbug1259077]
* [Threat Nix - Exploiting CSP in Webkit to Break Authentication & Authorization][prakash]

---

## Fetch Metadata

### The need for request metadata

Servers have little information about the context in which a request was
initiated in the browser.

In particular, not all requests contain `Referer` and `Origin` headers.

---

### Fetch Metadata to the rescue

A set of [four request headers][fetch-metadata-mdn] automatically added by the browser.

Servers can [leverage those request metadata][fetch-metadata-webdev] in order to

* implement some server-side isolation policy,
* defend users against cross-origin attacks.

A promising technology!

Not widely supported yet: only in Chromium and Firefox.

Little library/framework support so far...

Would you have a use for Fetch Metadata headers?

[acme-wiki]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
[albinowax-about-complexity]: https://www.youtube.com/watch?v=gAnDUoq1NzQ&t=20s
[burp]: https://portswigger.net/burp
[crbug1259077]: https://bugs.chromium.org/p/chromium/issues/detail?id=1259077
[cheeto-lock]: https://i.kym-cdn.com/entries/icons/original/000/026/380/lock.jpg
[csp-evaluator]: https://csp-evaluator.withgoogle.com/
[csp-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
[cspro-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
[owasp-juice-shop-github]: https://github.com/juice-shop/juice-shop
[owasp-juice-shop-heroku]: https://jub0bs-owasp-juice-shop.herokuapp.com/#/
[x-xss-protection-filedescriptor]: https://blog.innerht.ml/the-misunderstood-x-xss-protection/
[fetch-metadata-mdn]: https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header
[fetch-metadata-webdev]: https://web.dev/fetch-metadata/
[report-uri]: https://report-uri.com/
[prakash]: https://threatnix.io/blog/exploiting-csp-in-webkit-to-break-authentication-authorization/
[sniffing-standard]: https://mimesniff.spec.whatwg.org/#introduction
[x-content-type-options-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
[clickjacking-owasp]: https://owasp.org/www-community/attacks/Clickjacking
[chromium-referer-spoofing]: https://bugs.chromium.org/p/chromium/issues/detail?id=1233375
[cors-stackoverflow]: https://stackoverflow.com/questions/tagged/cors
[cors-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[cors-playground]: https://jakearchibald.com/2021/cors/playground/
[cors-insecure-origin]: https://twitter.com/jub0bs/status/1352160391032401923
[cors-portswigger]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
[cors-zomato-h1]: https://hackerone.com/reports/168574
[cors-webstorm]: http://blog.saynotolinux.com/blog/2016/08/15/jetbrains-ide-remote-code-execution-and-local-file-disclosure-vulnerability-analysis/
[cors-terrible-so-answer]: https://stackoverflow.com/questions/8719276/cross-origin-request-headerscors-with-php-headers/9866124#9866124
[defence-in-depth]: https://en.wikipedia.org/wiki/Defense_in_depth_(computing)
[dig-ditches]: https://www.youtube.com/watch?v=xPGdOXstSyk&t=180s
[doesmysiteneedhttps]: https://doesmysiteneedhttps.com/
[domain-relaxation-html-spec]: https://html.spec.whatwg.org/multipage/origin.html#relaxing-the-same-origin-restriction
[fetch-standard]: https://fetch.spec.whatwg.org/
[helms-deep]: https://cdnb.artstation.com/p/assets/images/images/006/318/889/large/adam-middleton-lotr-helms-deep-01-am.jpg
[html-spec-noopener]: https://github.com/whatwg/html/issues/4078
[httponly-portswigger]: https://portswigger.net/research/web-storage-the-lesser-evil-for-session-tokens#httponly
[https-everywhere]: https://www.eff.org/https-everywhere
[hstspreload]: https://hstspreload.org
[hstspreload-continued-requirements]: https://hstspreload.org/#continued-requirements
[hstspreload-iterative]: https://hstspreload.org/#deployment-recommendations
[hsts-network-attack]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#an_example_scenario
[hstspreload-removal]: https://hstspreload.org/removal/
[hstspreload-chromium-github]: https://github.com/chromium/chromium/blob/master/net/http/transport_security_state_static.json
[hsts-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
[http-01]: https://letsencrypt.org/docs/challenge-types/#http-01-challenge
[jsonp-wiki]: https://en.wikipedia.org/wiki/JSONP
[least-privilege]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
[myblog]: https://jub0bs.com/posts
[noopener-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types/noopener
[noopenerbydefault-compat-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#browser_compatibility
[owasp-hsts]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
[postman]: https://www.postman.com/
[referrer-policy-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
[referrer-policy-default-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy#browser_compatibility
[rfc-6797]: https://datatracker.ietf.org/doc/html/rfc6797
[samesite-jub0bs]: https://jub0bs.com/posts/2021-01-29-great-samesite-confusion/
[sca-owasp]: https://owasp.org/www-community/Component_Analysis
[scott-helme-copypaste]: https://scotthelme.co.uk/death-by-copy-paste/
[scott-helme-hsts]: https://scotthelme.co.uk/hsts-cheat-sheet/
[set-cookie-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
[shodan]: https://www.shodan.io/
[sop-mdn]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
[snyk]: https://snyk.io/
[subdomain-takeover]: https://www.honeybadger.io/blog/subdomain-takeover/
[subdomain-xir]: https://twitter.com/jub0bs/status/1139927828370210817
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
