# Denial of Service through Cache Poisoning and Misconfigured CORS Origins

This repository is strongly linked to the repo [link]. The script `doscors.py` checks whether sites that using CORS (Cross-Origin Resource Sharing) can be vulnerable to a Denial of Service (DoS) attack exploiting the Same-Origin Policy (SOP).

The project investigates a particular form of Denial of Service (DoS) attack that arises from cache poisoning, caused by misconfigured Cross-Origin Resource Sharing (CORS) origins. In this scenario, an attacker manipulates a web application's cache by inserting malicious content or directives. The misconfigured CORS origins further allow this poisoned cache to be served to genuine users. When users attempt to access the resources, the Single Origin Policy (SOP) blocks the request due to the malicious CORS headers in the poisoned cache, thereby denying service.

The cache poisoning process encompasses the following steps:

![dos.png](/img/dos.png)

1. **Sending a Malicious Request**:
   - In this step, an attacker crafts and sends a malicious request aimed at exploiting vulnerabilities within the caching mechanism of the target system.

2. **Forwarding the Request from Cache to the Server**:
   - Upon receiving the request, the cache checks for a valid stored response. If a response is either not present or has expired, the cache forwards the request to the server to obtain a fresh response.

3. **Acceptance of the Malicious Origin by the Server**:
   - The server processes the forwarded request and generates a response. In a cache poisoning scenario, the server mistakenly treats the malicious request as legitimate and responds accordingly.

4. **Storing the Bad Response in the Cache Table**:
   - Unaware of the server's error, the cache stores the malicious response in its cache table associating it with the corresponding request. This step ensures that future requests for the same resource will retrieve the poisoned response from the cache, culminating in a DoS for legitimate users.

## How to run

Install the dependencies: pip install -r requirements.txt

#### Launcher 
Make sure to have launched corsoauth.py beforehand.
```bash
python3 doscors.py
```

## Authors
This code was developed by Matteo Golinelli, Elham Arshad and Dmytro Kashchuk
