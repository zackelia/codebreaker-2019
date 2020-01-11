# Task 1 - It Begins! - [Getting Started - Part 1] - (Network Traffic Analysis)

*There are many challenges that we will need to overcome in order to exploit TerrorTime. The first is that we do not yet have a copy of it. We have learned few details through intelligence sources, but the terrorists have managed to keep the app hidden. It is not publicly available on any App Store. Fortunately, as part of a recent military operation, specialized collection gear was forward deployed near the terrorist's area of operations. This resulted in a trove of collected traffic and we need your help to analyze it. Your first task is to find and extract a copy of the TerrorTime Android Package (APK) file from the packet capture. Submit the APK's SHA256 hash. This will help us search other intelligence sources for connections to users. To test out the app, we also need the registration information their leadership uses to register each client. Analyze the packet capture for this data and submit the registration information for 2 clients (in any order).*

*Downloads:*

* *Captured Traffic (terrortime.pcapng)*

## Solution

For this task, we need to analyze the given network traffic to find the TerrorTime APK and registrations information for two clients.

The provided traffic is given as a pcap file and one of the most widely used tools for analyzing these files is [Wireshark](https://www.wireshark.org/download.html). Opening the file in Wireshark shows over 8000 packets which is quite a bit to analyze manually. Thankfully, Wireshark has a convenient option to extract files from a packet trace. `File > Export Objects > HTTP...` shows us that there are two files which we will save for analysis.

`terrortime.apk` is the TerrorTime Android application and `README.developer` is an internal developer log.

We can obtain the SHA-256 hash of the APK with a simple command:

```
$ shasum -a 256 terrortime.apk
0d3445e984e04b684f9636ca20c60f9bb73c050ae623ac9e51f50675222d3397  terrortime.apk
```

And the credentials for leadership can be viewed in the README in plain text:

```
keily--vhost-32@terrortime.app -- First Terrortime test account client id
preston--vhost-32@terrortime.app -- Second Terrortime test account client id
3kY3uYB8oEAfuC -- First Terrortime test account client secret
k9ytf7UHYniYTM -- Second Terrortime test account client secret
```
