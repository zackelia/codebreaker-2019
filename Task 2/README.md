# Task 2 - Permissions - [Getting Started - Part 2] - (Mobile APK Analysis)

*The TerrorTime APK file contains metadata that describes various security properties of the application that we want to know. Since we now have a copy of the APK thanks to the military operation described in Task 1, we need you to identify and submit the following:*

* *App Permissions*
* *The SHA256 hash of the Code Signing Certificate*
* *The Common Name of the Certificate Signer*

*Please note that completion of task 1 is required to complete this task.*

*Downloads:*

* *Captured Traffic (terrortime.pcapng)*

## Solution

For this task, we need to idenitfy information about the APK and its signing certificate.

To examine the APK, we will use [Android Studio](https://developer.android.com/studio) and some of the tools that it installs. We can start to view metadata for the APK by choosing `Profile or debug APK`. There are many folders and compiled files but the most important file is `AndroidManifest.xml`. This file is essential to every Android app and contains the app's package name, components, permissions, and software/hardware features. The permissions are easily located in the `uses-permission` tags:

```
<uses-permission
    android:name="android.permission.INTERNET" />

<uses-permission
    android:name="android.permission.ACCESS_NETWORK_STATE" />
```

The permissions are `INTERNET` and `ACCESS_NETWORK_STATE`.

In order to view certificate information, we will have to utilize a tool that comes with Android Studio. Searching the Android developer documentation for "Code Signing Certificate", we find a tool called `apksigner`. The usage page shows us how to view the certificate information:

```
$ apksigner verify --print-certs terrortime.apk
Signer #1 certificate DN: CN=dev_terrorTime_964446, OU=TSuite
Signer #1 certificate SHA-256 digest: 843591fa64697ff6471adf6fb897d135b83448833fdc2a0c16771fafc2a41f67
Signer #1 certificate SHA-1 digest: 070c5d0ab5e1866a5a2fc7692de26b7fc83d6539
Signer #1 certificate MD5 digest: 57444bc436df73adfed87ce012c858b2
```

The reamining information we need is listed in the output. The common name (CN) is `dev_terrorTime_964446` and the SHA-256 hash of the certificate is `843591fa64697ff6471adf6fb897d135b83448833fdc2a0c16771fafc2a41f67`.
