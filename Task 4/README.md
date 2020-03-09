# Task 4 - Schemes - (Cryptography; Reverse Engineering; Language Analysis)

*While analyzing the TerrorTime SQLite database found on the terrorist’s device, analysts discovered that the database has cached credentials but requires a pin to log in. If we can determine how the credentials are protected and find a way to recover the pin, we should be able to masquerade as the arrested terrorist. Perform reverse engineering to identify how the terrorist’s credentials are protected and submit the terrorist's Client ID and Client Secret. Once you have uncovered their credentials, masquerade (i.e., login) as him using the TerrorTime app. Review their chat history and assess additional information regarding their organization. Though the app encrypts messages back and forth, the terrorists have previously spoken in some form of code to ensure their plans were protected. To prove completion of this task, you will need to analyze the terrorist's conversation history in order to uncover/deduce the following information:*


* *Terror Cell Leader's Username*
* *The date on which the action will occur*

## Solution

For this task, we need to reverse engineer the database and TerrorTime application in order to log in as the arrested terrorist.

**Note**: Task 4 is where the difficulty begins to get exponentially harder and reverse engineering is necessary. To begin the rest of these harder challenges, we will set up an Android emulator and a reverse engineering environment.

To create a new emulator, we will open the AVD Manager within Android Studio. The device does not matter but we need to choose a compatible OS. If we look back at `AndroidManifest.xml`, we see that the minimum version needed is API 26 (Oreo). We will choose Oreo x86 with Target Android 8.0 because it is a smaller size image and it is trivial to root. Once we boot the emulator, we can drag `terrortime.apk` onto the device to install it.

Before attempting reverse engineering, we will gather what we can by just using the app. The part of the app relevant to this task is the login screen. The client ID to use is `natalie--vhost-32@terrortime.app` which is found in the database. If we put in a random password, we see that the requirement is that the password is a pin that is exactly six numbers. In the database, this would make the most sense with the `checkpin` column. If we look at the data, there is not a pin but 32 seemingly random bytes which indicate some form of encoding or encryption. With this knowledge, it is now time to reverse engineer.

We will use [Ghidra](https://ghidra-sre.org) to analyze the code from the APK. First, we will create a new non-shared project and figure out which files to import. Compiled Android code is stored in `.dex` files and with larger apps there will be multiple such files due to multidex. In our case, there are three. Not all of them might be useful, so we will do a quick search to see if they all have contents relating to TerrorTime.

```
$ strings classes.dex  | grep -q -i terrortime && echo found
$ strings classes2.dex | grep -q -i terrortime && echo found
found
$ strings classes3.dex | grep -q -i terrortime && echo found
```

After running these commands, we see that only `classes2.dex` has relevant code so we will import that into Ghidra and let it run its initial analysis. Once analysis is complete, we will take a look at the exports and classes to get a feel of what methods exist. What initially sticks out is that code is written in a standard Java paradigm with getters and setters as access control. With this, we will easily be able to see how variables are stored and retrieved.

To learn more about the `checkpin` column, we will look at `setCheckPin`. We see that the bytes are stored in an object of type `BlobAppField`, which is not a native type to Java or any library. Since this value is being compared when we login and it is a custom type, there must be an overridden `equals` method for this type. There are several `equal` functions but we will choose the one from the `BlobAppField` class. We can now use `Show References to` in order to see where this function is called. The two results are the Client `equals` and `generateSymmetricKey`.

Looking at `generateSymmetricKey`, we see that an `encryptPin` is being "checked" against the `checkPin`. Using the decompiled Java, we can see how these values are calculated.

```java
ref_04 = this.encryptPin;
ref = ref_04.getValue()
...
ref_05 = this.checkPin;
pbVar2 = ref_05.getValue();
ref_00 = MessageDigest.getInstance("SHA-256");
pbVar3 = ref.getBytes("UTF-8");
pbVar3 = ref_00.digest(pbVar3);
...
ref_05 = new BlobAppField(pbVar3);
bVar1 = ref_05.equals(this.checkPin);
```

We can reason that `encryptPin` must be the user input because it is being compared to the stored `checkPin`. Before the comparison, the user input is hashed using SHA-256. This makes sense because SHA-256 hashes are 32 bytes like the value we saw earlier. Since hashing is a one-way function, there is no way to reverse it so it must be brute forced. Luckily, we know that the pin is a six digit number so it is trivial to crack it using Python.

```python
import hashlib

checkPin = "1f86e51f7187772c1c7bb589299162e466f0c99d72abf4a2b04da03e9f70766e"

for i in range(1000000):
    encryptPin = str(i).zfill(6)  # Format as a six digit number
    hash = hashlib.sha256(encryptPin.encode()).hexdigest()
    
    if hash == checkPin:
        print(encryptPin)
```

The program quickly prints the pin `207698`. If we log in with our client ID and this pin, it should work, but it does not. This is because we need to load the database with the cached credentials onto the emulator to replicate the terrorist's device. We can use the `adb` tool from Android Studio to do this.

```
$ adb root
$ adb shell

generic_x86:/ # find . -name "clientDB.db" 2> /dev/null
./data/data/com.badguy.terrortime/databases/clientDB.db
generic_x86:/ # exit

$ adb push clientDB.db /data/data/com.badguy.terrortime/databases/
[100%] /data/data/com.badguy.terrortime/databases/clientDB.db
```

Now if we log in again, we can successfully see Natalie's messages! She has been talking to two other individuals, Alice and Gittel. To determine the relevant information, we have to examine important parts of the conversations about time.

```
Natalie: the spirits will be picked up at 1416
Gittel: Exactly. before the holiday, 2 days
...
Alice: we will not let Gittel down.
Natalie: yes
Natalie: see you before Memorial Day
```

After examining the conversations, it appears that Alice is another cell member and Gittel is their cell leader. Gittel's client ID would be `gittel--vhost-32@terrortime.app`. The action date is May 23, 2020 at 2:16 PM. The Unix timestamp for this date is `1590243360`.
