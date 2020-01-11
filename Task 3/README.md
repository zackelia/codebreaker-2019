# Task 3 - Turn of Events - [Getting Started - Part 3] - (Database Analysis)

*Analysts found TerrorTime installed on a device that was taken from a terrorist arrested at a port of entry in the US. They were able to recover the SQLite database from the TerrorTime installation on the device, which should provide us with more in-depth knowledge about the terrorist's communications and the TerrorTime infrastructure. Your goal for this task is to analyze the database and submit the addresses of the TerrorTime OAUTH (authentication) and XMPP (chat) servers.*

*Downloads:*

* *Database (clientDB.db)*

## Solution

For this task, we need to analyze the database to find the IP addresses for the OAuth and XMPP servers.

To view the SQLite database, we will use [DB Browser for SQLite](https://sqlitebrowser.org/dl/). After opening the database, we see that the only information is an entry in the Clients table. The only two pieces of data that are addresses are the xsip `chat.terrortime.app` and the asip `register.terrortime.app`. These are the XMPP and OAuth servers respectively.

Since these are domain names and we need IP addresses, we will need a simple networking tool to resolve the domains. Here we will use `ping`:

```
$ ping chat.terrortime.app
PING chat.terrortime.app (54.91.5.130): 56 data bytes
```

```
$ ping register.terrortime.app
PING codebreaker.ltsnet.net (54.197.185.236): 56 data bytes
```

The IP addresses for the servers are `54.91.5.130` (XMPP) and `54.197.185.236` (OAuth).
