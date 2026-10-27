blaster
=======

Blaster is a tool for querying servers from the Valve Master Server List. There are three components: a set of libraries for querying Valve protocols (which have many edge cases), a concurrent batch-processing library, and a command-line tool for getting query results as JSON.

Valve's master server has a rate limit of about 15 queries per minute, and returns a batch of ~220 servers for each query. For a popular game, it can take a long time (around ten minutes) to retrieve its entire server list. Blaster will query individual game servers in the background to lessen the overall waiting time. By default it processes 20 servers concurrently; use `-j` to change this (more will introduce more timeouts).

This is a fork of [alliedmodders/blaster](https://github.com/alliedmodders/blaster). It adds support for servers that send several A2S_INFO challenges in a row, A2S_PLAYER queries, and hardened A2S_RULES parsing.

Usage
-----
You can use blaster either across all of Half-Life 1 or Half-Life 2, or with a specific list of Application IDs. For a full list of Application IDs, see: https://developer.valvesoftware.com/wiki/Steam_Application_IDs

For example, querying "Bloody Good Time":
```
$ blaster -appids 2450 -norules -format=list
[
	{
		"ip": "168.62.205.3:27016",
		"protocol": 17,
		"name": "DMServer",
		"map": "horrorhouse",
		"folder": "pm",
		"game": "Bloody Good Time",
		"players": 9,
		"max_players": 16,
		"bots": 6,
		"type": "dedicated",
		"os": "windows",
		"visibility": "public",
		"vac": true,
		"appid": 2450,
		"game_version": "1.0.0.0",
		"port": 27016,
		"steamid": "90091830459546624",
		"gameid": "2450",
		"rules": null
	}
]
```

Building
--------

You will need Go 1.27+ installed (see: https://go.dev/doc/install).

```bash
go install github.com/nikooo777/blaster@latest
```

Or build from source:

```bash
git clone https://github.com/nikooo777/blaster.git
cd blaster
go build
```

The query libraries can also be used on their own:

```go
import "github.com/nikooo777/blaster/valve"
```

Resources
---------
https://developer.valvesoftware.com/wiki/Master_Server_Query_Protocol
https://developer.valvesoftware.com/wiki/Server_queries
