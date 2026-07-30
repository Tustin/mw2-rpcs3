You are tasked with emulating the Demonware matchmaking service for Call of Duty: Modern Warfare 2 (2009). Refer to CURRENT_PROGRESS.md to see what tasks need to be accomplished and the current status of the implemtation. Also ensure you update this file when tasks are completed/updated. We will be using RPCS3 to test. When working on tasks, stick to one at a time and work your way down. We don't want to get bogged down trying to solve multiple tasks/issues as the same time.

The captures/ folder contains useful debugging and reverse engineering items:

- mw2 ps3.pcapng is a full capture from game start to lobby on a retail PS3 with successful demonware authentication. It should be used as the source of truth. If you refer to any 3rd party demonware projects, they might be implemtning demonware from another Call of Duty title that won't necessarily match Modern Warfare 2.

- default_mp.elf is a decrypted executable of the multiplayer of Modern Warfare 2 on PS3.

- RPCS3 log can be found at /mnt/e/rpcs3/log/RPCS3.log. I have enabled network debugging traces in RPCS3 so it will log all PS3 network calls.

- iw6_ds_ps3.exe/pdb is a Call of Duty Ghosts PS3 server executable with debug symbols available. It might be useful as it's also an Infinity Ward title, albeit it a couple years newer than Modern Warfare 2. It might be useful for cross referencing strings to the default_mp.elf.

- server_log.log is the latest log from the server. It was ran in debug mode so it can provide as much detail as necessary.

You also have access to IDA Pro MCP server which has default_mp.elf loaded for debugging purposes if you need to reverse engineer any of the demonware structures, enums or functions for more clarity.
