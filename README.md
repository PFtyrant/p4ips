# P4-IPS

## Note
**Please check your SDE env variables first. If you have not set SDE env vars, P4-IPS can't be run.**

Running Steps:
Compile P4Zeek_DP -> Compile P4Zeek_CP -> run P4Zeek_CP -> send pakcets(tcpreply with attached Pcap file) -> send terminate packet -> see result.

Server jobs:
  send pakcets(tcpreply with attached Pcap file)
Switch jobs:
  Compile P4Zeek_DP, Compile P4Zeek_CP, run P4Zeek_CP, send terminate packet.

---
## P4Zeek Data-Plane
### How to build?
move into P4Zeek_DP directory.
```bash
  cd ~/p4ips/P4Zeek_DP
  make
```
Makefile will process configuration, compilation, and installation.
After make, there is no job to do. moving to P4Zeek_CP for compiling the control plane.

## P4Zeek Control-Plane
### How to build?
move into P4Zeek_DP directory.
```bash
  cd ~/p4ips/P4Zeek_CP
  make
```
---
## How ot run?
### ENV setup

Add path env variable for the completion, which will be used in P4Zeek_cp.

```
  export PATH=$PATH:$SDE_INSTALL/bin
```

### Running APP
P4Zeek_CP Makefile will process g++ compilation, after compilatoin, which will generates "build" directory.
After cmopiling move into "build" dir.
```bash
  cd ~/p4ips/P4Zeek_CP/build
  # run P4Zeek(P4-IPS) This step will cover all of the settings, which include setting table, insertnig entries of table, port setting.
  ./P4Zeek_cp 100
```
> In this case, $1 is 100. $1 argument value present how to determine CPU usage and info. But it is not correct now, don't care abuot it.

### Dump NN network reponose time.
Note: Please sending packet first!

Sending terminate packet into CPU port, APP will Sensenig packet, and will print out NN network response time information to CLI.
The "otuput.txt" file represents which one is malware(label = 1) or not(label = 0). But, the result of the outupt.txt may not be the same for every running. 
Because P4Zeek_CP doesn't handle packets by sequential order(multi-threading).
```bash
  cd ~/p4ips/P4Zeek_CP/
  pytohn send_terminate.py
  # See P4Zeek_cp screen for check NN network response time.
```
```bash
  # After send_terminate.py, P4Zeek_cp will wirte the "output.txt" file, which repersents the flow is malware or not.
  cd ~/p4ips/P4Zeek_CP/build
  cat output.txt
```
---

## Server replay packet(sending pacekt from server!)
```bash
  cd ~/p4ips
  sudo tcpreplay -i ens11f1 -p 1000 -L 5000 15000_mac.pcap
```
