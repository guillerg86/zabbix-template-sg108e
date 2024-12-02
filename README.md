## Template TP-Link SG105E / SG108E

This template allows to monitor TP-Link SG105E / SG108E switch. This switch is a home switch, so doesn't have SNMP or SSH, just a website.

Check images folder for examples

### Requeriments

requests (use pip install request)

### Items

- Hostname
- Firmware
- Hardware
- Mac Address

### Triggers

- Hostname changed
- Firmware changed
- Hardware changed
- MAC address changed

### Discovery rules

There's a discovery rule for detect network ports. When executed, it returns a json with port number and adminstatus

```
{
    "interfaces": [
        {
			"{#JSON.INDEX}": 0,
			"{#IFNUMBER}": 1,
			"{#IFADMINSTATUS}": "1"
        },
        {
			"{#JSON.INDEX}": 1,
			"{#IFNUMBER}": 2,
			"{#IFADMINSTATUS}": "0"
        },
        {
			"{#JSON.INDEX}": 2,
			"{#IFNUMBER}": 3,
			"{#IFADMINSTATUS}": "0"
        },
        {
			"{#JSON.INDEX}": 3,
			"{#IFNUMBER}": 4,
			"{#IFADMINSTATUS}": "0"
        },
        {
			"{#JSON.INDEX}": 4,
			"{#IFNUMBER}": 5,
			"{#IFADMINSTATUS}": "1"
        },
        {
			"{#JSON.INDEX}": 5,
			"{#IFNUMBER}": 6,
			"{#IFADMINSTATUS}": "1"
        },
        {
			"{#JSON.INDEX}": 6,
			"{#IFNUMBER}": 7,
			"{#IFADMINSTATUS}": "1"
        },
        {
			"{#JSON.INDEX}": 7,
			"{#IFNUMBER}": 8,
			"{#IFADMINSTATUS}": "1"
        }
    ]
}
```

Only creates Item prototypes when {#IFADMINSTATUS} = 1 (enabled)

#### Item prototypes 

- Admin status
- Operational status
- Flow control actual
- Flow control configuration
- Received packets
- Received packets error
- Transmitted packets
- Transmitted packets error
- Trunk status
- Speed configuration
- Speed actual
- Speed (bps)

#### Trigger prototypes

- Interface: Link down
- Interface: Link speed is lower than before
- Interface: Flow control changed
- Interface: Speed configuration changed

## Tested on

- TP-Link SG108E v6.0 
  - Firmware: 20230218 ✔
  - Firmware: 20201208 ✔
- TP-Link SG108E v5.0 
  - Firmware: 20191021 ✔ (thanks to <a href="https://github.com/jeffersonraimon" target="_blank">@jeffersonraimon</a>)
- TP-Link SG105E / TL-SG108E v4.0
  - Firmware: 20181120 ✔ (thanks to <a href="https://github.com/jeffersonraimon" target="_blank">@jeffersonraimon</a>)
  - Firmware: 20180720 (with -hv 4 parameter) ✔ (thanks to <a href="https://github.com/jeffersonraimon" target="_blank">@jeffersonraimon</a>)
- TP-Link SG108E v3.0
  - Firmware: 20171214 (with -hv 3 parameter) ✔ (thanks to <a href="https://github.com/jeffersonraimon" target="_blank">@jeffersonraimon</a>)
  
  
## Parameters

|SHORT PARAM|LONG PARAM|REQUIRED|VALUES|DEFAULT VALUE|DESCRIPTION|
|-|-|-|-|-|-|
|-i|--ip-address|Yes|||IP address of the switch (ex: 192.168.0.1)|
|-u|--username|Yes|||Username for web login|
|-p|--password|Yes|||Password for web login|
|-a|--action|Yes|`allinfo`<br>`sysinfo`<br>`discovery`<br>`portinfo` -> requires port-number param||Script will get some info depending of action selected|
|-hv|--hardware-version|No|`3`<br>`4`<br>`5`<br>`6`|`6`|Support for some changes on TPLink Hardware Versions|
||--port-number|Only with<br>action `portinfo`|Number of port (1-maxport)|-1|Return info only of the specified port|
  

## Test script before install on Zabbix

If you want to test before install on Zabbix, you need a machine with Python 3.x installed (tested on 3.12).

**Get System Info**

```
python3 tplinkswitch2zabbix.py -i IP_ADDRESS -u WEBUSERNAME -p WEBPASSWORD -a sysinfo
```

Output be like:

```
{
    "firmware": "1.0.0 Build 20230218 Rel.50633",
    "hardware": "TL-SG108E 6.0",
    "description": "PSC-SW-SG108E",
    "mac_address": "00:31:92:B3:EE:12",
    "ip_address": "10.15.1.2",
    "netmask": "255.255.255.0",
    "gateway": "10.15.1.1",
    "port_number": 0,
    "ports": []
}
```

This method only takes system information, no ports information.

**Discovery ports**

```
python3 tplinkswitch2zabbix.py -i IP_ADDRESS -u WEBUSERNAME -p WEBPASSWORD -a discovery
```

Output be like:

```
{
    "interfaces": [
        {
            "{#JSON.INDEX}": 0,
            "{#IFNUMBER}": 1,
            "{#IFADMINSTATUS}": "1"
        },
        {
            "{#JSON.INDEX}": 1,
            "{#IFNUMBER}": 2,
            "{#IFADMINSTATUS}": "1"
        },
		....
		....
        {
            "{#JSON.INDEX}": 7,
            "{#IFNUMBER}": 8,
            "{#IFADMINSTATUS}": "1"
        }
    ]
}
```

**Port detail**

```
python3 tplinkswitch2zabbix.py -i IP_ADDRESS -u WEBUSERNAME -p WEBPASSWORD -a portinfo --port-number 8
```

Output be like

```
{
    "port_number": 8,
    "admin_status": "1",
    "trunk_status": "0",
    "operation_status": 1,
    "speed_config": "1",
    "speed_actual": "6",
    "speed_bps": 1000000000,
    "flowcontrol_config": "0",
    "flowcontrol_actual": "0",
    "transmitted_packets": "324937",
    "transmitted_packets_error": "0",
    "received_packets": "615998",
    "received_packets_error": "708"
}
```

**All Info**

```
python3 tplinkswitch2zabbix.py -i IP_ADDRESS -u WEBUSERNAME -p WEBPASSWORD -a allinfo
```

Output be like 

```
{
    "firmware": "1.0.0 Build 20230218 Rel.50633",
    "hardware": "TL-SG108E 6.0",
    "description": "PSC-SW-SG108E",
    "mac_address": "00:31:92:B3:EE:12",
    "ip_address": "10.15.1.2",
    "netmask": "255.255.255.0",
    "gateway": "10.15.1.1",
    "port_number": 8,
    "ports": [
        {
            "port_number": 1,
            "admin_status": "1",
            "trunk_status": "0",
            "operation_status": 0,
            "speed_config": "1",
            "speed_actual": "0",
            "speed_bps": 0,
            "flowcontrol_config": "0",
            "flowcontrol_actual": "0",
            "transmitted_packets": "0",
            "transmitted_packets_error": "0",
            "received_packets": "0",
            "received_packets_error": "0"
        },
		....
		....
        {
            "port_number": 8,
            "admin_status": "1",
            "trunk_status": "0",
            "operation_status": 1,
            "speed_config": "1",
            "speed_actual": "6",
            "speed_bps": 1000000000,
            "flowcontrol_config": "0",
            "flowcontrol_actual": "0",
            "transmitted_packets": "346961",
            "transmitted_packets_error": "0",
            "received_packets": "540128",
            "received_packets_error": "504"
        }
    ]
}
```

## Installation

You can monitor this switch using agent or server/proxy (external script). 

### Macros

|MACRO|DESCRIPTION|
|-|-|
|{$SW.IP}|IP ADDRESS of the Switch|
|{$SW.USER}|Switch Webadmin user|
|{$SW.PASS}|Switch Webadmin password|
|{$SW.HARDVERSION}|Switch hardware version (default 6)|

### By Zabbix agent

- Import template `Template TP-Link SG108E Webparsing by Zabbix Agent.yaml` to your zabbix server.
- Create a folder inside zabbix-agent folder.

```
mkdir /etc/zabbix/scripts
```

- Download script `tplinkswitch2zabbix.py` and copy to scripts folder

```
cp tplinkswitch2zabbix.py /etc/zabbix/scripts/
chmod +x /etc/zabbix/scripts/tplinkswitch2zabbix.py
```
- Download `tplinkswitch.conf` and copy to `/etc/zabbix/zabbix_agentd.d/` or `/etc/zabbix/zabbix_agent2.d/`.
- Reboot agent with

```
systemctl restart zabbix_agentd.service
```
or

```
systemctl restart zabbix_agent2.service
```

- Create a host on Zabbix with agent and asigng the Template `Template TP-Link SG108E Webparsing by Zabbix Agent.yaml`
- Inside host set macros values
- If host is monitored by proxy (wait, resync or restart proxy)
- Test and confirm


### By Zabbix Server / Proxy (external script)

External scripts are scripts executed by zabbix server or proxy (not by agent), so no need to copy UserParameters config. 

- Import template `Template TP-LINK SG108E WebParsing by Zabbix Server or Proxy.yaml` to your zabbix server.
- Check the path of ExternalScripts on your Zabbix Server or Zabbix Proxy config (default is on `/usr/lib/zabbix/externalscripts`)

For server

```
cat /etc/zabbix/zabbix_server.conf | grep ExternalScripts
```

For proxy

```
cat /etc/zabbix/zabbix_proxy.conf | grep ExternalScripts
```

- Download python script and copy to ExternalScripts path

```
cp tplinkswitch2zabbix.py /usr/lib/zabbix/externalscripts/
chmod +x /usr/lib/zabbix/externalscripts/tplinkswitch2zabbix.py
```

- Create a host, add template `Template TP-LINK SG108E WebParsing by Zabbix Server or Proxy`
- Inside host set macros values
- If host is monitored by proxy (wait, resync or restart proxy)
- Test and confirm


## "Problems detected"

This switch only allows some concurrent sessions on web management, so when this script connects to retrieve data this will force a logout on your web session if you are connected. You can do one of both things.

- Install TP-Link Easy Smart Configuration Utility (you can manage switch without getting disconnected)
- Stop monitoring this switch while you are configuring the switch via web.

### HTTP 401 after login

- Hardware versions 4 and older return HTTP 401 on sucessful login process. 
- Hardware versions 4 with firmware 20181120 and newer return HTTP 200 on sucessful login process.


## Greetings

- <a href="https://github.com/jeffersonraimon" target="_blank">@jeffersonraimon</a>: tested on SG108E v3, SG105E/SG108E v4, SG108E v5

