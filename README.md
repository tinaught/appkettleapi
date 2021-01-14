# appkettleapi
Python implementation of an API for appkettle

See the code in [protocol_parser.py](protocol_parser.py) for a description of the packets the kettle uses to communicate. This code implements ON, OFF, KEEPWARM and returns the state of the kettle (temperature, volume).

Uses python's paho.mqtt to interact with the kettle via MQTT.

See also: https://github.com/filcole/AppKettle for details on the cloud API. This code does not use the cloud API but instead communicates with the kettle on the local network only (suggest to disable kettle access to the internet via a firewall)

## Notes
* Multiple network interfaces: this program uses an UDP broadcast packet to prompt a reply from the kettle and discover its IP address and IMEI. This packet is broadcast on 255.255.255.255. By default the Linux kernel only sends it to one interface. So if run on a machine with multiple interfaces, it may be broadcast on the wrong interface and never get to the kettle. The quickest way to fix this is to edit the broadcast address from 255.255.255.255 to something like 192.168.2.255 so it is routed to the right interface.
