# appkettleapi
Python implementation of an API for appkettle

See the code in [protocol_parser.py](protocol_parser.py) for a description of the packets the kettle uses to communicate. This code implements ON, OFF, KEEPWARM and returns the state of the kettle (temperature, volume).

Uses python's paho.mqtt to interact with the kettle via MQTT.

See also: https://github.com/filcole/AppKettle for details on the cloud API. This code does not use the cloud API but instead communicates with the kettle on the local network only (suggest to disable kettle access to the internet via a firewall)

## Notes
* Multiple network interfaces: this program uses an UDP broadcast packet to prompt a reply from the kettle and discover its IP address and IMEI. This packet is broadcast on 255.255.255.255. By default the Linux kernel only sends it to one interface. So if run on a machine with multiple interfaces, it may be broadcast on the wrong interface and never get to the kettle. The quickest way to fix this is to edit the broadcast address from 255.255.255.255 to something like 192.168.2.255 so it is routed to the right interface.

## This is just a fork of [tinaught/appkettleapi](https://github.com/tinaught/appkettleapi) with only slight enhancements all the hard work is his.

The Python script now runs in a docker container and will attempt to detect the kettle on your network and auto configure the script.

Here are some environmental variables and their defaults:

```yaml
MQTT_USERNAME: ''
MQTT_PASSWORD: ''
MQTT_BROKER: '127.0.0.1'
MQTT_PORT: '1883'
KETTLE_BROADCAST_ADDRESS: '255.255.255.255'
KETTLE_IP: 'None'
KETTLE_IMEI: 'None'
```

Update the variables in the example docker-compose file to match your environment.
If 'KETTLE_IP' is set to 'None', then auto detection will be attempted and the kettle IP and IMEI retrieved.