# appkettleapi
Python implementation of an API for appkettle

See the code in [protocol_parser.py](protocol_parser.py) for a description of the packets the kettle uses to communicate. This code implements ON, OFF, KEEPWARM and returns the state of the kettle (temperature, volume). 

Uses python's paho.mqtt to interact with the kettle via MQTT.

See also: https://github.com/filcole/AppKettle for details on the cloud API. This code does not use the cloud API but instead communicates with the kettle on the local network only (suggest to disable kettle access to the internet via a firewall)
