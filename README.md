# appkettleapi
Python implementation of an API for appkettle

See the code in [protocol_parser.py](protocol_parser.py) for a description of the packets the kettle uses to communicate. This code implements ON, OFF, KEEPWARM and returns the state of the kettle (temperature, volume).

Uses python's paho.mqtt to interact with the kettle via MQTT.

See also: https://github.com/filcole/AppKettle for details on the cloud API. This code does not use the cloud API but instead communicates with the kettle on the local network only (suggest to disable kettle access to the internet via a firewall)

## Notes
* Multiple network interfaces: this program uses an UDP broadcast packet to prompt a reply from the kettle and discover its IP address and IMEI. This packet is broadcast on 255.255.255.255. By default the Linux kernel only sends it to one interface. So if run on a machine with multiple interfaces, it may be broadcast on the wrong interface and never get to the kettle. The quickest way to fix this is to edit the broadcast address from 255.255.255.255 to something like 192.168.2.255 so it is routed to the right interface.

## This is only a slight enhancements to enable the sript to run in a Docker container.

### Features

Attempt to detect the kettle on your network and auto configure before connecting.
Flexible environmental variables
Runs under s6 overlay
Compatiable with Docker and Kubernetes

### Environmental variables and their default values:

```yaml
MQTT_USERNAME: ''
MQTT_PASSWORD: ''
MQTT_BROKER: '127.0.0.1'
MQTT_PORT: '1883'
KETTLE_IP: 'None'
KETTLE_IMEI: 'None'
KETTLE_UDP_IP_BCAST: '255.255.255.255'
KETTLE_KEEP_WARM_MINS: '30'
```

Update the variables in the example docker-compose file to match your environment.
If 'KETTLE_IP' is set to 'None', then auto detection will be attempted and the kettle's IP and IMEI retrieved.

### Docker Compose

```yaml
docker-compose up -d -f ./docker-compose.yaml
```

### Kubernetes Deployment

```yaml
kubectl apply -f ./kubernetes-deployment.yaml
```

