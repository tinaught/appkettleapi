#! /usr/bin/python3
"""Provides a running daemon for interfacing with an appKettle

usage: appkettle_mqtt.py [-h] [--mqtt host port username password] [host] [imei]

arguments:
  host              kettle host or IP
  imei              kettle imei (e.g. GD0-12300-35aa)

optional arguments:
  -h, --help        show this help message and exit
  --mqtt host port  MQTT broker host, port, username & password (e.g. --mqtt 192.168.0.1 1883 mqtt_user p@55w0Rd)

By default the both kettle and app talk via the cloud. Blocking internet access to
the kettle host triggers communication on local network

To find the IMEI and IP of the kettle run program without parameters

Pressing Ctrl+C while this program is connected enters into a simple debug interface:
see function cb_signal_handler for available commands

To log and debug traffic from Android app, install tcpdump on a rooted Android phone:
- adb shell
- android:/# tcpdump [host 192.168.0.1] -i wlan0 -s0 -U -w - | nc -k -l -p 11111
- adb forward tcp:11111 tcp:11111
- connect this script to localhost:1111. Alternatively,
    pipe traffic to wireshark (nc localhost 11111 | wireshark -k -S -i -)
"""

import sys
import time
import socket
import select
import signal
import json
import argparse
import paho.mqtt.client as mqtt     # pip install paho.mqtt
from Cryptodome.Cipher import AES   # pip install pycryptodomex

from protocol_parser import unpack_msg, calc_msg_checksum

DEBUG_MSG = True
DEBUG_PRINT_STAT_MSG = False  # print status messages
DEBUG_PRINT_KEEP_CONNECT = False  # print "keelconnect" packets
SEND_ENCRYPTED = False  # use AES encryted comms with kettle
MSGLEN = 3200  # max msg length: this needs to be long enough to allow a few msg to be received

KETTLE_SOCKET_CONNECT_ATTEMPTS = 3
KETTLE_SOCKET_TIMEOUT_SECS = 60
KEEP_WARM_MINS = 30  # Default keep warm amount

ENCRYPT_HEADER = bytes([0x23, 0x23, 0x38, 0x30])
PLAIN_HEADER = bytes([0x23, 0x23, 0x30, 0x30])
MSG_KEEP_CONNECT = b"##000bKeepConnect&&"
MSG_KEEP_CONNECT_FREQ_SECS = (
    30  # sends a KeepConnect to keep connection live (e.g. app open)
)
UDP_IP_BCAST = "255.255.255.255"
UDP_PORT = 15103

MQTT_BASE = "appKettle/"
MQTT_COMMAND_TOPIC = MQTT_BASE + "command"
MQTT_STATUS_TOPIC = MQTT_BASE + "status"

# AES secrets:
SECRET_KEY = b"ay3$&dw*ndAD!9)<"
SECRET_IV = b"7e3*WwI(@Dczxcue"


class AppKettle:
    """Represents a phisical appKettle"""

    def __init__(self, sock=None):
        self.sock = sock
        self.stat = {
            "cmd": "unk",
            "status": "unk",
            "keep_warm_secs": 0,
            "keep_warm_onoff": False,
            "temperature": 0,
            "target_temp": 0,
            "set_target_temp": 100,
            "volume": 0,
            "power": "OFF",
            "seq": 0,
        }

    def tick(self):
        """Increments seq by 1. To be called when sending something to kettle"""
        self.stat["seq"] = (self.stat["seq"] + 1) % 0xFF  # cap at 1 byte

    def turn_on(self, temp=None):
        """Turns on kettle at a given temperature (temp) and with Keep Warm enabled"""
        if self.stat["status"] != "Ready":
            self.wake()

        self.tick()

        if temp is None:
            temp = self.stat["set_target_temp"]

        msg = "AA001200000000000003B7{seq}39000000{temp}{kw}0000".format(
            temp=("%0.2X" % temp),
            kw=("%0.2X" % (KEEP_WARM_MINS * self.stat["keep_warm_onoff"])),
            seq=("%0.2x" % self.stat["seq"]),
        )

        msg = calc_msg_checksum(msg, append=True)
        return self.sock.send_enc(msg, SEND_ENCRYPTED)

    def wake(self):
        """Wake up kettle (status goes to "Ready") and display comes on"""
        self.tick()
        msg = "AA000D00000000000003B7{seq}410000".format(
            seq=("%0.2x" % self.stat["seq"])
        )
        msg = calc_msg_checksum(msg, append=True)
        return self.sock.send_enc(msg, SEND_ENCRYPTED)

    def turn_off(self):
        """Turn off the kettle"""
        self.tick()
        msg = "AA000D00000000000003B7{seq}3A0000".format(
            seq=("%0.2x" % self.stat["seq"])
        )
        msg = calc_msg_checksum(msg, append=True)
        return self.sock.send_enc(msg)

    def status_json(self):
        """Returns JSON message with the key status of the kettle"""
        status_dict = {
            key: self.stat[key]
            for key in self.stat.keys()
            & {
                "power",
                "status",
                "temperature",
                "target_temp",
                "volume",
                "keep_warm_secs",
            }
        }
        return json.dumps(status_dict)

    def update_status(self, msg):
        """Parses a wifi_cmd message to match this class status with the phisical kettle"""
        try:
            cmd_dict = unpack_msg(
                msg, DEBUG_MSG, DEBUG_PRINT_STAT_MSG, DEBUG_PRINT_KEEP_CONNECT
            )
        except ValueError:
            print("Error in decoding: ", cmd_dict)
            return

        if isinstance(msg, (str, bytes, type(None))):
            # decoding didn't return anything interesting for us
            return

        if "data3" in msg:
            try:
                self.stat.update(cmd_dict)
            except ValueError:
                print("Error in data3 cmd_dict: ", cmd_dict)
                return
        elif "data2" in msg:
            # this means it's a message we sent. Only useful for debugging tcpdump traffic
            pass
        else:
            print("Unparsed Json message: ", cmd_dict)
            # unparsed data2/3 status or a message we didn't understand


class KettleSocket:
    """ This class deals with the connection, encryption and decryption
        of messages sent by an AppKettle
    """

    def __init__(self, sock=None, imei=""):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(KETTLE_SOCKET_TIMEOUT_SECS)
        else:
            self.sock = sock

        self.connected = False
        self.imei = imei
        self.stat = ""

    def connect(self, host_port):
        """ Attempts to connect to the Kettle """
        attempts = KETTLE_SOCKET_CONNECT_ATTEMPTS
        print("Attempting to connect to socket...")
        while attempts and self.connected is False:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(KETTLE_SOCKET_TIMEOUT_SECS)
                self.sock.connect(host_port)
                self.keep_connect()
                self.connected = True
                return
            except (TimeoutError, OSError) as err:
                print("Socket error: ", err, " | ", attempts, "attempts remaining")
                self.kettle_probe()  # run kettle probe to try to wake up the kettle
                attempts -= 1
                self.connected = False

        print("Socket timeout")
        self.connected = False

    def kettle_probe(self):
        """Sends a UDP "probe" message to see what the kettle returns.
        Kettle responds with information about the kettle including the name

        Returns: json string with info about the kettle

        Example probe message: "Probe#2020-05-05-10-47-15-2"
        """

        for i in range(1, 4):
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
            rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            for _i in range(1, 4):
                # send 4 packets
                prb = time.strftime("Probe#%Y-%m-%d-%H-%M-%S", time.localtime())
                send_sock.sendto(str.encode(prb, "ascii"), (UDP_IP_BCAST, UDP_PORT))

            send_sock.close()
            print("Sent broadcast messages, waiting to hear back from kettle...", i)
            rcv_sock.bind(("", UDP_PORT))  # listen on all ports
            rcv_sock.settimeout(5)  # 5 sec timeout for this probe
            try:
                data, address = rcv_sock.recvfrom(1024)
            except socket.timeout:
                rcv_sock.close()
                continue

            data = data.decode("ascii")
            rcv_sock.close()

            msg = data.split("#")
            msg_json = json.loads(msg[6])  # item 6 has a JSON message with some info
            msg_json.update({"imei": msg[0]})
            msg_json.update({"version": msg[3]})
            msg_json.update({"kettleIP": address[0]})

            print("Discovered kettle with following parameters:")
            print("- Name:", msg_json["AP_ssid"])
            print("- IP:", msg_json["kettleIP"])
            print("- IMEI:", msg_json["imei"])
            print("- Wifi SSID:", msg_json["devRouter"])
            print("- Software version:", msg_json["version"])
            if DEBUG_MSG:
                print(
                    "- Device Status:", msg_json["deviceStatus"]
                )  # same format as status msg

            self.stat = msg_json
            return msg_json

    def keep_connect(self):
        """ Sends a ping message to keep connection going """
        if DEBUG_PRINT_KEEP_CONNECT:
            print("A: KeepConnect")

        try:
            self.sock.sendall(MSG_KEEP_CONNECT)
        except OSError as err:
            print("Socket error (keep connect):", err)
            self.connected = False
            return

    def close(self):
        """ Tidy up function to close scoket """
        print("Closing socket...")
        self.sock.close()

    def send(self, msg):
        """ Send a message to the kettle using socket.sendall() """
        try:
            sent = self.sock.sendall(msg)
        except OSError as err:
            print("Socket error (send):", err)
            self.connected = False
            return
        if sent is not None:
            self.connected = False
            raise RuntimeError("Socket connection broken")

    def receive(self):
        """ Called back from main event loop, receives a message and then parses it

        Messages are received until '&&' (message terminator), and then parsed
        """
        chunks = []
        bytes_recd = 0
        chunk = b""
        while (
            bytes_recd < MSGLEN
            and chunks[-2:] != [b"&", b"&"]
            and self.connected is True
        ):
            try:
                chunk = self.sock.recv(1)
                chunks.append(chunk)
                bytes_recd = bytes_recd + len(chunk)
            except socket.error:
                print("Socket connection broken?",)
                self.connected = False
                return None
            if chunk == b"":
                print("Socket connection broken / no data")
                self.connected = False
                return None

        # this is necessary so it works also when streaming tcpdump traffic,
        # it filters out anything before b"##" (e.g. TCP packet headers)
        frame = b"".join(chunks).partition(b"##")
        frame = frame[1] + frame[2]

        if frame[:4] == ENCRYPT_HEADER:
            res = self.decrypt(frame[6:-2])
        elif frame[:4] == PLAIN_HEADER:
            res = frame[6:-2]
        else:
            res = frame
            if len(frame) > 0:
                print("Response not recognised", frame)

        try:
            res = res.decode("ascii")
            return to_json(res.rstrip("\x00"))
        except UnicodeDecodeError:
            return None

    @staticmethod
    def decrypt(ciphertext):
        """ AES decryption of text received in ciphertext

        Text lenght needs to be a multiple of 16 bytes
        """
        try:
            cipher_spec = AES.new(SECRET_KEY, AES.MODE_CBC, SECRET_IV)
            return cipher_spec.decrypt(ciphertext)
        except ValueError:
            print("Not 16-byte boundary data")
            return ciphertext
        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise

    # pads with 0x00 as this is what the kettle wants rather than some other padding algorithm
    @staticmethod
    def pad(data_to_pad, block):
        """ Pads data with 0x00 to match block size """
        extra = len(data_to_pad) % block
        if extra > 0:
            return data_to_pad + (b"\x00" * (block - extra))
        return data_to_pad

    def encrypt(self, plaintext):
        """ AES encryption of plaintext """
        try:
            cipher_spec = AES.new(SECRET_KEY, AES.MODE_CBC, SECRET_IV)
            return cipher_spec.encrypt(self.pad(plaintext, AES.block_size))
        except ValueError:
            print("Not 16-byte boundary data: ", plaintext)
            return plaintext
        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise

    def send_enc(self, data2, encrypt=False):
        """ Sends a data2 command encoded with header and termination characters
            Can send Encrypted but can also send plain
            Note: commands in clear also work
        """
        msg = '{{"app_cmd":"62","imei":"{imei}","SubDev":"","data2":"{data2}"}}'.format(
            imei=self.imei, data2=data2
        )
        if encrypt:
            content = self.encrypt(msg.encode())
            header = ENCRYPT_HEADER
        else:
            content = msg.encode()
            header = PLAIN_HEADER
        encoded_msg = header + bytes("%0.2X" % len(content), "utf-8") + content + b"&&"
        self.send(encoded_msg)
        if DEBUG_MSG:
            unpack_msg(to_json(msg))


def cb_mqtt_on_connect(client, kettle, flags, rec_code):
    """ The callback for when the client receives a CONNACK response from the server. """
    print("Connected to MQTT broker with result code " + str(rec_code))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe(MQTT_COMMAND_TOPIC + "/#")  # subscribe to all topics
    

def cb_mqtt_on_message(mqttc, kettle, msg):
    """ The callback for when a PUBLISH message is received from the server. """
    print("MQTT MSG: " + msg.topic + " : " + str(msg.payload))
    kettle.wake()  # wake up kettle when receiving a command

    if msg.topic == MQTT_COMMAND_TOPIC + "/power":
        if msg.payload == b"ON":
            kettle.turn_on()
        elif msg.payload == b"OFF":
            kettle.turn_off()
        else:
            print("MQTT MSG: msg not recognised:", msg)
        mqttc.publish(MQTT_STATUS_TOPIC + "/power", kettle.stat["power"])

    elif msg.topic == MQTT_COMMAND_TOPIC + "/keep_warm_onoff":
        if msg.payload == b"True":
            kettle.stat["keep_warm_onoff"] = True
        elif msg.payload == b"False":
            kettle.stat["keep_warm_onoff"] = False
        else:
            print("MQTT MSG: msg not recognised:", msg)
        mqttc.publish(
            MQTT_STATUS_TOPIC + "/keep_warm_onoff", kettle.stat["keep_warm_onoff"]
        )

    elif msg.topic == MQTT_COMMAND_TOPIC + "/set_target_temp":
        kettle.stat["set_target_temp"] = int(msg.payload)
        mqttc.publish(
            MQTT_STATUS_TOPIC + "/set_target_temp", kettle.stat["set_target_temp"]
        )


def to_json(myjson):
    """ Helper function: if it is Json returns Json otherwise returns original string """
    try:
        json_object = json.loads(myjson)
    except (ValueError, TypeError):
        return myjson
    return json_object


def main_loop(host_port, imei, mqtt_broker):
    """ Main event loop called from __main__

    Args:
        host_port: tuple with the kettle host and port
        imei: kettle IMEI
        mqtt_broker: array with mqtt broker ip, port, username & password
    """

    kettle_socket = KettleSocket(imei=imei)
    kettle = AppKettle(kettle_socket)
    kettle_info = kettle_socket.kettle_probe()
    if kettle_info is not None:
        kettle.stat.update(kettle_info)

    if not mqtt_broker is None:
        mqttc = mqtt.Client()
        if not mqtt_broker[2] is None:
            mqttc.username_pw_set(mqtt_broker[2], password=mqtt_broker[3])
        mqttc.on_connect = cb_mqtt_on_connect
        mqttc.on_message = cb_mqtt_on_message
        mqttc.user_data_set(kettle)  # passes to each callback $kettle as $userdata
        mqttc.will_set(MQTT_STATUS_TOPIC + "/status", "Disconnected", retain=True)
        mqttc.connect(mqtt_broker[0], int(mqtt_broker[1]))
        mqttc.loop_start()

    def cb_signal_handler(sig, frame):
        """Handles Ctrl+C signal. Useful for debugging and testing the protocol"""
        user_input = input("prompt|>> ")
        if user_input == "q":
            kettle.sock.close()
            sys.exit(0)
            return

        if user_input == "":
            return

        params = user_input.split()

        if user_input[:2] == "on":
            if len(params) == 1:
                kettle.turn_on()
            elif len(params) == 2:
                kettle.turn_on(int(params[1]))
        elif user_input == "off":
            kettle.turn_off()
        elif user_input == "wake":
            kettle.wake()
        elif user_input == "s":
            print("s: ", kettle.status_json())
        elif user_input == "ss":
            print("ss: ", kettle.stat)
        elif user_input[:3] == "k":
            kettle_socket.keep_connect()
        elif user_input[:3] == "sl:":
            # send literal - for debug (this is the entire ##0080{...}&& msg)
            kettle.sock.send(bytes(user_input[3:].encode()))
        elif user_input[:3] == "sm:":
            # send message - for debug (this is the data2 string)
            kettle.sock.send_enc(user_input[3:], SEND_ENCRYPTED)
        else:
            print("Input not recognised:", user_input)

    signal.signal(signal.SIGINT, cb_signal_handler)
    timestamp = time.time()

    if host_port[0] is None:
        kettle.sock.close()
        print("Run again with all parameters - exiting")
        sys.exit(0)
        return

    while True:
        if not kettle_socket.connected:
            kettle_socket.connect(host_port)
            print("Connected succesfully to socket on host", host_port[0])

        inout = [kettle_socket.sock]
        infds, outfds, errfds = select.select(inout, inout, [], 120)

        if len(infds) != 0:
            k_msg = kettle_socket.receive()
            kettle.update_status(k_msg)
            if not mqtt_broker is None:
                mqttc.publish(MQTT_STATUS_TOPIC + "/STATE", kettle.status_json())
                for i in [
                    "temperature",
                    "target_temp",
                    "set_target_temp",
                    "status",
                    "power",
                    "version",
                    "keep_warm_secs",
                    "keep_warm_onoff",
                ]:
                    mqttc.publish(MQTT_STATUS_TOPIC + "/" + i, kettle.stat[i])

        if len(outfds) != 0:
            # print("we could be writing here")
            pass
        if len(errfds) != 0:
            # print("we could be handling socket errors here")
            pass

        if time.time() - timestamp > MSG_KEEP_CONNECT_FREQ_SECS:
            kettle_socket.keep_connect()
            timestamp = time.time()

        time.sleep(0.2)  # build-in a little sleep
        # print("".join("%02x " % i for i in response))


def argparser():
    """Parses input arguments, see -h"""
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", help="kettle host or IP")
    parser.add_argument("imei", nargs="?", help="kettle IMEI (e.g. GD0-12300-35aa)")
    parser.add_argument(
        "--port", help="kettle port (default 6002)", default=6002, type=int
    )

    parser.add_argument(
        "--mqtt",
        help="MQTT broker host, port, username & password (e.g. --mqtt 192.168.0.1 1883 mqtt_user p@55w0Rd)",
        nargs=4,
        metavar=("host", "port", "username", "password"),
    )

    args = parser.parse_args()
    main_loop((args.host, args.port), args.imei, args.mqtt)


if __name__ == "__main__":
    argparser()
