#! /usr/bin/python3
"""Formats a message received from the kettle or sent to the kettle.

Communication over TCP port 6002
Messages are JSON strings
Occasionally app sends a KeepConnect message which is acknowledged
Messages are AES encrypted with the keys in the code, but kettle is happy to reply to
    messages sent in clear which makes debugging easier

Kettle sends a heartbeat message with the status (see below, "STATUS") every second or so
App sends commands -> Kettle acknowledges commnand. Commands are variable length. If the
command is not recongised, the kettle tends to send back the exact command received

Protocol packet description (messages contained in data2 and data3):
    Bytes:
    0x00    : head   : 0xAA or 0xaa [Note: use of AA vs aa unclear (app: AA/ kettle aa mostly)]
    0x01-02 : len    : 0xXX XX = Number of bytes (00 = 1 byte) following in the packet
    x03     : b03    : 0x00 (sometimes in status messages this is 03) [00 vs 03 unclear]
    0x04-07 : pad    : 0x00000000 - padding
    0x08    : pad    : 0x00 - padding
    0x09-0A : b090A  : 0x0000 or 0x03B7 [0 vs 3B7 unclear]
    0x0B    : seq    : 0x00 or a frame sequence byte. Counts up each hearthbeat or message
    0x0C    : cmd    : Command byte, see list below
    0x0D-0E : pad3   : 0x0000 - padding
    0x0F    : ack    : See note on ack
    0x10-.. : frame  : Frame content. First byte is 0x00 for most messages but not all
    0xXX    : chksum : Checksum = (0xFF - (sum(msg[1:-1]) % 256))

Note on ack byte:
    In short app messages this byte is not there, and the cmd byte is followed by the checksum
    Otherwise, the app tends send 0x00 (but occasionally other values, meaning unclear)
    The Kettle sends:
        0xc8=success
        0x00=error. For example will reply with 0x00 if trying to turn on an empty kettle
        If the kettle can't parse a message, it tends to send back the same message again

Note on byte with val 0x55:
    Occasionally the seq byte or the checksum byte are replaced by 0xaa55, adding 1 byte to the
    message length in addition to the length set out in byte 0x01. Checksum checks. Meaning unclear
    For debug, sending "AA001200000000000003B765390000006400000031" prompts a reply including 0x55

UDP discovery and first message:
    Kettle replies to a UDP broadcast message to 255.255.255.255 in the form:
        Probe#2020-05-05-10-47-15-2
    with a JSON string with various information, including a string "deviceStatus",
    same format as "status" message. After succesfully connecting to the TCP port 6002, the kettle
    returns a short "first" message (aa000d01...+padding) followed by the deviceStatus.

Commands (byte 0x0c in the message):
    0x36: STATUS, sync/heartbeat/status message
    0x39: ON, kettle on
    0x3A: OFF, turn kettle off
    0x41: WAKE, wake kettle (turn on display, ready to accept command)
    0x43: timer related message [not explored further]
    0x44: also a timer related message [not explored further]

0x36: STATUS (sync/heartbeat/status message)
    If sent by the app, it's used to sync with the heartbeat
    If sent by the kettle, contains the status of the kettle. This is the key info:

    0x0F    : 0xc8 for sucess
    0x10    : 0x00 - padding?
    0x11    : status : 0="Not on base", 2="Standby", 3="Ready", 4="Heating", 5="Keep Warm"
    0x12-13 : Number of seconds to "keep warm" - it counts down from 60*mins, where
              mins is set in the ON message
    0x14    : Current temperature, in Celsius (Hex, so 0x26 = 40C)
    0x15    : Target Temperature, as set in the ON message (Hex, so 0x64 = 100C)
    0x16-17 : Volume, (Hex, so 043b = 1203ml)
    0x18-19 : 0x00 - padding? Unused?

0x39: ON
    This turns on the kettle and sets the target temperature and keep warm period (in minutes)
    0x0F    : 0xc8 for sucess, 0x00 if sent by app
    0x10    : Target Temperature, (Hex, so 0x64 = 100C)
    0x11    : Minutes to Keep Warm. App allows range 00-1e (0 to 30min)
    0x12-13 : 0x00 - padding? Unused?

"""
import struct

# states: 0 = kettle not on base, 2 = on the base "standby" mode (display off, app shows "zzz")
#         3 = on base ready to go, 4 = heating on
STATES_MAP = ("Not on base", "TBD?", "Standby", "Ready", "Heating", "Keep Warm")
ONOFF_MAP = ("OFF", "OFF", "OFF", "OFF", "ON", "OFF")
ACK_OK = b"\xc8"

# Msg packing formats. Second item in the tuple is a format character from the struct module
# c or B = 1 byte, h = 2 bytes, i = 4 bytes. x= 1 byte of padding (ignored)
CMD_HEADER_STRUCT = (
    ("head", "c"),
    ("length", "h"),
    ("b03", "B"),
    ("pad", "xxxx"),
    ("pad", "x"),
    ("b090A", "h"),
    ("seq", "B"),
    ("cmd", "c"),
    ("pad", "xx"),
)

CMD_STATUS_STRUCT = (
    ("pad", "x"),
    ("status", "B"),
    ("keep_warm_secs", "h"),
    ("temperature", "B"),
    ("target_temp", "B"),
    ("volume", "h"),
    ("pad", "xx"),
)

CMD_ON_STRUCT = (
    ("target_temp", "B"),
    ("keep_warm_secs", "B"),
    ("pad", "xx"),
)

CMD_UNKNOWN_STRUCT = (("unk", "Command not yet parsed / unknown"),)

CMD_PARSER = {
    b"\x36": ("STAT", CMD_STATUS_STRUCT),
    b"\x39": ("K_ON", CMD_ON_STRUCT),
    b"\x3A": ("KOFF", None),  # this cmd has no frame
    b"\x41": ("WAKE", None),  # this cmd has no frame
    b"\x43": ("TIM1", CMD_UNKNOWN_STRUCT),  # something to do with timers
    b"\x44": ("TIM2", CMD_UNKNOWN_STRUCT),  # something to do with timers
    b"\xa4": ("INIT", None),  # this is the initial connection msg - ignored
}


def unpack_cmd_bytes(msg_bytes, parser_struct):
    """Returns a dictionary parsing the message with the relevant format"""
    parser_format = ">" + "".join(  # ">" = big endian
        [x for _, x in parser_struct]  # extract second item in each tuple
    )
    cmd_values = struct.unpack(parser_format, msg_bytes)
    cmd_keys = [key for key, fmt in parser_struct if "x" not in fmt]
    # extract first item in each tuple as long as format is not "x" (skip)
    if len(cmd_keys) == len(cmd_values):
        return dict(zip(cmd_keys, cmd_values))

    print("Error unpacking")
    return {"": ""}


def format_hex_msg_string(msg, parser_struct):
    """Helper function to print the hex message with spacing"""
    byte_slices = [struct.calcsize(x) * 2 for _, x in parser_struct]
    # calculate size of each byte slice based on the second (format character)
    # in the formatter. Multiplied *2 as each byte is two chars
    i = 0
    msg_formatted = ""
    for slice_size in byte_slices:
        # adds a space after each formatter block
        if slice_size > 0:
            msg_formatted += msg[i : i + slice_size] + " "
            i = i + slice_size
    return msg_formatted


def calc_msg_checksum(msg, append=False):
    """Calculates checksum byte of a string msg

    Args:
        msg: checksum calculated on msg
        append: True - returns msg + checksum byte
                False - returns just the checksum byte
    """
    msg_bytes = bytes.fromhex(msg)
    checksum = 0xFF - (sum(msg_bytes[1:-1]) % 256)
    if append:
        return msg + ("%0.2x" % checksum)
    else:
        return checksum


def cmd_unpack(msg, print_msg=True, print_stat_msg=True, cmd_sender="U"):
    """Formats a message received from the kettle.

       Returns a json dict with the data parsed
    """

    msg_bytes = bytes.fromhex(msg)

    cmd_header = unpack_cmd_bytes(msg_bytes[:15], CMD_HEADER_STRUCT)

    if len(msg_bytes) != (cmd_header["length"] + 3):
        # +3: 3 bytes for the heading are not included in "length" field
        print("Length does not match the received packet, ignoring msg:", msg)
        return {"": ""}

    msg_checksum = calc_msg_checksum(msg)
    cmd_checksum = int.from_bytes(
        msg_bytes[-1:], byteorder="big"
    )  # last byte = checksum byte

    if cmd_checksum != msg_checksum:
        print("Bad checksum, ignoring msg:", msg)
        return {"": ""}

    cmd_name = "UNKN"
    cmd_ack = None
    cmd_frame = None

    if cmd_header["length"] >= 14:  # short commands don't have an ack byte
        cmd_ack = {"ack": msg_bytes[15:16]}

    cmd_name, cmd_frame_parser_struct = CMD_PARSER.get(cmd_header["cmd"], ("unk", ""))

    if cmd_header["length"] >= 16:  # longer commands have a cmd frame
        cmd_frame = unpack_cmd_bytes(msg_bytes[16:-1], cmd_frame_parser_struct)

    # form dictionary with all the info we parsed:
    cmd_dict = cmd_header
    if cmd_frame is not None:
        cmd_dict.update(cmd_frame)
    if cmd_ack is not None:
        cmd_dict.update(cmd_ack)

    ## amend some formatting where we know
    cmd_dict["cmd"] = cmd_name
    if "status" in cmd_dict:
        cmd_dict["status"] = STATES_MAP[cmd_frame["status"]]
        cmd_dict.update({"power": ONOFF_MAP[cmd_frame["status"]]})

    if cmd_name == "K_ON":
        cmd_dict.update({"power": "ON"})

    if cmd_name == "KOFF":
        cmd_dict.update({"power": "OFF"})

    if print_msg and (print_stat_msg or cmd_name != "STAT"):
        ## prepare the spacing for the space formatted debug print of msg ##
        msg_parser_struct = (
            CMD_HEADER_STRUCT
            + ((("cmd_ack", "c"),) if cmd_ack is not None else (("", ""),))
            + (cmd_frame_parser_struct if cmd_frame is not None else (("", ""),))
            + (("checksum", "B"),)
        )
        print(cmd_sender, "-", cmd_name, sep="", end=": ")
        print(format_hex_msg_string(msg, msg_parser_struct))

    return cmd_dict


def unpack_msg(msg, print_msg=True, print_stat_msg=True, print_keep_connect=True):
    """Decides which function should format the message

    Args:
        print_stat_msg: print the heartbeat status messages ('aa0018...'). Useful to set to False
            to filter out heartbeat status when debugging conversations betweeen app and kettle
        print_keep_connect: print the KeepConnect messages sent/received
    """
    if msg == "KeepConnect":
        if print_keep_connect:
            print("KeepConnect")
        return None

    if not isinstance(msg, dict):
        print("Unkwn binary msg:", msg)
        return None

    if "wifi_cmd" in msg:
        return cmd_unpack(msg["data3"], print_msg, print_stat_msg, "K")

    if "app_cmd" in msg:
        return cmd_unpack(msg["data2"], print_msg, print_stat_msg, "A")

    print("Unkwn dict msg:", msg)
    return None


if __name__ == "__main__":
    TEST_MSG_STRINGS = (
        "aa000d010000000000000096a40000b7000200004164011e00008c",  # initial status, ignored for now
        "aa001803000000000000009b360000c800030000505004b30000f1",  # status
        "aa00180300000000000000a7360000c800030000505004b30000e5",  # another status
        "aa000d010000000000000017a4000036000200002364035e0000e6",  # status: doesn't match length
        "aa0018030000000000000052360000c8000200002364035e0000aa55",  # status: aa55 example
        "aa00180300000000000000aa55360000c8000200002f60014f000006", #another aa55 example
        "00001803000000000003b78b360000c8000400002b64039100007a",  # another status starting 00...
        "AA001200000000000003B70c390000006402000088",  # kettle on
        "AA000D00000000000003B7283A0000d6",  # kettle off
        "aa000e0000000000000000093a0000c8e6",  # ack kettle off
        "AA000D00000000000003B76d36000095",  # sync msg
        "aa000e00000000000003b715390000c821",  # ack on
        "aa000e0000000000000000093a0000c8e6",  # ack off
    )

    for test_msg in TEST_MSG_STRINGS:
        cmd_unpack(test_msg, True)
