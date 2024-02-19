#!/usr/bin/env python3
"""
SIM Modem Script ... Runs on our measurement nodes in controlled environment on Raspberry Pi
"""


import hashlib
import serial, ssl, socket, struct
import time
import base64
from datetime import datetime
import logging
from io import TextIOWrapper
from mobileatlas.probe.probe_args import ProbeParser
from moatt_types.connect import Token

from smartcard.util import toHexString

from functools import reduce
from itertools import zip_longest
from datetime import date
import signal


logger = logging.getLogger(__name__)

SOCKET_RECV_LENGTH = 4096  # 2**12
DELAY_RELAY_SECONDS = 1.2

LOOP = True

def signal_handler(sig, frame):
    global LOOP
    LOOP = False

def wait_for_pico() -> serial.Serial:
    while LOOP:
        try:
            s: serial.Serial = serial.Serial(
                port="/dev/ttyACM0",
                parity=serial.PARITY_EVEN,
                stopbits=serial.STOPBITS_ONE,
                timeout=1.1,
            )
            return s
        except Exception as e:
            logging.warning(e)
            time.sleep(1)


def relay_with_pico(imsi, connection: ssl.SSLSocket, delay_relay=False):
    # TODO Consider outer while loop
    connection.send(struct.pack("!Q", imsi))
    _atr = None
    while _atr is None or len(_atr) == 0:
        _atr = connection.recv(33)  # ATR max length
    atr = _atr
    s = wait_for_pico()
    logging.info("pico connected")
    pico_measurements = []
    probe_measurements = []

    OP_APDU = 0x00
    OP_RESET = 0x01
    OP_DEBUGMSG = 0x02
    OP_SENDATR = 0x03
    OP_MEASUREMENT = 0x04
    OP_REQUEST_STATE = 0x05

    buf = struct.pack("=BI", OP_REQUEST_STATE, 0)
    s.write(buf)

    while LOOP:
        header = s.read(5)
        if len(header) == 0:
            continue
        opcode = header[0]
        length, = struct.unpack("I", header[1:])
        data = s.read(length)
        if opcode == OP_APDU:
            start_probe = time.perf_counter_ns()
            connection.send(data)
            resp = connection.recv(65535)
            end_probe = time.perf_counter_ns()

            buf = struct.pack("=BI", OP_APDU, len(resp))
            logging.info(f"Forwarding header {buf} (len {len(resp)})")
            s.write(buf)
            s.write(resp)
            probe_measurements.append(
                (
                    (end_probe - start_probe) // 1000,
                    toHexString(list(data)),
                    toHexString(list(resp)),
                )
            )
            logging.info(f"Forwarding response {len(resp)} {toHexString(list(resp))}")
        elif opcode == OP_RESET:
            pass
        elif opcode == OP_DEBUGMSG:
            msg = data#.decode('ascii')
            logging.info(f"Debug: {msg}")
        elif opcode == OP_SENDATR: #or (opcode == OP_REQUEST_STATE and data == b'1'):
            buf = struct.pack("=BI", OP_SENDATR, len(atr))
            s.write(buf)
            s.write(atr)
        elif opcode == OP_REQUEST_STATE:
            if data == b'\x00':
                buf = struct.pack("=BI", OP_SENDATR, len(atr))
                s.write(buf)
                s.write(atr)
        elif opcode == OP_MEASUREMENT:
            msg = data.decode('ascii')
            splits = msg.split(',')
            pico_measurements.append(list(map(int, splits)))

    return pico_measurements, probe_measurements

def format_measurement(x):
    probe, pico = x
    if len(pico) == 0:
        return ",".join(
            [
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                probe[0],  # time diff probe
                '-1',  # time diff pico E2E
                '-1',  # time diff pico read command to send command to proxy
                '-1',  # time diff pico read command to receive response
                probe[1],
                probe[2],
            ]
        )
    return ",".join(
        [
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            probe[0],  # time diff probe
            str(pico[0]),  # time diff pico E2E
            str(pico[1]),  # time diff pico read command to send command to proxy
            str(pico[2]),  # time diff pico read command to receive response
            probe[1],
            probe[2],
        ]
    )


def main():
    """
    Main script on measurement node
         1) Connect to Serial Modem and GPIO with ModemTunnel
         2) Setup Linux Network Namespace + ModemManager + NetworkManager with Magic
         3) Execute Test Script with TestWrapper
    """

    # parse commandline params
    parser = ProbeParser()
    try:
        parser.parse()
    except ValueError as e:
        exit(f"{e}\nExiting...")

    # Create modem tunnel
    logger.info("setup modem tunnel...")

    tls_ctx = ssl.create_default_context(
        cafile=parser.get_cafile(), capath=parser.get_capath()
    )
    tls_ctx.check_hostname = False
    tls_ctx.verify_mode = ssl.CERT_NONE
    logger.info(f"tls context {tls_ctx.verify_mode}")

    if parser.get_use_reader():
        canonical_name = parser.get_reader_name()[:-5]
        imsi = abs(int(hashlib.md5(canonical_name.encode()).hexdigest(), 16)) % (2 ** 64)
    else:
        imsi = parser.get_imsi()

    logger.info(f"requesting {imsi}")
    socket_connection = tls_ctx.wrap_socket(
        socket.create_connection((parser.get_host(), parser.get_port())),
        server_hostname=parser.get_tls_server_name(),
    )

    while LOOP:
        pico_measurements, probe_measurements = relay_with_pico(
            imsi, socket_connection, delay_relay=False
        )
        measurements = reduce(
            lambda x, y: x + "\n" + y,
            map(
                format_measurement,
                zip_longest(
                    (
                        (str(a), '"' + str(b) + '"', '"' + str(c) + '"')
                        for (a, b, c) in probe_measurements
                    ),
                    pico_measurements,
                    fillvalue="",
                ),
            ),
            "",
        )

        logging.info("writing measurements...")

        with open("measurements.csv", mode="a", encoding="utf-8") as measurement_file:
            measurement_file.write(measurements + "\n")

    exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
