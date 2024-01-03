#!/usr/bin/env python3
"""
SIM Modem Script ... Runs on our measurement nodes in controlled environment on Raspberry Pi
"""

# venv hack (to make it work with sudo):
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
activate_this = os.path.join(base_dir, "mobileatlas/probe/venv/bin/activate_this.py")
exec(open(activate_this).read(), {"__file__": activate_this})

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


logger = logging.getLogger(__name__)

SOCKET_RECV_LENGTH = 4096  # 2**12
DELAY_RELAY_SECONDS = 1.2


def wait_for_pico() -> serial.Serial:
    while True:
        try:
            s: serial.Serial = serial.Serial(
                port="/dev/ttyACM0",
                parity=serial.PARITY_EVEN,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.01,
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
    atr = bytearray(b"\x20")
    atr += bytearray(len(_atr).to_bytes(2, "big"))

    logging.info("ATR, %i: %s", len(atr), _atr)
    atr += bytearray(
        reduce(lambda x, y: x + y, map(lambda y: y.to_bytes(1, "big"), _atr))
    )

    s = wait_for_pico()
    logging.info("pico -> atr")
    while True:
        msg = s.read_until("\n")
        if len(msg) == 0:
            s.write(b"\x10\x00\x00")
            time.sleep(1)
        elif b"Waiting for " in msg:
            break
        else:
            logging.info(msg)

    s.write(atr)
    s.flush()
    logging.info("atr exchanged")
    pico_measurements = []
    probe_measurements = []

    while True:
        header: bytes = s.read(2)
        if len(header) == 0:
            continue
        if header[0] == 16:  # b'\x10':
            length: int = int.from_bytes(header[1:3], byteorder="big", signed=True)
            body = s.read(length)
            if len(body) < 5:
                continue
            start_probe = time.perf_counter_ns()

            connection.send(body)
            response = connection.recv(SOCKET_RECV_LENGTH)
            comm = bytearray(b"\x10")
            comm += bytearray(len(response).to_bytes(2, "big"))

            if delay_relay:
                logging.debug("sleep %fs", DELAY_RELAY_SECONDS)
                time.sleep(DELAY_RELAY_SECONDS)
            s.write(comm + bytearray(response))
            s.flush()
            end_probe = time.perf_counter_ns()
            logging.info("command %s | response %s", toHexString(list(body)), toHexString(list(response)))
            probe_measurements.append(
                (
                    end_probe - start_probe,
                    toHexString(list(body)),
                    toHexString(list(response)),
                )
            )
        else:
            body = s.read_until(b"\n")
            try:
                line = (header + body).decode()
                if "Waiting for " in line:
                    continue
                logging.info(line)
                if line.startswith("done"):
                    logging.info("stop relaying: %s", line)
                    return pico_measurements, probe_measurements
                if line.startswith("diff "):
                    splits = line.split("=", maxsplit=1)
                    logging.info(splits[1])
                    ms = splits[1].split(",")
                    logging.info(ms)
                    pico_measurements.append(list(map(lambda x: int(x), ms)))
            except UnicodeDecodeError:
                print((header + body))


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

    if not parser.get_direct_tunnel():
        try:
            api_token = Token(base64.b64decode(os.environ["API_TOKEN"]))
        except:
            exit("API_TOKEN environment variable is unset.\nExiting...")

    # Create modem tunnel
    logger.info("setup modem tunnel...")

    tls_ctx = ssl.create_default_context(
        cafile=parser.get_cafile(), capath=parser.get_capath()
    )
    tls_ctx.check_hostname = False
    tls_ctx.verify_mode = ssl.CERT_NONE
    logger.info(f"tls context {tls_ctx.verify_mode}")

    reader_name = "HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00".strip()
    canonical_name = reader_name[:-5]
    imsi = abs(int(hashlib.md5(canonical_name.encode()).hexdigest(), 16)) % (2 ** 64)
    imsi = 232077613951364
    logging.info(f"reader with canonical name '{canonical_name}' and imsi {imsi} added")

    socket_connection = tls_ctx.wrap_socket(
        socket.create_connection((parser.get_host(), parser.get_port())),
        server_hostname=parser.get_tls_server_name(),
    )
    logger.info(f"requesting {imsi}")
    while True:
        pico_measurement, probe_measurement = relay_with_pico(imsi, socket_connection, delay_relay=False)

        print(pico_measurement)
        measurements = reduce(
            lambda x, y: x + "\n" + y,
            map(
                lambda x: ",".join(
                    [
                        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                        x[0][0],
                        x[1],
                        x[0][1],
                        x[0][2],
                    ]
                ),
                zip_longest(
                    (
                        (str(a), '"' + str(b) + '"', '"' + str(c) + '"')
                        for (a, b, c) in probe_measurement
                    ),
                    map(str, pico_measurement),
                    fillvalue="",
                ),
            ),
            "",
        )

        logging.info("writing measurements...")

        with open("measurements.csv", mode="a", encoding="utf-8") as measurement_file:
            measurement_file.write(measurements + "\n")
        socket_connection.close()
    exit(0)


if __name__ == "__main__":
    main()
