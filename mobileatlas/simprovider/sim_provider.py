#!/usr/bin/env python3
"""
SIM Provider Main
"""
import hashlib
import logging
from mobileatlas.simprovider.device_observer import DeviceEvent, DeviceObserver
from pySim.transport.serial import SerialSimLink
from pySim.transport.pcsc import PcscSimLink
from pySim.transport.bluetooth_rsap import BluetoothSapSimLink
from pySim.commands import SimCardCommands
from pySim.cards import SimCard


class SimInfo:
    def __init__(self, iccid, imsi, device_name, atr, sl):
        self.iccid = iccid
        self.imsi = imsi
        self.device_name = device_name
        self.atr = atr
        self.sl = sl

class SimProvider(DeviceEvent):
    def __init__(self, bluetooth_mac=None):
        self.sims = []
        self.device_change_callback = None
        if bluetooth_mac:
            sl = BluetoothSapSimLink(bluetooth_mac) #("80:5A:04:0E:90:F6")
            sim = SimProvider.query_sim_info("Bluetooth[rSAP]", sl)
            self.sims.append(sim)
        observer = DeviceObserver()
        observer.add_observer(self)
        observer.start()

    def set_device_change_callback(self, callback):
        self.device_change_callback = callback

    def device_added(self, device_type, device):
        device_name = f"{device_type}[{device}]"
        self.prepare_sim_interface(device_name, device_type, device)

        if self.device_change_callback != None:
            self.device_change_callback()

    def device_removed(self, device_type, device):
        device_name = f"{device_type}[{device}]"
        self.sims = [e for e in self.sims if e.device_name != device_name]

        if self.device_change_callback != None:
            self.device_change_callback()
    
    def prepare_sim_interface(self, device_name, device_type, device):
        try:
            if device_type == DeviceEvent.DEVICE_TYPE_SERIAL:
                sl = SerialSimLink(device=device)
            elif device_type == DeviceEvent.DEVICE_TYPE_SCARD:
                sl = PcscSimLink(device.index)
            sim = SimProvider.query_sim_info(device_name, sl)
            self.sims.append(sim)
        except Exception as e:
            logging.warn(f"prepare sim interface error {repr(e)}")

    def get_sims(self):
        logging.info(f"get sims {list(map(lambda x: (x.device_name,x.imsi), self.sims))}")
        return self.sims

    @staticmethod
    def query_sim_info(device_name, sl, is_connected=False):
        """
        Retrieve sim info
        """
        # connect simlink if not connected
        if not is_connected:
            sl.connect()

        def do_sim():
                # Create command layer
            scc = SimCardCommands(transport=sl)

            # TODO: add check that it is an actual sim card?
            sim_card = SimCard(scc) #Card(scc)

            # query iccid
            iccid, sw = sim_card.read_iccid()
            if not iccid or sw != '9000':
                logging.debug(f"Error querying iccid ({iccid}, {sw})")
                return None

            # query imsi
            imsi, sw = sim_card.read_imsi()
            if not imsi:
                logging.debug(f"Error querying imsi ({imsi}, {sw})")
                return None

            sim_info = SimInfo(iccid, imsi, device_name, sl.get_atr(), sl)

            # bring back into disconnected state
            if not is_connected:
                sl.disconnect()

            logging.info(f"device {sim_info.device_name} --> has imsi {sim_info.imsi}, iccid {sim_info.iccid}, and atr {sim_info.atr}")

            return sim_info
        
        def do_scard_t1():
            # In some T1 cards iccid, imsi are not available
            # -> use hashed reader name
            #cn = 'Generic Smart Card Reader Interface [Smart Card Reader Interface] (20070818000000000) 00 00'
            
            reader_name = str(sl._con.component.reader)
            canonical_name = reader_name[:-5]
            imsi = abs(int(hashlib.md5(canonical_name.encode()).hexdigest(), 16)) % (2**64)
            return SimInfo(None, imsi, device_name, sl.get_atr(), sl)
        
        """ https://github.com/LudovicRousseau/pyscard/blob/master/smartcard/CardConnection.py#L150
            defaultprotocol: a bit mask of L{CardConnection.T0_protocol},
                L{CardConnection.T1_protocol}, L{CardConnection.RAW_protocol},
                L{CardConnection.T15_protocol}
                Example:
                0010 = 2 -> T1
                0011 = 3 -> T0,T1
        """
        logging.info(f"device name {device_name}")
        if hasattr(sl, '_con') and sl._con.component.defaultprotocol % 4 == 2:
            return do_scard_t1()
        return do_sim()


def main():
    logging.basicConfig(level=logging.ERROR)

    # sim_mapping[ imsi:string ] = serial_port:string
    sim_provider = SimProvider()
    available_sims = sim_provider.get_sims()

    device = next((x for x in available_sims), None)
    if not device:
        exit("no device found...")
    print(f"device {device.device_name} has atr {device.atr.hex()}, imsi {device.imsi}, iccid {device.iccid}")

    import time
    start_time = time.time()
    # reset card and query stuff
    for x in range(10):
        SimProvider.query_sim_info(device.device_name, device.sl, False)
    
    stop_time = time.time()
    elapsed_1 = stop_time - start_time


    start_time = time.time()

    device.sl.connect()
    for x in range(10):
        SimProvider.query_sim_info(device.device_name, device.sl, True)

    stop_time = time.time()
    elapsed_2 = stop_time - start_time

    # just for fun, lets generate some traffic to ensure verything is working well
    # if no error was thrown we assume that everythin is fine
    for x in range(100):
        SimProvider.query_sim_info(device.device_name, device.sl, True)
    device.sl.disconnect()


    print(f"benchmark finished, timings (with/without reset): {elapsed_1:.2f}/{elapsed_2:.2f}")

if __name__ == "__main__":
    main()
