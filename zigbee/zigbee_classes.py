class ZigBeeDevice:
    def __init__(self, dev=None, src=None) -> None:
        self.src = src if src else ""
        self.manufacturer = dev['manufacturer'] if dev else ""
        self.model = dev['model'] if dev else ""
        self.build = dev['build'] if dev else ""

    def _set_manufacturer(self, manu):
        self.manufacturer = manu

    def _set_model(self, model):
        self.model = model

    def _set_build(self, build):
        self.build = build

    def __repr__(self) -> str:
        if self.model and self.build and self.manufacturer:
            return f"Device(src='{self.src}', manufacturer='{self.manufacturer}', model='{self.model}', build='{self.build}')"
        return ""

    def __str__(self) -> str:
        if self.model and self.build and self.manufacturer:
            return f"Device Info ({self.src}):\nManufacturer: {self.manufacturer}\nModel: {self.model}\nBuild: {self.build}"
        return ""

    def __hash__(self) -> int:
        return hash((self.manufacturer, self.model, self.build))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ZigBeeDevice):
            return NotImplemented
        return (self.manufacturer, self.model, self.build) == (other.manufacturer, other.model, other.build)


class ZigBeeCapture:
    def __init__(self,
                 filename,
                 creation_time,
                 nr_packets,
                 nr_zigbee_packets,
                 channel,
                 transport_keys,
                 trust_keys,
                 programs_used,
                 sniffing_device,
                 sniffing_device_dev_id,
                 devices):
        self.filename = filename
        self.start_time = creation_time
        self.finish_time = 0
        self.nr_packets = nr_packets
        self.nr_zigbee_packets = nr_zigbee_packets
        self.channel = channel
        self.transport_keys = transport_keys
        self.trust_keys = trust_keys
        self.programs_used = programs_used
        self.sniffing_device = sniffing_device
        self.sniffing_device_dev_id = sniffing_device_dev_id
        self.devices = devices
