import os
import struct
import sys
import unittest

_test_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.dirname(_test_dir)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

try:
    from pc_monitor.someip_decoder import (
        MessageType,
        ReturnCode,
        SdEntryType,
        SdOptionType,
        decode_sd,
        decode_someip,
        format_hex_dump,
        interpret_payload,
    )
except ImportError:
    from someip_decoder import (
        MessageType,
        ReturnCode,
        SdEntryType,
        SdOptionType,
        decode_sd,
        decode_someip,
        format_hex_dump,
        interpret_payload,
    )


class TestSomeIpDecoder(unittest.TestCase):
    def test_decode_request(self):
        # Service 0x1234, Method 0x0001, Length 16 (8 hdr + 8 payload)
        # Client 0x0001, Session 0x0042, Proto 1, Iface 1, Type REQUEST (0x00), Code E_OK (0x00)
        pdu = bytes([
            0x12, 0x34, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x10,
            0x00, 0x01, 0x00, 0x42,
            0x01, 0x01, 0x00, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ])
        msgs = decode_someip(pdu)
        self.assertEqual(len(msgs), 1)
        msg = msgs[0]
        self.assertEqual(msg.header.service_id, 0x1234)
        self.assertEqual(msg.header.method_id, 0x0001)
        self.assertFalse(msg.header.is_event)
        self.assertEqual(msg.header.length, 16)
        self.assertEqual(msg.header.client_id, 0x0001)
        self.assertEqual(msg.header.session_id, 0x0042)
        self.assertEqual(msg.header.message_type, MessageType.REQUEST)
        self.assertEqual(msg.header.return_code, ReturnCode.E_OK)
        self.assertFalse(msg.header.is_tp)
        self.assertEqual(msg.payload, bytes([1, 2, 3, 4, 5, 6, 7, 8]))
        self.assertFalse(msg.is_sd)

    def test_decode_tp_notification(self):
        # Event 0x8123 (bit 15 set), Length 16, Type TP_NOTIFICATION (0x22)
        # TP Header: Offset=16, More=1
        pdu = bytes([
            0x12, 0x34, 0x81, 0x23,
            0x00, 0x00, 0x00, 0x10,
            0x00, 0x01, 0x00, 0x05,
            0x01, 0x01, 0x22, 0x00,
            0x00, 0x00, 0x01, 0x01,
            0xAA, 0xBB, 0xCC, 0xDD,
        ])
        msgs = decode_someip(pdu)
        self.assertEqual(len(msgs), 1)
        msg = msgs[0]
        self.assertTrue(msg.header.is_event)
        self.assertTrue(msg.header.is_tp)
        self.assertEqual(msg.header.message_type, MessageType.TP_NOTIFICATION)
        self.assertEqual(msg.header.tp_offset, 0x00000100)
        self.assertTrue(msg.header.tp_more_segments)
        self.assertEqual(msg.payload, bytes([0xAA, 0xBB, 0xCC, 0xDD]))

    def test_decode_sd_offer_service(self):
        # SOME/IP-SD OfferService
        pdu = bytes([
            # SOME/IP Header (16 bytes)
            0xFF, 0xFF, 0x81, 0x00,
            0x00, 0x00, 0x00, 0x30, # Length 48 (8 hdr + 40 SD payload)
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0x02, 0x00,
            # SD Flags (4 bytes)
            0xC0, 0x00, 0x00, 0x00, # Reboot=1, Unicast=1
            # Entries Length (4 bytes)
            0x00, 0x00, 0x00, 0x10,
            # Entry 0 (16 bytes)
            0x01, 0x00, 0x00, 0x10, # OfferService, Opt1_Idx=0, 1 Opt
            0x12, 0x34, 0x56, 0x78, # Service 0x1234, Instance 0x5678
            0x01, 0x00, 0x00, 0x0A, # Major 1, TTL 10
            0x00, 0x00, 0x00, 0x2A, # Minor 42
            # Options Length (4 bytes)
            0x00, 0x00, 0x00, 0x0C,
            # Option 0 (12 bytes)
            0x00, 0x09, 0x04, 0x00, # Length 9, IPv4 Endpoint
            192, 168, 1, 10,
            0x00, 0x11, 0x0B, 0xBA, # UDP, port 3002
        ])
        msgs = decode_someip(pdu)
        self.assertEqual(len(msgs), 1)
        msg = msgs[0]
        self.assertTrue(msg.is_sd)
        self.assertIsNotNone(msg.sd)
        self.assertTrue(msg.sd.reboot_flag)
        self.assertTrue(msg.sd.unicast_flag)
        self.assertEqual(len(msg.sd.entries), 1)

        entry = msg.sd.entries[0]
        self.assertEqual(entry.entry_type, SdEntryType.OFFER_SERVICE)
        self.assertEqual(entry.type_name, "OfferService")
        self.assertEqual(entry.service_id, 0x1234)
        self.assertEqual(entry.instance_id, 0x5678)
        self.assertEqual(entry.major_version, 1)
        self.assertEqual(entry.minor_version, 42)
        self.assertEqual(entry.ttl, 10)

        # Options check
        self.assertEqual(len(msg.sd.options), 1)
        opt = msg.sd.options[0]
        self.assertEqual(opt.option_type, SdOptionType.IPV4_ENDPOINT)
        self.assertEqual(opt.ip, "192.168.1.10")
        self.assertEqual(opt.port, 3002)
        self.assertEqual(opt.proto, "UDP")

        # Resolved option on entry
        self.assertEqual(len(entry.endpoint_options), 1)
        self.assertEqual(entry.endpoint_options[0].ip, "192.168.1.10")
        self.assertEqual(entry.endpoint_options[0].port, 3002)

    def test_format_hex_dump(self):
        data = b"\x00\x01\x02\x03\x04\x05Hello World!\x00"
        dump = format_hex_dump(data, width=16)
        self.assertIn("0000", dump)
        self.assertIn("Hello Worl", dump)
        self.assertIn("d!.", dump)

    def test_interpret_payload(self):
        # Payload from comsumer.py: counter (uint32) + temperature (float32)
        counter = 42
        temperature = 23.5
        payload = struct.pack(">If", counter, temperature)
        interp = interpret_payload(payload)
        self.assertEqual(interp["Length (bytes)"], 8)
        self.assertEqual(interp["Uint32 (BE)"], 42)
        self.assertIn("Telemetry (>If)", interp)
        self.assertIn("23.50", interp["Telemetry (>If)"])

        # Inspect float at offset 4
        interp_float = interpret_payload(payload, offset=4)
        self.assertEqual(interp_float["Float32 (BE)"], 23.5)


    # ---------------------------------------------------------------
    # False-positive rejection tests
    # These verify that non-SOME/IP data is NOT incorrectly decoded.
    # ---------------------------------------------------------------

    def test_reject_json_payload(self):
        """Agent's own JSON telemetry must never be decoded as SOME/IP."""
        json_data = b'{"type":"status","message":"Capture started","packets":0}'
        msgs = decode_someip(json_data)
        self.assertEqual(msgs, [], f"JSON payload should not be decoded as SOME/IP: {json_data[:32]}")

    def test_reject_too_short(self):
        """Data shorter than 16 bytes cannot be a SOME/IP message."""
        msgs = decode_someip(b"\x12\x34\x00\x01\x00\x00\x00\x08")
        self.assertEqual(msgs, [])

    def test_reject_invalid_message_type(self):
        """Undefined message type byte must be rejected."""
        pdu = bytearray([
            0x12, 0x34, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x08,
            0x00, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x05, 0x00,  # msg_type=0x05 is undefined
        ])
        msgs = decode_someip(bytes(pdu))
        self.assertEqual(msgs, [], "Undefined message type should be rejected")

    def test_reject_wrong_protocol_version(self):
        """Protocol version != 1 must be rejected."""
        pdu = bytearray([
            0x12, 0x34, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x08,
            0x00, 0x01, 0x00, 0x01,
            0x02, 0x01, 0x00, 0x00,  # proto_ver=0x02, invalid
        ])
        msgs = decode_someip(bytes(pdu))
        self.assertEqual(msgs, [], "Protocol version != 1 must be rejected")

    def test_reject_sd_with_nonzero_client_id(self):
        """SOME/IP-SD messages must have client_id == 0x0000."""
        pdu = bytearray([
            0xFF, 0xFF, 0x81, 0x00,
            0x00, 0x00, 0x00, 0x08,
            0x00, 0x01, 0x00, 0x01,  # client_id = 0x0001 (invalid for SD)
            0x01, 0x01, 0x02, 0x00,
        ])
        msgs = decode_someip(bytes(pdu))
        self.assertEqual(msgs, [], "SD with non-zero client_id must be rejected")

    def test_reject_length_overflow(self):
        """Message with length field exceeding available data must be rejected."""
        pdu = bytearray([
            0x12, 0x34, 0x00, 0x01,
            0x00, 0xFF, 0xFF, 0xFF,  # length = 0xFFFFFF, way larger than pdu
            0x00, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x00, 0x00,
        ])
        msgs = decode_someip(bytes(pdu))
        self.assertEqual(msgs, [], "Overflow length must be rejected")


if __name__ == "__main__":
    unittest.main()
