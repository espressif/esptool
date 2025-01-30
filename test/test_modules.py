# Tests for regressions in python modules
# used by esptool.py, espefuse.py, and espsecure.py

import pytest

import reedsolo


@pytest.mark.host_test
def test_reed_solomon_encoding():
    # fmt: off
    pairs = [("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "0404992ae0b12cb0ef0d4fd3"),
             ("11a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbd11bf", "e001803c2130884c190d57d5"),
             ("22a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbd22bf", "6c32056dd3fcc33fa6193773"),
             ("0a1a2a3a4a5a6a7a8a9aaabacadaeafa0b1b2b3b4b5b6b7b8b9babbbcbdbebfb", "08149eef461af628943c2661"),
             ("b3f455fb0b275123dec0e73c4becca19246bf2b103df401844a3bdcd3fd01a95", "500409183fa1b8e680568da7"),
             ("435777773fb1e36f7d6b5f1e99afaa7a57f16be0ed36bc057c7dae6a266d1504", "815d3007153d797bd6630d0e"),
             ("20a126c10f50ee871f43cfcfe4e62a492e3f729a6c48348a58863f3a482a69fe", "36150928f41dcacf396c0893"),
             ("a8d5fbda18d75605c422d2b10ac7f73283a5c9609d6b8c90ffaa96b84f133582", "a4f21330282242c9e20b6acf"),
             ("4296abb9a44432c8656d5605feffc25d71941fd0abf0ff0d61a01a19315a264c", "1bb4c3afd14b9023b33a2f15"),
             ("206e4f83f8173635d7d554d96b84586fbc3a4280b4403cba5834d3dc8e99a682", "1b7edac989c569cb08f9efd9"),
             ("57e8dc1b37c6b53a428fc6d7242114eaf3d80b0447bb642703120a257cf7ec52", "5ee82f785f3d5e19df92635b"),
             ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "13a36292597404257375e0aa"),
             ("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0", "f66cb1ba3ee5d164a19668a0"),
             ("abad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1deaabad1dea", "1171924a9b34c16878e182a5"),
             ("abad1deadeadbeefabadbabecafebabe11223344556677889900aabbccddeeff", "7601266085196663727c6522"),
             ("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000"),
             ("1000000000000000000000000000000000000000000000000000000000000000", "b6f06eae2266cc0bfca685ca"),
             ("0001000100010001000a000b000c000d000e000f000100010001000100010001", "6dc2afb4820bb002d9263544"),
             ("0000000000000000000000000000000000000000000000000000000000000001", "44774376dc1f07545c7fd561"),
             ]  # Pregenerated pairs consisting of 32 bytes of data + 12 bytes of RS ECC (FPGA verified)
    # fmt: on

    rs = reedsolo.RSCodec(12)  # 12 ECC symbols

    for pair in pairs:
        bin_base = bytearray.fromhex(pair[0])
        # Encode the original 32 bytes of data
        encoded_data = rs.encode([x for x in bin_base])
        assert encoded_data == bytearray.fromhex(pair[0] + pair[1])
