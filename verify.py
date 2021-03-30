#!/usr/bin/env python3

# Copyright 2021 Vanessa Sochat
# Copyright 2011 Trevor Bentley

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#  http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
from struct import unpack, calcsize

import sys
import struct
import math
from Crypto.Hash import SHA
from Crypto.Cipher import DES3
import getpass
import zlib
import tempfile


# keep a list of packets
packets = []


def read_bytes(filey, fmt, number=None):
    """just read a number of bytes from an open file.
    Parameters
    ==========
    filey: an open file object
    number: the number of bytes to read
    fmt: an optional format string
    """
    if number == None:
        number = calcsize(fmt)

    return filey.read(number)


def unpack_bytes(filey, fmt, number=None):
    """read AND unpack a number of bytes from an open file. If a
    format is provided, convert to utf-8 and return the string.
    If fmt is None, assume a character string of the same length.
    Parameters
    ==========
    filey: an open file object
    number: the number of bytes to read
    fmt: an optional format string
    """
    byte_values = read_bytes(filey, fmt, number)
    return unpack(fmt, byte_values)


def load_packets_file_to_list(fd):
    global packets

    # Create a Packet, including reading in the packet header
    while True:

        # The binary information is made of packets. Each packet has:
        # 1. a packet header (of variable length)
        # 2. followed by the packet body.
        packet = Packet()
        if not packet.load_file(fd):
            break
        packets.append(packet)


def main(gpgfile):
    """
    Given a gpgfile, verify the signature
    """
    gpgfile = os.path.abspath(gpgfile)
    if not os.path.exists(gpgfile):
        sys.exit("%s does not exist." % gpgfile)

    # Read binary information
    with open(gpgfile, "rb") as fd:
        load_packets_file_to_list(fd)

    packet = packets[0]
    print("TODO: how to process signature?")
    import IPython

    IPython.embed()


global packetList
packetList = []


class PacketHeader:
    """Represents the header of a PGP packet"""

    packetTagStrings = {
        0: "Reserved",
        1: "PUB ENC Session",
        2: "Signature",
        3: "SYM ENC Session",
        4: "One-Pass Signature",
        5: "Secret Key",
        6: "Public Key",
        7: "Secret Subkey",
        8: "Compressed Data",
        9: "SYM ENC Data",
        10: "Marker",
        11: "Literal Data",
        12: "Trust",
        13: "User ID",
        14: "Public Subkey",
        17: "User Attribute",
        18: "SYM ENC INTEG Data",
        19: "Modification Detection Code",
    }
    """Packet tag identifies the type of packet"""

    def __init__(self):
        self.raw_packet_tag_byte = None
        self.new_format = None
        self.tag = None
        self.header_length = None
        self.length = None
        self.is_partial = None

    def load_from_file(self, fd):
        """
        Load the packet header from an open file
        """
        # The first octet of the packet header is called the "Packet Tag".  It
        # determines the format of the header and denotes the packet contents.
        # The remainder of the packet header is the length of the packet.
        tagByte = fd.read(1)

        # It must be defined, otherwise cut out early
        if len(tagByte) == 0:
            return False

        # The most significant bit is the leftmost bit, called bit 7
        # A mask for this bit is 0x80 in hexadecimal.
        # https://tools.ietf.org/html/rfc4880#section-4.2
        tagByte = ord(tagByte)
        if not (tagByte & 0x80):
            sys.exit("Invalid tag byte: 0x%x" % tagByte)
        self.raw_packet_tag_byte = tagByte

        # There is a new and and old format
        self.new_format = tagByte & 0x40
        if self.new_format:
            self.tag = tagByte & 0x1F
        else:
            self.tag = (tagByte >> 2) & 0x0F
        self.read_header_length(fd)
        return True

    def read_header_length(self, fd):
        """Read the packet header variable length"""
        if self.new_format:
            self.length = self.load_new_length(fd)
        else:

            # https://tools.ietf.org/html/rfc4880#section-4.2.1
            lentype = self.raw_packet_tag_byte & 0x03

            # header is 2 octets long
            if lentype == 0:
                self.header_length = 2

            # header is 3 octets long
            elif lentype == 1:
                self.header_length = 3

            # header is 5 octets long
            elif lentype == 2:
                self.header_length = 5

            # 3, undeterminable length. If the packet is in a file, it extends to end.
            else:
                self.header_length = 1
                self.length = 0
                return
            self.length = self.load_old_length(fd)

    def load_new_length(self, fd):
        """Read a new header length

        For new-style packets, value of each byte tells us how many more to read
        We can keep reading by calling this function until is_partial is False.
        """
        self.is_partial = False
        bytes = fd.read(1)
        val = ord(bytes[0])

        # one byte length
        if val <= 191:
            self.header_length = 2
            return val

        # two byte length
        if val >= 192 and val <= 223:
            self.header_length = 3
            bytes += f.read(1)
            val = ((val - 192) << 8) + ord(bytes[0]) + 192
            return val

        # 4 byte length
        if val == 255:
            self.header_length = 6
            bytes = f.read(4)
            val = (
                ord(bytes[0]) << 24
                | ord(bytes[1]) << 16
                | ord(bytes[2]) << 8
                | ord(bytes[3])
            )
            # val = ord(bytes[0])<<0 | ord(bytes[1])<<8 | ord(bytes[2])<<16 | ord(bytes[3])<<24
            return val

        # This is partial length header
        self.header_length = 2
        self.is_partial = True
        bytes = 1 << (val & 0x1F)
        return bytes

    def load_old_length(self, fd):
        """Read an old header length
        For old style packets, bits in tag tell us how many bytes to read
        """
        numbytes = self.header_length - 1
        bytes = fd.read(numbytes)
        val = 0
        for i in range(numbytes):
            val <<= 8
            val += bytes[i]
        return val

    def tagString(self):
        """Print string description of header tag"""
        try:
            return PacketHeader.packetTagStrings[self.tag]
        except KeyError:
            return "UNKNOWN"

    def __str__(self):
        """Print formatted description of this header"""
        return "HEADER TYPE (%s) HEADER SIZE (%d) DATA LEN (%d)" % (
            self.tagString(),
            self.header_length,
            self.length,
        )


class Packet:
    """Stores content of a PGP packet, and a copy of its header"""

    algorithmStrings = {
        1: "RSA",
        2: "RSA Encrypt-Only",
        3: "RSA Sign-Only",
        16: "Elgamal",
        17: "DSA",
        18: "Elliptic Curve",
        19: "ECDSA",
        20: "Elgamal OLD",
        21: "Diffie-Hellman",
    }
    """Asymmetric ciphers"""

    encryption_strings = {
        0: "Plaintext",
        1: "IDEA",
        2: "TripleDES",
        3: "CAST5",
        4: "Blowfish",
        7: "AES-128",
        8: "AES-192",
        9: "AES-256",
        10: "Twofish",
    }
    """Symetric ciphers"""

    hashStrings = {
        1: "MD5",
        2: "SHA-1",
        3: "RIPE-MD/160",
        8: "SHA256",
        9: "SHA384",
        10: "SHA512",
        11: "SHA224",
    }
    """Hash algorithms"""

    compressedStrings = {0: "Uncompressed", 1: "ZIP", 2: "ZLIB", 3: "BZip2"}

    def __init__(self):
        """
        Create empty packet with an empty header.
        """
        self.header = PacketHeader()
        self.data = None

    def __str__(self):
        return str(self.header)

    def __repr__(self):
        return str(self)

    def load_file(self, fd):
        """
        Load the packet header, and then the rest of the content.
        """
        if not self.header.load_from_file(fd):
            return False

        # keep reading until is_partial is false (we've read the whole thing)
        if self.header.length > 0:
            self.data = fd.read(self.header.length)
            while self.header.is_partial:
                bytes = self.header.load_new_length(fd)
                self.header.length += bytes
                self.data += fd.read(bytes)

        # old type header, packet is inderminable length
        else:
            self.data = fd.read(1024 * 1024 * 1024)
        print(self.header)

        # These are the kinds of packets (by tag)
        # https://tools.ietf.org/html/rfc4880#section-4.3

        # secret key or secret subkey packet
        if self.header.tag == 5 or self.header.tag == 7:
            self.load_secret_key_packet(self.data)

        # Public key encrypted session key package
        elif self.header.tag == 1:
            self.load_session_key(self.data)

        # Sym. Encrypted and Integrity Protected Data Packet
        elif self.header.tag == 18:
            self.load_encrypted_data_packet(self.data)

        # Compressed Packet
        elif self.header.tag == 8:
            self.load_compressed_packet(self.data)

        # Literal Data Packet
        elif self.header.tag == 11:
            self.load_literal_data_packet(self.data)

        return True

    def load_literal_data_packet(self, data):
        print("Literal Data packet")
        idx = 0
        self.format = data[idx]
        idx += 1
        print(data)

    def load_compressed_packet(self, data):
        print("Compressed packet")
        idx = 0
        self.algo = data[idx]
        idx += 1
        print(self.compressed_string())

        uncompressed = None

        # ZIP
        if self.algo == 1:
            # Magic "wbits=-15" means do a raw decompress without ZIP headers
            uncompressed = zlib.decompress(data[idx:], -15)

        # ZLIB
        elif self.algo == 2:
            uncompressed = zlib.decompress(data[idx:])

        if uncompressed != None:
            tfile = tempfile.TemporaryFile()
            tfile.write(uncompressed)
            tfile.seek(0)
            load_packets_file_to_list(tfile)

    def load_encrypted_data_packet(self, data):
        sys.exit("Loading an encrypted data packet is not supported.")

    def load_session_key(self, data):
        sys.exit("Loading a session key is not supported.")

    def load_secret_key_packet(self, data):
        """
        Load contents of a secret key -- decrypt encrypted contents.
        See gist with repository for link to original code (that needs work).
        """
        sys.exit("Loading and decrypting secret key contents is not supported.")

    def read_mpi_from_buffer(self, data):
        """Reads a multi-precision integer from a buffer of bytes."""
        # First two bytes are number of bits to read
        bits = struct.unpack(">H", data[0:2])[0]
        # print " * MPI bits: %d" % bits
        # Convert bits to bytes, add 2 for the header
        bytes = int((bits + 7) / 8) + 2
        return data[0:bytes]

    def algo_string(self):
        """Convert asymmetric algorithm index to string"""
        try:
            return Packet.algorithmStrings[self.algo]
        except Exception:
            return "UNKNOWN - %d" % self.algo

    def encryption_string(self):
        """Convert symmetric algorithm index to string"""
        try:
            return Packet.encryption_strings[self.encryption]
        except Exception:
            return "UNKNOWN - %d" % self.encryption

    def hash_string(self):
        """Convert hash algorithm index to string"""
        try:
            return Packet.hashStrings[self.hash]
        except Exception:
            return "UNKNOWN - %d" % self.hash

    def compressed_string(self):
        """Convert asymmetric algorithm index to string"""
        try:
            return Packet.compressedStrings[self.algo]
        except Exception:
            return "UNKNOWN - %d" % self.algo


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.exit("Please provided a *.gpg file to verify")
    main(sys.argv[1])
