#!/usr/bin/env python3

import socket

# Legitimate ciphertext
CT = bytes.fromhex("e6 b1 48 42 41 1b 31 fb fe 02 e3 32 b5 14 61 81")
CT += bytes.fromhex("f0 d0 7c 0f a5 0f 26 f4 c4 6c 57 a0 c5 6c bb 3b")
CT += bytes.fromhex("f9 e6 a6 0d ee 42 82 96 f0 70 7a fc 2e fc 08 d5")
CT += bytes.fromhex("89 ab ca 17 71 4b fa 5e 30 93 e3 98 e6 e9 15 53")
CT += bytes.fromhex("7f 3b 77 eb 9d 15 db dc 89 37 49 29 12 ea 22 bc")
CT += bytes.fromhex("24 a9 79 cc df cc 5f 67 ee 4d 84 d5 ba 05 47 16")
CT += bytes.fromhex("7f 50 5c 18 55 5d fc 70 aa 8f 54 9d 87 36 d6 ec")
CT += bytes.fromhex("b2 4c f7 e3 49 d7 0f 49 d5 cd e8 98 8b a3 db af")
CT += bytes.fromhex("8e 70 12 13 c6 b4 dd e0 ce 78 bc d2 18 ca 73 33")
CT += bytes.fromhex("23 00 a2 91 99 2e 8e 8e 5f 70 b5 47 53 bd 81 a3")
CT += bytes.fromhex("da 46 d3 27 ab d5 49 ae 46 ae 73 4a 4a 65 99 05")
CT += bytes.fromhex("e4 64 3f 0c ad b1 6c 2b 68 6a 48 6a 1f d6 5b cc")
CT += bytes.fromhex("11 e7 1c ea bd fb 40 b3 72 ed dd b0 fa 31 18 74")
CT += bytes.fromhex("58 64 7f 0d 0a 60 85 e9 b9 c4 3d a3 1e 70 99 56")
CT += bytes.fromhex("2d 23 ca 34 72 01 f5 55 09 04 60 af 5b 6b 40 0e")
CT += bytes.fromhex("b2 4b 7a 4b 5d d8 4c de a9 48 96 de 89 7b cd b8")
CT += bytes.fromhex("2c 61 3c 0b 24 a6 fc ed b4 02 7a ce c3 38 47 0b")

# Size not divisible by blocksize
CT2 = CT + b"\x00"

#Corrupted
CT3 = CT[0:-1] + b"\x00"

def send_message(buf, host, port):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=0)
    sock.sendto(buf, (host, port))
    (data, addr_info) = sock.recvfrom(512)
    sock.close()

    return data

if __name__ == "__main__":
    data = send_message(CT, "127.0.0.1", 8642);
    print(f"Received: {data}")
    data = send_message(CT2, "127.0.0.1", 8642);
    print(f"Received: {data}")
    data = send_message(CT3, "127.0.0.1", 8642);
    print(f"Received: {data}")

