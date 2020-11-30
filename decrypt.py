#!/usr/bin/env python3

import socket
import sys
import math

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


def send_message(buf, host, port):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=0)
    sock.sendto(buf, (host, port))
    (data, addr_info) = sock.recvfrom(512)
    sock.close()

    return data


def convBytes(item):
    return bytes.fromhex("{:02x}".format(item))


def checkPadding(bytes, question=1):
    data = send_message(bytes, "127.0.0.1", 8642)
    if question == 2:
        return True if data == b'You sent the magic phrase!' else False
    return True if data == b'Message OK' else False


def decrypt():
    block_num = 0
    block_size = 16
    final_plain_text = ''
    NUM = 0

    while block_num < len(CT) // block_size:
        PT = ''
        if block_num == 0:
            C1 = '\x00' * 16
            C2 = CT[block_num * block_size:(block_num + 1) * block_size]
        else:
            C1 = CT[(block_num - 1) * block_size:(block_num) * block_size]
            C2 = CT[(block_num) * block_size:(block_num + 1) * block_size]
        padding = 1

        i = block_size - 1
        while i >= 0:
            DC = decrypt_helper(C1, C2, padding, i, PT)
            PT += DC[0]
            NUM += DC[1]
            padding += 1
            i -= 1
            print(PT)

        final_plain_text += PT[::-1]
        block_num += 1

        print(f'Number of queries: {NUM}')
        print(f'Final Decrypted Text (including garbage IV): {final_plain_text}')


def decrypt_helper(C1, C2, padding, i, PT):
    """
    Function to decrypt the given bock

    :param C1: Previous block that assists in decrypting
    :param C2: Block to decrypt
    :param padding: Value of padding that should be given to the block
    :param i: Index of position in the block
    :param PT: Plain text
    :return: The decrypted character at position i
    """

    NUM = 0
    for item in range(256):
        NUM += 1
        C_PRIME = b'\x00' * i + convBytes(item)

        if padding > 1:
            p = padding - 1
            while p > 0:
                C_PRIME += convBytes(padding ^ ord(PT[p - 1]) ^ ord(C1[16 - p: 16 - p + 1]))
                p -= 1
        msg = C_PRIME + C2

        if checkPadding(msg):
            character = chr(padding ^ item ^ ord(C1[16 - padding: 16 - padding + 1]))
            print('Found Character:', character, ord(character))
            return (character, NUM)


def add_padding():
    plaintext = 'It was the best of times, it was the worst of times'

    PT = [ord(c) for c in plaintext]
    padding = len(PT)
    while padding % 16 != 0:
        padding += 1

    required = padding - len(PT)
    PT.extend([required] * required)
    return PT


def encrypt():
    PT = add_padding()
    n = math.ceil(len(PT) / 16)

    CN = b''.join([convBytes(c) for c in range(16)])

    CT_LIST = [CN]

    while n > 0:
        i = 15
        padding = 1
        CMAJOR = []

        while i >= 0:

            for item in range(256):
                C1_PRIME = (b'\x00' * i) + convBytes(item)
                if padding > 1:

                    for p in range(padding - 1):
                        C1_PRIME += convBytes(CMAJOR[p] ^ padding)
                        p -= 1
                C1_PRIME += CN

                if checkPadding(C1_PRIME):
                    print(f'C1_PRIME: {C1_PRIME}')
                    print('Found Item: ', item)
                    CMAJOR.insert(0, item ^ padding)
                    break

            i -= 1
            padding += 1

            print('New CMAJOR:', CMAJOR)

        print(f'CMAJOR XORd: {b"".join([convBytes(c) for c in CMAJOR])}')
        CN = b''

        currentPTBlock = PT[(n - 1) * 16:(n-1) * 16 + 16]
        print(f'Current PT Block:', currentPTBlock)

        for c in range(16):
            xor = convBytes(CMAJOR[c] ^ currentPTBlock[c])
            CN += xor

        CT_LIST.insert(0, CN)
        print(f"CTLIST: {b''.join(CT_LIST).hex()}")

        n -= 1

    print('Final CT:', b''.join(CT_LIST))
    return b''.join(CT_LIST)


if __name__ == "__main__":
    encryptedData = encrypt()
    print(checkPadding(encryptedData, 2))

    decrypt()
