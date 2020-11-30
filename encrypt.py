import math

from oracle import addPadding, convBytes, checkPadding


def encrypt() -> bytes:
    """
    Function to encrypt the given data
    :return: Bytes of encrypted data
    """

    PT = addPadding()  # plain text with padding
    n = math.ceil(len(PT) / 16)  # number of blocks

    PREV_BLOCK = b''.join([convBytes(c) for c in range(16)])  # initializing previous block with random values
    CT_LIST = [PREV_BLOCK]  # final cipher-text list

    while n > 0:
        INT_BLOCK = encrypt_helper(PREV_BLOCK)

        PREV_BLOCK = b''

        currentPTBlock = PT[(n - 1) * 16:(n - 1) * 16 + 16]

        for c in range(16):
            xor = convBytes(INT_BLOCK[c] ^ currentPTBlock[c])
            PREV_BLOCK += xor

        CT_LIST.insert(0, PREV_BLOCK)

        n -= 1

    print('Final CT:', b''.join(CT_LIST))
    return b''.join(CT_LIST)


def encrypt_helper(PREV_BLOCK) -> list:
    """
    Helper function to find out the intermediate block
    :param PREV_BLOCK: Previous block of encrypted data
    :return: Intermediate block
    """

    i = 15  # position in block
    padding = 1
    INT_BLOCK = []

    while i >= 0:

        for value in range(256):
            C_PRIME = (b'\x00' * i) + convBytes(value)
            if padding > 1:

                for p in range(padding - 1):
                    C_PRIME += convBytes(INT_BLOCK[p] ^ padding)
                    p -= 1

            C_PRIME += PREV_BLOCK

            if checkPadding(C_PRIME):
                print('Found Value: ', value)
                INT_BLOCK.insert(0, value ^ padding)
                break

        i -= 1
        padding += 1

        return INT_BLOCK


