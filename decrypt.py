import math

from oracle import CT, convBytes, checkPadding, BLOCK_SIZE, HEX_VALUES




def decrypt() -> None:
    """
    Function to decrypt a the given CT
    """

    block_num = 0
    final_plain_text = ''
    NUM = 0

    while block_num < math.ceil(len(CT) / BLOCK_SIZE):
        PT = ''
        if block_num == 0:
            C1 = '\x00' * 16
            C2 = CT[block_num * BLOCK_SIZE:(block_num + 1) * BLOCK_SIZE]
        else:
            C1 = CT[(block_num - 1) * BLOCK_SIZE:block_num * BLOCK_SIZE]
            C2 = CT[block_num * BLOCK_SIZE:(block_num + 1) * BLOCK_SIZE]
        padding = 1

        i = BLOCK_SIZE - 1
        while i >= 0:
            DC = decrypt_helper(C1, C2, padding, i, PT)
            PT += DC[0]
            NUM += DC[1]
            padding += 1
            i -= 1

        final_plain_text += PT[::-1]
        block_num += 1

        print(f'Number of calls: {NUM}')
        print(f'Final Decrypted Text (including garbage IV): {final_plain_text}')


def decrypt_helper(C1, C2, padding, i, PT):
    """
    Function to decrypt the given block

    :param C1: Previous block that assists in decrypting
    :param C2: Block to decrypt
    :param padding: Value of padding that should be given to the block
    :param i: Index of position in the block
    :param PT: Plain text
    :return: A tuple (decrypted character at i, number of tries to get the correct padding)
    """

    NUM = 0
    for value in range(HEX_VALUES):
        NUM += 1
        C_PRIME = b'\x00' * i + convBytes(value)

        if padding > 1:
            p = padding - 1
            while p > 0:
                C_PRIME += convBytes(padding ^ ord(PT[p - 1]) ^ ord(C1[BLOCK_SIZE - p: BLOCK_SIZE - p + 1]))
                p -= 1
        msg = C_PRIME + C2

        if checkPadding(msg):
            character = chr(padding ^ value ^ ord(C1[BLOCK_SIZE - padding: BLOCK_SIZE - padding + 1]))
            print('Found Character:', character, ord(character))
            return character, NUM
