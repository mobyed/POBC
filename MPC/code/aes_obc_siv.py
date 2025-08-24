from copy import copy
import sys

from Programs.Source.utils import tag_check
from Programs.Source.aes_gf_long import Aes128

from Compiler.library import for_range, for_range_opt, if_, print_ln, for_range_multithread, for_range_opt_multithread
from Compiler.types import program, cgf2n, regint, Matrix, sgf2n, Array, sfix, MultiArray, MemValue, sint

program.bit_length = 128
#BENCHMARK=False

#N = int(sys.argv[2])
#nparallel = int(sys.argv[3])

"""
Test Vectors:

plaintext:
6bc1bee22e409f96e93d7e117393172a

key:
2b7e151628aed2a6abf7158809cf4f3c

resulting cipher
3ad77bb40d7a3660a89ecaf32466ef97



test_message = "6bc1bee22e409f96e93d7e117393172a"
test_key = "2b7e151628aed2a6abf7158809cf4f3c"


"""

def incr_ctr_be_vec(base_ctr, nparallel, count):
    ctr_blocks = []
    for i in range(count):
        ctr = base_ctr + i
        bits = ctr.bit_decompose(32)
        ctr_bytes = []
        for j in range(4):
            part_bits = bits[8 * (3 - j): 8 * (3 - j) + 8]
            val_part = sum([cgf2n(2**k, size=nparallel) * b for k, b in enumerate(part_bits)])
            # print_ln('%s', val_part.reveal())
            ctr_bytes.append(val_part)
        ctr_blocks.append(ctr_bytes)
    return ctr_blocks


def aes_encrypt_block(state: Array, round_keys, cipher: Aes128):
    """AES encrypt one 16-byte block with expanded key"""
    num_rounds = 10
    state = cipher.SecretArrayEmbedd(state)
    # print(type(state[0]))
    #first round
    cipher.addRoundKey(round_keys[0])(state)
    
    for r in range(1, num_rounds):
        cipher.aesRound(round_keys[r])(state)

    # final round (no MixColumns)
    cipher.subBytes(state)
    cipher.shiftRows(state)
    cipher.addRoundKey(round_keys[num_rounds])(state)

    return state


def aes_obc_siv_128_decrypt(c, tag_expected, k, nonce):
    """ 
    c : ciphertext
    tag_expected: IV*
    k : key
    nonce : IV
    """
    assert len(k) == 16
    assert len(tag_expected) == 16
    nparallel = tag_expected[0].size
    assert len(nonce) == 12

    cipher = Aes128(nparallel)
    key_emb = [cipher.ApplyEmbedding(_) for _ in k]
    expanded_key = cipher.expandAESKey(key_emb)
    AES = cipher.encrypt_without_key_schedule(expanded_key)
    nrounds = len(expanded_key)//16
    round_keys = MultiArray([nrounds, 16], sgf2n)

    for r in range(nrounds):
        for j in range(16):
            round_keys[r][j] = expanded_key[r * 16 + j]
    # print(len(round_keys))
    # print(len(round_keys[0]))

    m_blocks = (len(c) + 15) // 16
    temp_c = MultiArray([m_blocks, 16], cgf2n)
    m_ctrs = incr_ctr_be_vec(regint(0), nparallel, m_blocks)
    for i in range(m_blocks):
        for j in range(len(nonce)):
            temp_c[i][j] = nonce[j]
        for j in range(4):
            temp_c[i][12 + j] = m_ctrs[i][j]

    output = MultiArray([m_blocks, 16], sgf2n)
    @for_range_opt_multithread(m_blocks, m_blocks)
    def _(i):
        input_block = Array(16,cgf2n)
        for j in range(16):
            input_block[j] = temp_c[i][j]
        output_block = aes_encrypt_block(input_block, round_keys, cipher)
        output[i] = output_block

    message = []
    for i in range(m_blocks):
        mblock = [c[i * 16 + j] + output[i][j].reveal() for j in range(16) if i * 16 + j < len(c)]
        message.extend(mblock)
    
    "Compute tag(IV*)"
    ptx = Array(len(message), cgf2n)
    for i in range(len(message)):
        ptx[i] = message[i]

    t_blocks = (len(ptx) + 11) // 12

    pad = [cgf2n(0, size=nparallel)] * (12 * t_blocks - len(ptx))
    temp_t = MultiArray([t_blocks, 16], cgf2n)

    t_ctrs = incr_ctr_be_vec(regint(2**31 + 1), nparallel, t_blocks)

    # Fill the first 4 bytes with t_ctrs and the last 12 bytes with ptx
    for i in range(t_blocks - 1):
        for j in range(4):
            temp_t[i][j] = t_ctrs[i][j]
        for j in range(12):
            temp_t[i][j + 4] = ptx[i * 12 + j]
        
    # Fill the last block
    for j in range(4):
        temp_t[t_blocks - 1][j] = t_ctrs[-1][j]
    for i in range(len(ptx)-12 * (t_blocks - 1)):
        temp_t[t_blocks - 1][i + 4] = ptx[12 * (t_blocks - 1) + i]
    for i in range(12 * t_blocks - len(ptx)):
        temp_t[t_blocks - 1][ len(c) - 12 * (t_blocks - 1) + 4 + i] = pad[i]
    # for i in range(t_blocks):
    #     for j in range(16):
    #         print_ln('temp_t[%s][%s] = %s', i, j, temp_t[i][j].reveal())


    output = MultiArray([t_blocks, 16], sgf2n)
    @for_range_opt_multithread(t_blocks, t_blocks)
    def _(i):
        input_block = Array(16,cgf2n)
        input_block = copy(temp_t[i])
        output_block = aes_encrypt_block(input_block, round_keys, cipher)
        output[i] = output_block
    
    temp_inner = Array(16, cgf2n)
    for i in range(16):
        temp_inner[i] = output[0][i].reveal()
    for i in range(1, t_blocks):
        for j in range(16):
            temp_inner[j] = temp_inner[j] + output[i][j].reveal()
    
    temp_inner[15] = temp_inner[15] & cgf2n(0xFC)
    # for i in range(16):
    #     print_ln('temp_inner[%s] = %s', i, temp_inner[i].reveal())

    temp = []
    for i in range(16):
        temp.append(temp_inner[i])
    tag = AES(temp)
    # for i in range(16):
    #     print_ln('tag[%s] = %s', i, tag[i].reveal())

    check = tag_check(tag, tag_expected, bit_decompose=lambda x: x.bit_decompose(8))
    return check.reveal(), message



"""
if BENCHMARK:
    import random
    import math
    random.seed(N)

    def random_bytes(n, type):
        return [type(random.randint(0,255), size=nparallel) for i in range(n)]

    # in the benchmark, we don't care about supplying correct ciphertext,tag pairs
    key = random_bytes(16, sgf2n)
    nonce = random_bytes(12, cgf2n)
    ciphertext = random_bytes(N, cgf2n)
    tag = random_bytes(16, cgf2n)
    start_timer(1)
    check, message = aes_obc_siv_128_decrypt(ciphertext, tag, key, nonce)
    stop_timer(1)
    print_ln('Tag: %s', check)
    print_ln("Message")
    print_ln('%s' * N, *[m.reveal() for m in message])
else:
    key = [sgf2n(x, size=nparallel) for x in conv("320db73158a35a255d051758e95ed4ab")]
    nonce = [sgf2n(x, size=nparallel) for x in conv("b2cdc69bb454110e82744121")]
    message = conv("67c6697351ff4aec29cdbaabf2fbe3467cc254f81be8e78d765a2e63339fc99a66")
    ciphertext = [cgf2n(x, size=nparallel) for x in conv("9d6490765381e7f2241218de5caeae3e7af6f4ee93f7ae3562051e5f088a43747f")]
    tag = [cgf2n(x, size=nparallel) for x in conv("ffa633b9d065d916bdee1d0ae8d3cd9e")]

    check, dec_mes = aes_obc_128_decrypt(ciphertext, tag, key, nonce)
    print_ln('Check tag = %s', check)
    for byte in dec_mes:
        print_ln("%s", byte.reveal())
"""