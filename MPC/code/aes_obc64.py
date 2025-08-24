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


def aes_obc64_128_decrypt(c, tag_expected, k, nonce):
    assert len(k) == 16
    assert len(tag_expected) == 16
    nparallel = tag_expected[0].size
    assert len(nonce) == 12
    m_blocks = (len(c) + 15) // 16
    t_blocks = (len(c) + 11) // 12
    blcoks_num = 1 + m_blocks + t_blocks

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

    pad = [cgf2n(0, size=nparallel)] * (12 * t_blocks - len(c))

    a = MultiArray([blcoks_num, 16], cgf2n)
    iv_0 = incr_ctr_be_vec(regint(0), nparallel, 1)
    # Fill the first 4 bytes with iv_0 and the last 12 bytes with nonce => a[0...15]
    for i in range(4):
        a[0][i] = iv_0[0][i]
    for i in range(len(nonce)):
        a[0][i + 4] = nonce[i]
    

    m_ctrs = incr_ctr_be_vec(regint(1), nparallel, m_blocks)
    
    # Fill the first 4 bytes with m_ctrs and the last 12 bytes with nonce => a[16...16*(16*m_blocks+15)]
    for i in range(m_blocks):
        for j in range(4):
            a[i + 1][j] = m_ctrs[i][j]
        for j in range(len(nonce)):
            a[i + 1][4 + j] = nonce[j]



    t_ctrs = incr_ctr_be_vec(regint(2**31 + 1), nparallel, t_blocks)

    # Fill the first 4 bytes with t_ctrs and the last 12 bytes with c => a[16*(16*m_blocks+15)...]
    for i in range(t_blocks - 1):
        for j in range(4):
            a[m_blocks + 1 + i][j] = t_ctrs[i][j]
        for j in range(12):
            a[m_blocks + 1 + i][4 + j] = c[i * 12 + j]
    # Fill the last block
    for j in range(4):
        a[m_blocks + t_blocks][j] = t_ctrs[-1][j]
    for i in range(len(c)-12 * (t_blocks - 1)):
        a[m_blocks + t_blocks][i + 4] = c[12 * (t_blocks - 1) + i]
    for i in range(12 * t_blocks - len(c)):
        a[m_blocks + t_blocks][4 + len(c) - 12 * (t_blocks - 1) + i] = pad[i]
    # for i in range(blcoks_num):
    #     for j in range(16):
    #         print_ln('a[%s][%s] = %s', i, j, a[i][j].reveal())


    b = MultiArray([blcoks_num, 16], sgf2n)
    @for_range_opt_multithread(blcoks_num, blcoks_num)
    def _(i):
        input_block = Array(16,cgf2n)
        input_block = a[i]
        output_block = aes_encrypt_block(input_block, round_keys, cipher)
        
        # print(type(output_block))#list
        # print(type(output_block[0]))#sgf2n
        b[i] = output_block

    message = []
    for i in range(m_blocks):
        mblock = [c[i * 16 + j] + b[i + 1][j].reveal() for j in range(16) if i * 16 + j < len(c)]
        message.extend(mblock)
    # for j in range(len(message)):
    #     print_ln('message[%s] = %s', j, message[j].reveal())

    tag = []
    for i in range(16):
        tag.append(b[0][i])
    for i in range(t_blocks):
        tag = [a + b for a, b in zip(b[1 + m_blocks + i].reveal(), tag)]
    # for j in range(len(tag)):
    #     print_ln('tag[%s] = %s', j, tag[j].reveal())

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
    check, message = aes_obc_128_decrypt(ciphertext, tag, key, nonce)
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