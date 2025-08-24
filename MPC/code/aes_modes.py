from Compiler.library import *
from Compiler.types import *
from Programs.Source.testutils import import_path
from Programs.Source.utils import tag_check
from Programs.Source.aes_gf_long import Aes128
from Compiler.types import cgf2n, sgf2n, cint

def conv(x):
    return [int(x[i : i + 2], 16) for i in range(0, len(x), 2)]

def aes_ctr_dec(cipher, AES, counter, ciphertext):
    # key is embedded, counter and ciphertext is not

    # counter is big endian (bytewise)
    counter_bytes = [t.bit_decompose(8) for t in counter[12:]]
    counter_bytes = [sum((2**i * b for i,b in enumerate(bits))) for bits in counter_bytes]
    counter_block_res = cipher.SecretArrayEmbedd(counter[:12])

    # set MSbit of counter_block[15] to 1
    # tag_bits = tag[15].bit_decompose(7) + [1]
    # counter_block_res.append(ApplyBDEmbedding(tag_bits))

    n_blocks = len(ciphertext) // 16
    if len(ciphertext) % 16 != 0:
        n_blocks += 1
    ctr = regint(sum(2**(3-i) * b  for i,b in enumerate(counter_bytes)))
    # print_ln('Parsed ctr = %s', ctr)
    message = []
    m_ctr = 0

    for i in range(n_blocks):
        # set ctr
        ctr_bits = ((ctr + i) % 2**32).bit_decompose(32)
        ctr_cells = [sum([cgf2n(2**i, size=cipher.nparallel) * b for i,b in enumerate(ctr_bits[8*(3-j):8*(3-j)+8])]) for j in range(32//8)]
        counter_block =  list(counter_block_res) + cipher.SecretArrayEmbedd(ctr_cells)
        # print_embedded_buf(counter_block, "Counter input")
        mask = AES(counter_block)
        # print_embedded_buf(mask, "Counter output")
        for i in range(min(16,len(ciphertext)-m_ctr)):
            message.append(ciphertext[m_ctr] + cipher.InverseEmbedding(mask[i]))
            m_ctr += 1
    return message

# def digest(blocks, nonce):
#     sigma = cint(0)
#     for block in [nonce] + blocks:
#         bits = [cint(b) for cell in block for b in Aes128(1).bit_decompose_embedding(cell, range(8))]
#         element = cint(0)
#         for i, b in enumerate(bits):
#             element += b * (cint(1) << i)
#         sigma += element
    
#     hash = sigma.digest(16)
#     bits = hash.bit_decompose()
#     block = []
#     for i in range(16):
#         byte_bits = bits[8*i:8*i+8]
#         byte = cgf2n(0)
#         for j, bit in enumerate(byte_bits):
#             byte += cgf2n(bit.reveal()) << j
#         block.append(byte)
#     return block

def pack(blocks, base_type):
    n = len(blocks)
    if n == 1:
        return blocks[0]
    return [base_type([blocks[j][i] for j in range(n)], size=n) for i in range(len(blocks[0]))]

def unpack(block):
    n = len(block[0])
    blocks = [[block[j][i] for j in range(len(block))] for i in range(n)]
    return blocks


def pmac(message_blocks, key):
    """
    PMAC implementation over AES-128 in GF(2^128)
    Input:
        message_blocks: list of blocks (each block is a list of 16 sgf2n elements)
        key: list of 16 sgf2n values
    Output:
        tag: list of 16 sgf2n values
    """
    n_blocks = len(message_blocks)
    assert all(len(block) == 16 for block in message_blocks)

    cipher = Aes128(1)
    expanded_key = cipher.expandAESKey(key)

    # Compute L = AES(key, 0^128)
    zero_block = [sgf2n(0)] * 16
    L = cipher.encrypt_without_key_schedule_no_emb(expanded_key)(zero_block)

    # Helper: GF(2^128) multiplication by x (doubling)
    def double(block):
        res = []
        carry = sgf2n(0)
        for i in reversed(range(16)):
            b = block[i]
            bits = b.bit_decompose(8)
            msb = bits[7]
            new_byte = (b + b) + carry  # left shift by 1
            carry = msb  # MSB of byte becomes carry
            res.insert(0, new_byte)
        res[-1] ^= sgf2n(0x87) * carry  # Reduction polynomial in GF(2^128)
        return res

    # Precompute mask for each block: L, L·x, L·x², ..., L·x^n
    masks = [L]
    for _ in range(1, n_blocks):
        masks.append(double(masks[-1]))

    # PMAC accumulation
    acc = [sgf2n(0)] * 16
    for i in range(n_blocks - 1):
        m_i = message_blocks[i]
        m_masked = [m_i[j] ^ masks[i][j] for j in range(16)]
        cipher_out = cipher.encrypt_without_key_schedule_no_emb(expanded_key)(m_masked)
        acc = [acc[j] ^ cipher_out[j] for j in range(16)]

    # Final block
    last_block = message_blocks[-1]
    is_full = len(last_block) == 16

    if is_full:
        last_mask = double(masks[n_blocks - 1])  # L·x^n
        final_block = [last_block[j] ^ last_mask[j] for j in range(16)]
    else:
        padded = last_block + [sgf2n(0)] * (16 - len(last_block))
        last_mask = masks[n_blocks - 1]  # L·x^(n-1)
        padded[ len(last_block) ] ^= sgf2n(0x80)  # Padding with 1
        final_block = [padded[j] ^ last_mask[j] for j in range(16)]

    cipher_out = cipher.encrypt_without_key_schedule_no_emb(expanded_key)(final_block)
    acc = [acc[j] ^ cipher_out[j] for j in range(16)]

    # Final AES(key, acc)
    tag = cipher.encrypt_without_key_schedule_no_emb(expanded_key)(acc)
    return tag


def enc_pmac_aes128(message, key, nonce):
    assert len(message) % 16 == 0
    assert len(nonce) == 12, f'{len(nonce)}: {nonce}'
    nparallel = key[0].size

    cipher = Aes128(1)
    expanded_key = cipher.expandAESKey(key)
    AES = cipher.encrypt_without_key_schedule_no_emb(expanded_key)

    ctr_init = nonce + [cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0x1, size=nparallel)]
    ciphertext = aes_ctr_dec(cipher, AES, ctr_init, message)
    ciphertext_revealed = [c.reveal() for c in ciphertext]

    ciphertext_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    tag = pmac(ciphertext_blocks, key)
    return ciphertext_revealed, [t.reveal() for t in tag]

def dec_pmac_aes128(ciphertext, tag, key, nonce):
    assert len(ciphertext) % 16 == 0
    assert len(nonce) == 12, f'{len(nonce)}: {nonce}'
    nparallel = tag[0].size

    cipher = Aes128(1)
    expanded_key = cipher.expandAESKey(key)
    AES = cipher.encrypt_without_key_schedule_no_emb(expanded_key)

    ciphertext_secret = [sgf2n(c) for c in ciphertext]
    ctr_init = nonce + [cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0x1, size=nparallel)]
    message = aes_ctr_dec(cipher, AES, ctr_init, ciphertext_secret)
    message_revealed = [m.reveal() for m in message]

    ciphertext_blocks = [ciphertext_secret[i:i+16] for i in range(0, len(ciphertext_secret), 16)]
    computed_tag = pmac(ciphertext_blocks, key)
    check = tag_check(tag, computed_tag, lambda x: Aes128(1).bit_decompose_embedding(x, range(8)))
    return check.reveal(), message_revealed

# def enc_htmac_aes128(message, key, nonce):
#     assert len(message) % 16 == 0
#     assert len(nonce) == 12, f'{len(nonce)}: {nonce}'
#     assert len(key) == 16
#     nparallel = key[0].size

#     cipher = Aes128(1)
#     expanded_key = cipher.expandAESKey(key)
#     AES = cipher.encrypt_without_key_schedule_no_emb(expanded_key)

#     ctr_init = nonce + [cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0x1, size=nparallel)]
#     ciphertext = aes_ctr_dec(cipher, AES, ctr_init, message)

#     # group into blocks
#     ciphertext_blocks = [ciphertext[16*i:16*i+16] for i in range(len(message) // 16)]
#     h = digest(ciphertext_blocks, nonce)
    
#     tag = AES(h)
#     return ciphertext, [cell.reveal() for cell in tag]

# def dec_htmac_aes128(ciphertext, tag, key, nonce):
#     assert len(ciphertext) % 16 == 0
#     assert len(key) == 16
#     nparallel = key[0].size
#     assert len(nonce) == 12
    
#     cipher = Aes128(1)
#     expanded_key = cipher.expandAESKey(key)
#     AES = cipher.encrypt_without_key_schedule_no_emb(expanded_key)

#     ctr_init = nonce + [cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0, size=nparallel), cgf2n(0x1, size=nparallel)]
#     message = aes_ctr_dec(cipher, AES, ctr_init, ciphertext)

#     # group into blocks
#     ciphertext_blocks = [ciphertext[16*i:16*i+16] for i in range(len(message) // 16)]
#     h = digest(ciphertext_blocks, nonce)

#     computed_tag = AES(h)
#     check = tag_check(tag, computed_tag, lambda x: cipher.bit_decompose_embedding(x, range(8)))
#     return check.reveal(), message