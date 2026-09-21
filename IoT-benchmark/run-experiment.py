import serial
import os
import numpy as np
import argparse

def check_file_type(filepath):
    lower_path = filepath.lower()
    return ('pobc' in lower_path) and ('siv' in lower_path)

def main():
    parser = argparse.ArgumentParser(description='Run experiment on connected microcontroller')
    parser.add_argument('--samples', dest='samplepath', required=True, type=str, help='Path to file containing testvector samples')
    parser.add_argument('-o', dest='output', type=str, required=True, help='Path to output file')
    parser.add_argument('--cyclecounts', dest='n_cyclecounts', required=False, type=int, help='Nr of expected cycle counts returned by the controller. Defaults to 1', default=1)
    args = parser.parse_args()
    ser = serial.Serial('/dev/ttyUSB0', 115200)
    if check_file_type(args.samplepath):
        print("Running POBC+SIV version")
        HEADER = b'\x00\xff\x00'
        def listen(ser):
            if ser.in_waiting > 0:
                print(f'[DEVICE] {ser.read(ser.in_waiting)}')
        def benchmark_testvec(ser, n_cyclecounts, key, nonce, message, ciphertext, tag):
            listen(ser)
            ser.reset_input_buffer()
            print(f'sending header {HEADER.hex()}')
            ser.write(HEADER)
            listen(ser)
            message_len = len(message).to_bytes(2, byteorder='little')
            print(f'Sending mlen {message_len.hex()}')
            ser.write(message_len)
            print(f'Sending message {message.hex()}')
            ser.write(message)
            print(f'Sending key {key.hex()}')
            ser.write(key)
            ser.flush()
            cycle_counts = []
            for i in range(n_cyclecounts):
                cyclecount = ser.readline().decode("utf-8").strip()
                try:
                    cycle_counts.append(int(cyclecount))
                except:
                    print(cyclecount)
                    raise "something went wrong!"
            received_ciphertext = ser.read(len(ciphertext))
            print(f'[DEVICE] {received_ciphertext.hex()}')
            if len(tag) > 0:
                received_tag = ser.read(len(tag))
                print(f'[DEVICE] {received_tag.hex()}')
            return cycle_counts
        def load_testvecs(path):
            with open(path, 'r') as fp:
                lines = fp.readlines()
            vecs = []
            for line in lines:
                parts = line.split(' ')
                assert len(parts) == 5
                key = bytes.fromhex(parts[0])
                nonce = bytes.fromhex(parts[1])
                message = bytes.fromhex(parts[2])
                ciphertext = bytes.fromhex(parts[3])
                tag = bytes.fromhex(parts[4])
                vecs.append((key, nonce, message, ciphertext, tag))
            return vecs
    else:
        print("Running original version")
        HEADER = b'\x00\xff\x00'
        def listen(ser):
            if ser.in_waiting > 0:
                print(f'[DEVICE] {ser.read(ser.in_waiting)}')
        def benchmark_testvec(ser, n_cyclecounts, key, nonce, message, ciphertext, tag):
            listen(ser)
            ser.reset_input_buffer()
            print(f'sending header {HEADER.hex()}')
            ser.write(HEADER)
            listen(ser)
            message_len = len(message).to_bytes(2, byteorder='little')
            print(f'Sending mlen {message_len.hex()}')
            ser.write(message_len)
            print(f'Sending message {message.hex()}')
            ser.write(message)
            print(f'Sending key {key.hex()}')
            ser.write(key)
            print(f'Sending nonce {nonce.hex()}')
            ser.write(nonce)
            ser.flush()
            cycle_counts = []
            for i in range(n_cyclecounts):
                cyclecount = ser.readline().decode("utf-8").strip()
                try:
                    cycle_counts.append(int(cyclecount))
                except:
                    print(cyclecount)
                    raise "something went wrong!"
            received_ciphertext = ser.read(len(ciphertext))
            print(f'[DEVICE] {received_ciphertext.hex()}')
            if len(tag) > 0:
                received_tag = ser.read(len(tag))
                print(f'[DEVICE] {received_tag.hex()}')
            return cycle_counts
        def load_testvecs(path):
            with open(path, 'r') as fp:
                lines = fp.readlines()
            vecs = []
            for line in lines:
                parts = line.split(' ')
                assert len(parts) == 5
                key = bytes.fromhex(parts[0])
                nonce = bytes.fromhex(parts[1])
                message = bytes.fromhex(parts[2])
                ciphertext = bytes.fromhex(parts[3])
                tag = bytes.fromhex(parts[4])
                vecs.append((key, nonce, message, ciphertext, tag))
            return vecs
    testvecs = load_testvecs(args.samplepath)
    cnts = []
    for sample in testvecs:
        cnt = benchmark_testvec(ser, args.n_cyclecounts, *sample)
        cnts.append(cnt)
    print(f'Avg = {np.average(cnts)}, std={np.std(cnts)}')
    print(f'Writing results to {args.output}')
    with open(args.output, 'w') as fp:
        for cnt in cnts:
            fp.write(f'{" ".join(map(str, cnt))}\n')

if __name__ == '__main__':
    main()