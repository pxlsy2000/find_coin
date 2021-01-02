import sys
import os
import bitcoin
import time
from tqdm import tqdm
import multiprocessing as mp
from tqdm.contrib.concurrent import process_map  # or thread_map

# Find key from image Based on a magic number

# bytes to read at a time from file (4GB)
readlength=4*1024*1024*1024
#magic = b"\x81\xD3\x02\x01\x01\x04\x20"
magic = b"\x04\x20"
magiclen = len(magic)
keylen = 32

private_key_file="private_keys"
target_addr = "1PUXsA9TXsTNkBqwz7P3YWsGq9piqe8rFt"  #True addr
#target_addr = "1CJ9UKggqH8AkSwLzgh9eC53s2r1k7pAxB" # Test addr in test wallet.dat
#target_addr = "1ErQ7tRuZBCw4TLDhGizA6dK8nmDwmN8vH" # Test addr in images


def find_keys(fname):
    keys = list()

    # Get file size
    file_size = os.path.getsize(fname)

    founded_num=0
    pbar = tqdm(total=file_size)
    pbar.set_description(f"Scanning private keys... Founded {founded_num}")
    with open(fname, "rb") as f:
        #Read one block at a time, length == readlength(10MB)
        while True:
            data = f.read(readlength)

            if not data:
                break

            #process data here, when loop break, all data will be processed
            pos=0
            #look in this block for keys
            while True:
                # find the magic number
                pos = data.find(magic, pos)

                # No luck in this block
                if pos == -1:
                    break

                # Luck found in this block
                else:
                    key_offset = pos + magiclen
                    # a key is cross the boundary, skip it and search it later
                    if (key_offset + keylen) >= readlength:
                        break
                    key_data = data[key_offset:key_offset + keylen]
                    keys.append(key_data)
                    founded_num+=1

                    # add one byte here, maybe we could find more
                    # possiable key
                    pos += 1

                # File pointer operation
                # if current block size == readlength,
                # which means it's not the end of this file (maybe)
            if len(data) == readlength:
                # Make sure we didn't miss any keys that
                # at the boundary of the blocks
                f.seek(f.tell() - (32 + magiclen))
                pbar.update(readlength-(32+magiclen))
            else:
                pbar.update(len(data))

            pbar.set_description(f"Scanning private keys... Founded {founded_num}")

    pbar.close()
    return keys

def __check_valid(k):
    #get raw priv key:
    decode_private_key = bitcoin.decode_privkey(k)
    if decode_private_key >= bitcoin.N:
        return None
    #get compressed priv key:
    compressed_private_key = bitcoin.encode_privkey(decode_private_key, "hex_compressed")

    #get raw addr & compressed addr
    addr_raw = bitcoin.privkey_to_address(decode_private_key)
    addr_comp = bitcoin.privkey_to_address(compressed_private_key)

    if addr_raw == target_addr or addr_comp == target_addr:
        print(f"FOUND ONE!!!! PRIVATE KEY IS: {hex(decode_private_key)}")
        return hex(decode_private_key)


def check_validate(src_f, dst_f):
    #open file and got all private key in a list
    with open(src_f, "r") as f:
        lines=f.readlines()

    keys=[]
    for line in lines:
        keys.append(line.strip())

    # Using tqdm parallel method to do this
    chunk_size = (len(keys)//6)//10

    founded=process_map(__check_valid, keys, chunksize=chunk_size, max_workers=mp.cpu_count())

    with open(dst_f,"w") as f:
        for line in founded:
            if(line!=None):
                f.write(line)
                f.write("\n")


def main():
    if len(sys.argv) != 2:
        print("./{0} <filename>".format(sys.argv[0]))
        exit()

    # gave a unique privkey filename incase override
    pkey_file = private_key_file + time.strftime("_%Y_%m_%d_%H_%M_%S",time.localtime())
    result_file = "FOUNDED" + time.strftime("_%Y_%m_%d_%H_%M_%S",time.localtime())

    keys = find_keys(sys.argv[1])
    with open(pkey_file, "w") as f:
        for key in keys:
            f.write(key.hex())
            f.write("\n")

    print("FIND ALL PRIVATE_KEY IS DONE!! start check if there is one with money")

    check_validate(pkey_file, result_file)

if __name__ == "__main__":
    main()
