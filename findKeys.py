import sys
import os
import bitcoin
import time
# Find key from image

# bytes to read at a time from file (4GB)
readlength=4*1024*1024*1024
#readlength=100
#magic = b"\x81\xD3\x02\x01\x01\x04\x20"
magic = b"\x04\x20"
magiclen = len(magic)
keylen = 32

private_key_file="private_keys"
target_addr = "1PUXsA9TXsTNkBqwz7P3YWsGq9piqe8rFt"

def find_keys(fname):
    keys = list()

    i=0

    # Get file size
    size = os.path.getsize(fname)

    with open(fname, "rb") as f:
        #Read one block at a time, length == readlength(10MB)
        while True:
            data = f.read(readlength)
            print(f"Process {100*(f.tell()-readlength)/size:.2f}%")

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
                    #print(f"{i}:", f"file ptr={f.tell()-readlength}", f"block ptr={pos}",
                    #     f" sum={f.tell()-readlength+pos}")
                    key_offset = pos + magiclen
                    # a key is cross the boundary, skip it and search it later
                    if (key_offset + keylen) >= readlength:
                        break
                    key_data = data[key_offset:key_offset + keylen]
                    keys.append(key_data)
                    i+=1
                    print(f" No. {i} key found, {100*(f.tell()-readlength)/size:.2f}%")

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

    return keys

def check_validate(src_f, dst_f):
    #open file and got all private key in a list
    with open(src_f, "r") as f:
        lines=f.readlines()

    keys=[]
    for line in lines:
        keys.append(line.strip())

    founded=[]

    total_num=len(keys)

    for (i, k) in enumerate(keys):
        #get raw priv key:
        decode_private_key = bitcoin.decode_privkey(k)
        #get compressed priv key:
        compressed_private_key = bitcoin.encode_privkey(decode_private_key, "hex_compressed")

        #get raw addr & compressed addr
        addr_raw = bitcoin.privkey_to_address(decode_private_key)
        addr_comp = bitcoin.privkey_to_address(compressed_private_key)

        if addr_raw == target_addr or addr_comp == target_addr:
            print(f"FOUND ONE!!!! PRIVATE KEY IS: {hex(decode_private_key)}")
            founded.append(hex(decode_private_key))


    with open(dst_f,"w") as f:
        for line in founded:
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
