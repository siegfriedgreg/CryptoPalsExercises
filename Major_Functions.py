import Base_Functions as bf
import itertools as itt
import math 
from Crypto.Cipher import AES as aes

#*******************************************************************************
# START MAJOR FUNCTIONS      ***************************************************

# Encrypt a file by concatinating all lines, create a repeating key string to
# match, and XOR; then open output file and write encrypted text.
# Input : file_name as a string, key as a string
# Output: Output_ + file_name with each encrypted line
def EncryptFileKey(ifname, key):
    ret = ''
    with open(ifname, 'r', encoding='latin_1') as fd:
        temp = ""
        for line in fd:
            temp += line
        y = bf.RepString(key, len(temp))
        x = bf.Str2Byt(temp)
        y = bf.Str2Byt(y)
        ret = bf.DualBufferXOR(x,y)
    with open("Output_" + ifname, 'wb') as fd:
        fd.write(bf.Byt2Hex(ret)) 
    return bf.Byt2Hex(ret)

# Decrypt a file by converting each line to it's binary representation. Using 
# Character Freqency Analysis, find suitable decodings to update highest score.
# Input : file name as a string, or single string in byte format
# Output: best result as a list
def BreakCypherByte(ifname):
    temp = [0.0, '']
    score = 0.0
    for i in range(0,256,1):
        x = bf.SingleByteXOR(ifname, i)
        score = bf.ScoreLine(x)
        if score > temp[0]:
            temp[0] = score
            temp[1] = chr(i)    
    return temp

# Decrypt a file by converting each line to it's binary representation. Using 
# Character Freqency Analysis, find suitable decodings to update highest score.
# Input : file name as a string, or single string in hex format
# Output: best result as a list
def BreakCypherHex(ifname):
    temp = [0.0, '', '', '']
    score = 0.0
    if ifname.endswith('.txt'):
        with open(ifname, 'r', encoding='latin_1') as fd:
            for line in fd:
                for i in range(0,256,1):
                    x = bf.Hex2Byt(line.rstrip('\n'))
                    x = bf.SingleByteXOR(x, i)
                    score = bf.ScoreLine(x)
                    if score > temp[0]:
                        temp[0] = score
                        temp[1] = chr(i)
                        temp[2] = x
                        temp[3] = line
    else:
        for i in range(0,256,1):
            x = bf.Hex2Byt(ifname)
            x = bf.SingleByteXOR(x, i)
            score = bf.ScoreLine(x)
            if score > temp[0]:
                temp[0] = score
                temp[1] = chr(i)
                temp[2] = x
                temp[3] = ifname        
    return temp

# To break a repeating key cipher, find the lowest normalized (average) score
# using it's hamming distance to find a key length.  Break the cypher text into 
# key length blocks, treat each column as a cypher text row and decrypt using 
# the byte cypher process and char frequency to find the key for each row; which
# should provide the key.
# Inputs: provide file_name in bytes, key_length lo and hi, 
# Outputs: return  calculated key length, and highest frequency chars associatd
def BreakRepKeyXOR(ifname, lo=2, hi=40, st=4):
    result = {}
    for i in range(lo,hi+1):
        chunks = [ifname[j:j + i] for j in range(0, len(ifname), i)][0:st]
        hd = 0
        for x,y in itt.combinations(chunks,2):
            hd += bf.HammingDistance(x,y)
        hd /= (math.comb(st,2))
        result[i] = hd/i
    pkey = sorted(result, key=result.get)[0:1]
    ptext = []
    for k in pkey:
        key = []
        for i in range(k):
            block = b''
            for j in range(i, len(ifname), k):
                block += bytes([ifname[j]])
            key += BreakCypherByte(block)[1]    
        ptext = (k, "".join(key)) 
    return ptext

# To decrypt an AES_128bit_ECB cypher, pass a 16-byte key in byte format to 
# create a cypher key. Using the cypher key to decrypt and return the text.
# Inputs: provide a file_name and key in bytes/array format
# Outputs: returns the decrypted text in bytes/array
def DecryptAES128_ECB(ifname, key):
    ckey = aes.new(key, aes.MODE_ECB)

    return ckey.decrypt(ifname)

# To detect AES_128_ECB encryption, break the text up into 16 byte blocks, in
# hexidecimal. Find the number of repeated blocks in each text, the one with
# the most repetitions is most like the culprit.
# Inputs: provide file_name in hexidecimal, and a key size options. def = 16
# Outputs: returns line with the highest count of repeated blocks.
def DetectAES128_ECB(ifname, key=16):
    score = {}
    for i in range(0, len(ifname), key):
        x = bf.Byt2Str(ifname[i:i+key:1])
        if x in score:
            score[x] += 1
        else:
            score[x] = 0
    
    return sum(score.values())

# END MAJOR FUNCTIONS      *****************************************************
#*******************************************************************************
