import Base_Functions as bf
import itertools as itt



#*******************************************************************************
# START MAJOR FUNCTIONS      ***************************************************

# Decrypt a file by converting each line to it's binary representation. Using 
# Character Freqency Analysis, find suitable decodings to update highest score.
# Input : file name as a string, or single string
# Output: best result as a list
def DecryptCypherByte(ifname):
    temp = [0.0, '', '', '']
    score = 0.0
    if ifname.endswith('.txt'):
        with open(ifname, 'r', encoding='latin_1') as fd:
            for line in fd:
                for i in range(0,256,1):
                    x = bf.Hex2Bin(line.rstrip('\n'))
                    x = bf.SingleByteXOR(x, i)
                    score = bf.ScoreLine(x)
                    if score > temp[0]:
                        temp[0] = score
                        temp[1] = chr(i)
                        temp[2] = x
                        temp[3] = line
    else:
        for i in range(0,256,1):
            x = bf.Hex2Bin(ifname)
            x = bf.SingleByteXOR(x, i)
            score = bf.ScoreLine(x)
            if score > temp[0]:
                temp[0] = score
                temp[1] = chr(i)
                temp[2] = x
                temp[3] = ifname        
    return temp

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
        x = bf.Str2Bin(temp)
        y = bf.Str2Bin(y)
        ret = bf.DualBufferXOR(x,y)
    with open("Output_" + ifname, 'wb') as fd:
        fd.write(bf.Bin2Hex(ret)) 
    return "Written To File"

# Takes two input strings of the same length and XOR's the result.  The result
# counts the number of 1's in the result or hamming distance, and returns it.
# Inputs: Byte/arrays for XOR'ing
# Outputs: Count of Hamming Distance
def HammingDistance(temp1,temp2):
    a = bf.Str2Bin(temp1)
    b = bf.Str2Bin(temp2)
    res = bf.DualBufferXOR(a,b)
    return bf.Bin2Bit(res).count('1')

# To break a repeating key cipher, find the lowest normalized (average) score
# using it's hamming distance to find a key length.  Break the cypher text into 
# key length blocks, treat each column as a cypher text row and decrypt using 
# the byte cypher process and char frequency to find the key for each row; which
# should provide the key.
# Inputs: provide file_name and a key length option; default is 40
# Outputs: Return  calculated key length, and highest frequency chars associatd
def BreakRepKeyXOR(ifname, lo=2, hi=40, st=4):
    temp = ''
    with open(ifname, 'r') as fd:
        for line in fd:
            temp += line.rstrip('\n')
    temp = bf.Base642Bin(temp)
    result = {}
    for i in range(lo,hi+1):
        chunks = [temp[j:j + i] for j in range(0, len(temp), i)][0:st]
        hd = 0
        for x,y in itt.combinations(chunks,2):
            hd += bf.DualBufferXOR(x,y)
        hd /= 6
        result[i] = hd/i
    pk = sorted(result, key=result.get)[:3]
    ptexts = []
    for k in pk:
        key = b''
        for l in range(k):
            block = b''
            for m in range(l, len(temp), k):
                block += bytes([temp[m]])
            key += bf.SingleByteXOR(block, int(key))
        print(key)

             
    return temp

# END MAJOR FUNCTIONS      *****************************************************
#*******************************************************************************
