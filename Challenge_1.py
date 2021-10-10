import binascii as bicii
from Crypto.Util.strxor import strxor, strxor_c

# Challenge and result inputs to test against
Ch1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
Ch1Res = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
Ch2a = "1c0111001f010100061a024b53535009181c"
Ch2b = "686974207468652062756c6c277320657965"
Ch2Res = "746865206b696420646f6e277420706c6179"
Ch3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
Ch3Res = ('X', "Cooking MC's like a pound of bacon")
Ch4 = "Ch1_4.txt"
Ch4Res = ('5', 'Now that the party is jumping\n')
Ch5 = "Ch1_5.txt"
Ch5Res = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

# Weighed variables for Character Frequency tuning and selection
# BETA adjusts the percentage of the Character Frequency used in the resulting summation
BETA = 1.1

# Table based on 2.1 million characters and 380,703 words.
# Space character simulated with average of 'ETA'
CharFreqTable = {'A':0.0834, 'B':0.0154, 'C':0.0273,
                 'D':0.0414, 'E':0.1260, 'F':0.0203,
                 'G':0.0192, 'H':0.0611, 'I':0.0671,
                 'J':0.0023, 'K':0.0087, 'L':0.0424,
                 'M':0.0253, 'N':0.0680, 'O':0.0770,
                 'P':0.0166, 'Q':0.0009, 'R':0.0568,
                 'S':0.0611, 'T':0.0937, 'U':0.0234,
                 'V':0.0106, 'W':0.0234, 'X':0.0020,
                 'Y':0.0204, 'Z':0.0006, ' ':0.1009 }


# Takes Binary string and returns Base64 version
def Bin2Base64(temp):
    return bicii.b2a_base64(temp)

# Takes Binary string and returns hexidecimal version
def Bin2Hex(temp):
    return bicii.hexlify(temp)

# Takes Hex string and returns binary version
def Hex2Bin(temp):
    return bicii.unhexlify(temp)

# Takes String and returns binary version
def Str2Bin(temp):
    return temp.encode(encoding='latin_1')

# Inputs: A string, and a number
# Outputs: A string repeated to a certain length
def RepString(temp, num):
    return (temp * num)[0:num]

# Inputs: Two equal length strings in bytes
# Outputs: Bytearray decrypted in raw bytes
def DualBufferXOR(temp1,temp2):
    return strxor(temp1,temp2)

# Inputs: Byte/arrays and char as integer
# Outputs: Bytearray decrypted in raw bytes
def SingleByteXOR(temp, char):
    return strxor_c(temp, char)

# Takes the bytes and turns them into a string
# One char at a time to find the value in the char frequeny table
# Using BETA to weight the values further.
def ScoreLine(temp):
    score = 0
    string = bytes.decode(temp, 'latin_1').upper().rstrip('\n')
    for i in string:
        if i in CharFreqTable.keys():
            score += (BETA * CharFreqTable[i])
    return score

# Decrypt a file, line by line with SingleByteXOR
# Using Character Freqency Analysis, find suitable occurences
# Input : file name as a string, or single string
# Output: best result as a list
def DecryptCypherByte(fname):
    temp = [0.0, '', '', '']
    score = 0.0
    if fname.endswith('.txt'):
        with open(fname, 'r', encoding='latin_1') as fd:
            for line in fd:
                for i in range(0,256,1):
                    x = Hex2Bin(line.rstrip('\n'))
                    x = SingleByteXOR(x, i)
                    score = ScoreLine(x)
                    if score > temp[0]:
                        temp[0] = score
                        temp[1] = chr(i)
                        temp[2] = x
                        temp[3] = line
    else:
        for i in range(0,256,1):
            x = Hex2Bin(fname)
            x = SingleByteXOR(x, i)
            score = ScoreLine(x)
            if score > temp[0]:
                temp[0] = score
                temp[1] = chr(i)
                temp[2] = x
                temp[3] = fname        
    return temp

# Encrypt a file, line by line with a key using SingleByteXOR
# Input : file_name as a string, key as a string
# Output: Output_ + file_name with each encrypted line
def EncryptFileKey(ifname, key):
    ret = ''
    ofname = "Output_" + ifname
    with open(ifname, 'r', encoding='latin_1') as fd:
        temp = ""
        for line in fd:
            temp += line
        y = RepString(key, len(temp))
        x = Str2Bin(temp)
        y = Str2Bin(y)
        ret = DualBufferXOR(x,y)
    with open(ofname, 'w', encoding='latin_1') as fd:
        fd.write(Bin2Hex(ret)) 
    return "Written To File"
