import binascii as bicii
from Crypto.Util.strxor import strxor, strxor_c

#*******************************************************************************
# START VARIABLES     **********************************************************

# Table based on text from 2.1 million characters and 380,703 words.
# Space character simulated with average of characters 'ETA'
CharFreqTable = {'A':0.0834, 'B':0.0154, 'C':0.0273,
                 'D':0.0414, 'E':0.1260, 'F':0.0203,
                 'G':0.0192, 'H':0.0611, 'I':0.0671,
                 'J':0.0023, 'K':0.0087, 'L':0.0424,
                 'M':0.0253, 'N':0.0680, 'O':0.0770,
                 'P':0.0166, 'Q':0.0009, 'R':0.0568,
                 'S':0.0611, 'T':0.0937, 'U':0.0234,
                 'V':0.0106, 'W':0.0234, 'X':0.0020,
                 'Y':0.0204, 'Z':0.0006, ' ':0.1009 }

# BETA adjusts the % of the Character Frequency used in the resulting summation
# of ScoreLine.
BETA = 1.1

# END VARIABLES       **********************************************************
#*******************************************************************************

#*******************************************************************************
# START BASE FUNCTIONS      ****************************************************

# Takes Byte string and returns a Base64 string
def Byt2Base64(temp):
    return bicii.b2a_base64(temp)

# Takes Byte string and returns a Bit string
def Byt2Bit(temp):
    res = ""
    for i in temp:
        res += bin(i).lstrip('0b')
    return res

# Takes Byte string and returns a Hex string
def Byt2Hex(temp):
    return bicii.hexlify(temp)

# Takes Byte string and returns a ASCII string
def Byt2Str(temp):
    return temp.decode('utf-8')

# Takes Base64 string and returns a Byte string
def Base642Byt(temp):
    return bicii.a2b_base64(temp)

# Takes Base64 string and returns a ASCII string
def Base642Str(temp):
    return bicii.b2a_qp(temp)

# Takes Hex string and returns a Byte string
def Hex2Byt(temp):
    return bicii.unhexlify(temp)

# Takes String and returns a Byte string
def Str2Byt(temp):
    return temp.encode(encoding='latin_1')

# Inputs: A string, and a number
# Outputs: a string repeated to a certain length
def RepString(temp, num):
    return (temp * num)[0:num]

# Inputs: a byte array, and desired total padding length
# Outputs: a byte array padded to the desired length
def PadByteString(temp, num):
    x = num - len(temp)
    result = temp + bytes(range(x))

    return result

# Inputs: two equal length strings in bytes
# Outputs: bytearray decrypted in raw bytes
def DualBufferXOR(temp1,temp2):
    return strxor(temp1,temp2)

# Inputs: Byte/arrays and char as integer
# Outputs: bytearray decrypted in raw bytes
def SingleByteXOR(temp, char):
    return strxor_c(temp, char)

# Turns temp into a decoded string. Then each char at a time, finds the 
# value in the CharFreqTable and add's it to score. Using BETA to weight the
# values further if tougher encryption is encountered.
def ScoreLine(temp):
    score = 0
    string = bytes.decode(temp, 'latin_1').upper().rstrip('\n')
    for i in string:
        if i in CharFreqTable.keys():
            score += (BETA * CharFreqTable[i])
    return score

# Takes two input strings of the same length and XOR's the result.  The result
# counts the number of 1's in the result or hamming distance, and returns it.
# Inputs: Byte/arrays for XOR'ing
# Outputs: Count of Hamming Distance
def HammingDistance(temp1,temp2):
    if isinstance(temp1, str):
        temp1 = Str2Byt(temp1)
        temp2 = Str2Byt(temp2)
    res = DualBufferXOR(temp1,temp2)
    return Byt2Bit(res).count('1')

# END BASE FUNCTIONS      ******************************************************
#*******************************************************************************