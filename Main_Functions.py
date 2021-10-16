import Base_Functions as bf
import Major_Functions as mf

# ------------------------------------------------------------------------------
def Sec1_Ch1():
    Ch1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    Ch1Res = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = ""
    print("Section 1 : Challenge 1 \n")
    print(Ch1)
    temp = bf.Hex2Byt(Ch1)
    temp = bf.Byt2Base64(temp)
    result = bf.Base642Str(temp)
    print("Ans: '{}' ".format(result))
    print("Key: 'b'{}' ".format(Ch1Res))

    return
# ------------------------------------------------------------------------------
def Sec1_Ch2():
    print("Section 1 : Challenge 2 \n")
    Ch2a = "1c0111001f010100061a024b53535009181c"
    Ch2b = "686974207468652062756c6c277320657965"
    Ch2Res = "746865206b696420646f6e277420706c6179"
    temp1 = bf.Hex2Byt(Ch2a)
    temp2 = bf.Hex2Byt(Ch2b)
    result = bf.DualBufferXOR(temp1,temp2)
    result = bf.Byt2Hex(result)
    print("Ans: '{}' ".format(result))
    print("Key: 'b'{}' ".format(Ch2Res))

    return
# ------------------------------------------------------------------------------
def Sec1_Ch3():
    Ch3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    Ch3Res = ('X', "Cooking MC's like a pound of bacon")
    print("Section 1 : Challenge 3 \n")
    print(Ch3)
    result = mf.BreakCypherHex(Ch3)
    print("Ans: '{}' ".format(result))
    print("Key: 'b'{}' ".format(Ch3Res))   


    return
# ------------------------------------------------------------------------------
def Sec1_Ch4():
    Ch4 = "Ch1_4.txt"
    Ch4Res = ('5', 'Now that the party is jumping\n')
    print("Section 1 : Challenge 4 \n")
    result = mf.BreakCypherHex(Ch4)

    print("Ans: '{}' ".format(result))
    print("Key: 'b'{}' ".format(Ch4Res))
    
    return
# ------------------------------------------------------------------------------
def Sec1_Ch5():
    Ch5 = "Ch1_5.txt"
    Ch5k = "ICE"
    Ch5Res = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    print("Section 1 : Challenge 5 \n")
    result = mf.EncryptFileKey(Ch5, Ch5k)

    print("Ans: '{}' ".format(result))
    print("Key: 'b'{}' ".format(Ch5Res))

    return
# ------------------------------------------------------------------------------
def Sec1_Ch6():
    Ch6 = "Ch1_6.txt"
    hcA = 'this is a test'
    hcB = 'wokka wokka!!!' 

    hd_test = mf.HammingDistance(hcA,hcB)
    print("Hamming distance: {} \n".format(hd_test))

    temp = ''
    plain_text = ''
    with open(Ch6, 'r') as fd:
        for line in fd:
            temp += line.rstrip('\n')
    temp = bf.Base642Byt(temp)
    key = mf.BreakRepKeyXOR(temp)[1]
    print("Key Found to be: '{}' \n".format(key))
    key = bf.RepString(key, len(temp))
    key = bf.Str2Byt(key)

    plain_text = bf.DualBufferXOR(temp, key)
    print(plain_text)
    return
# ------------------------------------------------------------------------------
