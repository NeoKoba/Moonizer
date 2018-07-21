import argparse
import binascii
from Crypto.Cipher import AES
import base91
import base64
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))




'''def rocket64():
    cat = input("Input text \n")
    cat = binascii.b2a_base64(cat.encode('utf-8'))
    print(cat)
    dog = b""
    for x in range(1,58):
        cat = binascii.b2a_base64(cat)
        print(x)
    print(cat)
    for x in range(1,58):
        cat = binascii.a2b_base64(cat)
    dog = binascii.a2b_base64(cat)
    print("decrypted:  " + dog)'''



def Moonizer(path,pss, pss2, salt,output):
    goodpss = pss.encode("utf-8")
    goodpss2 = pss2.encode("utf8")
    urfile = open(path, "rb+")
    tmp = urfile.read()
    for x in range(1, salt):
        goodpss = binascii.b2a_base64(goodpss)
        goodpss = base91.encode(goodpss)
    for x in range(1, salt):
        goodpss2 = binascii.b2a_base64(goodpss2)
        goodpss2 = base91.encode(goodpss2)
    verygoodpss = ""
    verygoodpss2 = ""
    for x in range(1, 33):
        verygoodpss += goodpss[int(int(len(goodpss) / 8) / int(x))]
    for x in range(1, 33):
        verygoodpss2 += goodpss2[int(int(len(goodpss2) / 8) / int(x))]

    cipher = AESCipher(verygoodpss)
    encrypted = cipher.encrypt(tmp)
    cipher2 = AESCipher(verygoodpss2)
    double_encrypted = cipher2.encrypt(encrypted)
    kek = str(double_encrypted)
    #print double_encrypted
    #print encrypted
    #print cipher.decrypt(cipher2.decrypt(double_encrypted))
    outfile = open(output, "wb")
    #outfile.write("")
    outfile.write(kek)
   # print "output + " + outfile.read()
    #print double_encrypted
    outfile.close()
    urfile.close()
    print "Done"

def Demoonizer(path,pss, pss2, salt,output):
    goodpss = pss.encode("utf-8")
    goodpss2 = pss2.encode("utf8")
    urfile = open(path, "rb+")
    tmp = urfile.read()
    for x in range(1, salt):
        goodpss = binascii.b2a_base64(goodpss)
        goodpss = base91.encode(goodpss)
    for x in range(1, salt):
        goodpss2 = binascii.b2a_base64(goodpss2)
        goodpss2 = base91.encode(goodpss2)
    verygoodpss = ""
    verygoodpss2 = ""
    for x in range(1, 33):
        verygoodpss += goodpss[int(int(len(goodpss) / 8) / int(x))]
    for x in range(1, 33):
        verygoodpss2 += goodpss2[int(int(len(goodpss2) / 8) / int(x))]
    cipher = AESCipher(verygoodpss2)
    cipher2 = AESCipher(verygoodpss)
    encrypted = cipher.decrypt(tmp)
    double_encrypted = cipher2.decrypt(encrypted)
    kek = str(double_encrypted)
    #print "The encrypted ===>>  " + str(double_encrypted)
    #print encrypted
    outfile = open(output, "wb")
    outfile.write(str(kek))
    #print "output final + " + outfile.read()
    #print double_encrypted
    outfile.close()
    urfile.close()
    print "Done"

def parsering():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e",'--encrypt',help="encrypt the file", action='store_true')
    parser.add_argument("-d",'--decrypt',help="decrypt the file", action='store_true')
    parser.add_argument("-i",'--input',help="input file")
    parser.add_argument("-o",'--output',help="output file, needed in decryption but also can be taken in encryption if there is no output file, a .moon file will be generated in the input file directory")
    parser.add_argument("-p1",'--pass1',help="first password")
    parser.add_argument("-p2",'--pass2', help="second password")
    parser.add_argument("-s",'--salt', help="salt ( a number from 1 to 20 that will do the encryption even more secure )")
    args = vars(parser.parse_args())
    if(args['encrypt']):
        if(args['input']!=None and args['pass1']!=None and args['pass2']!=None and args['salt']!=None):
            if(args['output']!=None):
                Moonizer(args['input'], args['pass1'], args['pass2'], int(args['salt']), args['output'])
            else:
                out = args['input'][:str(args['input']).find(".")] + ".moon"
                print "output file ==>> " + out
                Moonizer(args['input'], args['pass1'], args['pass2'], int(args['salt']), out)
        else:
            print "Not enough arguments, please make sure you specified at least the input, password1, password2 and salt"
    if(args['decrypt']):
        if (args['input']!=None and args['pass1']!=None and args['pass2']!=None and args['salt']!=None and args['output']!=None):
            Demoonizer(args['input'], args['pass1'], args['pass2'], int(args['salt']), args['output'])
        else:
            print "Not enough arguments, please make sure you specified at least the input, password1, password2 and salt"
    else:
        parser.print_usage()


parsering()
#Moonizer(r"C:\MOON\kek.jpg","use only english lol", "something other",12, r"C:\MOON\kek.moon")
#Demoonizer(r"C:\MOON\xd2.jpg","use only english lol", "something other",12)