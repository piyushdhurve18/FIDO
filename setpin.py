####################
#   [Status]
#      Works
#
#   [Author]
#     REDPATH
#
#   [Use]
#      python3 setpin.py
#            or
#      python3 setpin.py --curl on
#
#   [Intent]
#    The intent of this code is to show all the APDUs needed to Set the PIN on the Java Card.
#    There are no convoluted class overloads and python source data class initializations. Basically
#    the confusing mess from Fido Alliance for test samples is gone. Yes thats right the pain is just gone.
#    
#
#   [Install]
#     pip3 install smartcard
#     pip3 install cbor2
#     pip3 install python-secrets
#     pip3 install cryptography
#################################################
import util, secrets, cbor2
import binascii, os


    
################
#  Platform is thi sPython App and the Authenticator is the Java Card
#
#  !!! This DOES PROTOCOL V2
#################################
def createCBOR(newPINenc, auth, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
    cbor_auth        = cbor2.dumps(auth).hex().upper()
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "03" # setPIN
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "04"+ cbor_auth
    dataCBOR = dataCBOR + "05"+ cbor_newPINenc
    length = (len(dataCBOR) >> 1) +1     #have to add the 06

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand




#############
#   This resets the Card so you can set the PIN.
#   Otherwise! you have to use change PIN and know the old one
#
#  [Info]
#    util.APDUhex("80108000010400","Get Info", cborflag=True)
#    util.APDUhex("801000000606A201020201","Get retries", cborflag=True)
#
#  result: 009000 success
################################
def cardReset():
    pindata="123456"
    util.printcolor(util.YELLOW,"****Card Reset ****")
 
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    
    util.APDUhex("80108000010700","Reset Card PIN")

    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")

    util.printcolor(util.YELLOW,"****Attempt to setPIN ****")
    util.printcolor(util.YELLOW,f"  PIN  data: {pindata}")
                                     
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pindata))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True);
    util.APDUhex("80100000010400","GetInfo")


def clientPinSet( pindata):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")

    util.APDUhex("80108000010700","Reset Card PIN")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    util.printcolor(util.YELLOW,"****Attempt to setPIN ****")
    util.printcolor(util.YELLOW,f"  PIN  data: {pindata}")
                                     
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pindata))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True);
    util.APDUhex("80100000010400","GetInfo")
   
   


def cardreset():
    util.printcolor(util.YELLOW,"****Card Reset ****")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo") 
    util.APDUhex("80108000010700","Reset Card PIN")

    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")







