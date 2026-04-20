import util
import binascii
import cbor2
def cardReset():
    util.printcolor(util.YELLOW,"****Card Reset ****")
    util.printcolor(util.YELLOW,"")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
    util.APDUhex("80108000010700","Reset Card PIN")
    util.APDUhex("80100000010400","GetInfo")

def pinset_protocol2(pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")

    util.printcolor(util.YELLOW,"****Attempt to setPIN ****")
    util.printcolor(util.YELLOW,f"  PIN  data: {pin}")
                                     
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True);
    util.APDUhex("80100000010400","GetInfo")

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