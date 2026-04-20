import cbor2
import util
import os
import binascii
import credentialManagement


def authenticatorConfig(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Authenticator Config ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01), and check that GetInfo.options.ep is set to true.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    subCommand = 0x01
    apdu=enableEnterpriseAttestation(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)


def authenticatorConfig(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Authenticator Config ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01), and check that GetInfo.options.ep is set to true.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    subCommand = 0x01
    apdu=enableEnterpriseAttestation(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)




def toggleAlwaysUv(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Authenticator Config ****")
    util.printcolor(util.YELLOW, """Test started: P-2
        If authenticator supports alwaysUv: Collect GetInfo.options.alwaysUv value. Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02),
        and check that:
            a) If authenticator supports alwaysUv, check that GetInfo.options.alwaysUv is opposite value
            b) Or if alwaysUv was true, and authenticator does not support disabling alwaysUv, check that authenticator returns CTAP2_ERR_OPERATION_DENIED(0x27).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    util.APDUhex("80100000010400", "Get Info")




def newMinPINLength(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Authenticator Config ****")
    util.printcolor(util.YELLOW, """Test started: P-3

        If authenticator supports setMinPINLength: Send authenticatorConfig(0x0D) with setMinPINLength(0x03),
        with newMinPINLength(0x01) larger than current character limit, and see that:
            a) Authenticator succeeds.
            b) forcePINChange is false.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    subCommand = 0x03
    apdu=newMinPinLength(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
    util.APDUhex("80100000010400", "Get Info")


def minPinLengthRPID(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Authenticator Config ****")
    util.printcolor(util.YELLOW, """Test started: P-4

        If authenticator supports setMinPINLength, and minPinLength extension:
        Send authenticatorConfig(0x0D) with setMinPINLength(0x03),
        with minPinLengthRPIDs(0x02) with max available RPIDs set to random domains, and see that authenticator succeeds.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    subCommand = 0x03
    apdu=minPinLengthRPIDs(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
    util.APDUhex("80100000010400", "Get Info")


def multipleRPIDSset(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Authenticator Config ****")
    util.printcolor(util.YELLOW, """Test started: P-5
         If authenticator supports setMinPINLength, and minPinLength extension: Send authenticatorConfig(0x0D) with setMinPINLength(0x03), with minPinLengthRPIDs(0x02) with max available RPIDs set to random domains, and see that authenticator succeeds..""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    subCommand = 0x03
    apdu=maximumRPIDs(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
    util.APDUhex("80100000010400", "Get Info")

#implement


def enableEnterpriseAttestation(pinToken, subCommand):
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # enableEnterpriseAttestation
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu





def newMinPinLength(pinToken, subCommand):

    subCommandParams = {
        0x01: 8,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: False   # forcePINChange = False
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu


def newMinPinLength_forcechangePin(pinToken, subCommand):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: True   # forcePINChange = True
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu




def minPinLengthRPIDs(pinToken, subCommand):

    subCommandParams = {
         0x02: ["example.com"]
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")


    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu



def maximumRPIDs(pinToken, subCommand):

    subCommandParams = {
         0x02: ["example.com"]
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")


    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu



#if maximum rpid 
def maximumRPIDs(pinToken, subCommand):

    subCommandParams = {
         0x02: ["example.com", "test.org", "fidoalliance.org"]
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")


    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu
