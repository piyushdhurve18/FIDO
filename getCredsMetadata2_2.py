import util
import binascii
import cbor2
import secrets
import string
import credentialManagement
import os
from textwrap import wrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib, hmac
import DocumentCreation


RP_domain = "localhost"
RP_domain1_1 = "localhost1_1"
RP_domain1_2 = "localhost1_2"
RP_domain1_3 = "localhost1_3"
RP_domain1_4 = "localhost1_4"
RP_domain2_1 = "localhost2_1"
RP_domain2_2 = "localhost2_2"
RP_domain2_3 = "localhost2_3"
RP_domain2_4 = "localhost2_4"

user="bobsmith"
user1_1="bobsmith1_1"
user1_2="bobsmith1_2"
user1_3="bobsmith1_3"
user1_4="bobsmith1_4"
user2_1="bobsmith2_1"
user2_2="bobsmith2_2"
user2_3="bobsmith2_3"
user2_4="bobsmith2_4"

new_Pin = ""
clientDataHash = os.urandom(32)
CM_PERMISSION_BYTE = 0x04
INVALID_PERMISSION_BYTE = 0x20
PCMR_PERMISSION_BYTE = 0x40
pinUvAuthTokenAssociatedRPID = b""
MODE = ""
makeCredResponse = ""
curpin="12345678"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "GET CREDS META DATA"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def executeGetCredMetaData(mode, reset_required, set_pin_required, make_cred_required, protocol):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL
    # maxCredCount = 50; #Comment it after static max cred count usage   
    maxCredCount = util.maxAllowedCredCount   #Remove Comment if you want dynamic max Cred Count
    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
    "fidoTool_PositiveCase": """Test started: P-1 :
        Precondition : Authenticator must be Reset, has PIN Set and Create new discoverable credential.;
        Send authenticatorCredentialManagement (0x0A) with getCredsMetadata (0x01), ensure all parameters are correct. The authenticator is expected to return CTAP2_OK.
        Verify that the response contains existingResidentCredentialsCount = 1 and maxPossibleRemainingResidentCredentialsCount > 1. After creating an additional discoverable credential, confirm that existingResidentCredentialsCount is updated to 2.""",

    "fidoDoc_WithoutPinUvAuthParamCase": """Test started: P-2 :
        Send getCredsMetadata (0x01) without pinUvAuthParam, while all other parameters are valid and correct. The authenticator is expected to return CTAP2_ERR_PUAT_REQUIRED.""",
    
    
    "fidoDoc_MissingMandatoryParamCase": """Test started: P-3 :
        Send getCredsMetadata(0x01) without(missing) mandatory parameter i.e. subCommand parameter, ensure all remaining parameters are correct. The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",
    
    "fidoDoc_UnsupportedProtocolCase": """Test started: P-4 :
        Send getCredsMetadata(0x01) with invalid/unsupported pinUvAuthProtocol (e.g. pinUvAuthProtocol = 3), ensure all remaining parameters are correct. The authenticator is expected to return CTAP1_ERR_INVALID_PARAMETER.""",
    
    "fidoDoc_PersistenTokenWithoutPCMRPermissionCase": """Test started: P-5 :
        Send getCredsMetadata (0x01) with a valid pinUvAuthParam generated from a persistentPinUvAuthToken that does not have pcmr permission, while all other parameters are valid and correct. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase": """Test started: P-6 :
        Send getCredsMetadata (0x01) using a pinUvAuthToken that does not have credential management (cm) permission, while all other parameters are correct. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_IncorrectPinUvAuthParamCase": """Test started: P-7 :
        Send getCredsMetadata (0x01) with an incorrect pinUvAuthParam (e.g., generated with an incorrect token or subCommand), ensuring all other parameters are valid. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase": """Test started: P-8 :
        Send getCredsMetadata (0x01) using a pinUvAuthToken that has an associated RP ID, while all other parameters are valid. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_UsingPersistentPinUvAuthTokenWithPCMRPermissionCase": """Test started: P-9 :
        Send getCredsMetadata (0x01) with valid pinUvAuthParam obtain using persistentPinUvAuthToken with correct pcmr permission, ensure all remaining pameters are correct. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 2 and  maxPossibleRemainingResidentCredentialsCount = maximum - 2.""",
    
    "self_UsingPinUvAuthTokenWithCMPermissionCase": """Test started: P-10 :
        Send getCredsMetadata (0x01) with valid pinUvAuthParam obtain using pinUvAuthToken with correct cm permission, ensure all remaining pameters are correct. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 2 and  maxPossibleRemainingResidentCredentialsCount = maximum - 2.""",
    
    "self_InvalidSubcommandCase": """Test started: P-11 :
        Send authenticatorCredentialManagement (0x0A) with an invalid subCommand value (while sendind getCredsMetadata command use subCommand 0x0A), while all other parameters are correct. The authenticator is expected to return CTAP2_ERR_INVALID_SUBCOMMAND.""",
    
    "self_TruncatedPinUvAuthParamFromPersistentTokenCase": """Test started: P-12 :
        Send getCredsMetadata (0x01) with a truncated pinUvAuthParam (from persistentPinUvAuthToken with correct pcmr permission), ensuring all remaining parameters are correct. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID. """,
    
    "self_TruncatedPinUvAuthParamFromPinUvAuthTokenCase": """Test started: P-13 :
        Send getCredsMetadata (0x01) with a truncated pinUvAuthParam(from pinUvAuthToken with correct cm permission), ensuring all remaining parameters are correct. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID. """,
    
    "self_ExpiredPersistenPinUvAuthTokenCase": """Test started: P-14 :
        Send getCredsMetadata (0x01) using an expired/old persistentPinUvAuthToken with pcmr permission, while all remaining parameters are correct. The authenticator is expected to return CTAP2_OK.""",
    
    "self_ExpiredPinUvAuthTokenCase": """Test started: P-15 :
        Send getCredsMetadata (0x01) using an expired or invalid pinUvAuthToken with cm permission, while all remaining parameters are correct. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_OnlyOneCredentialSlotRemainWithPCMRPermissionCase": """Test started: P-16 :
        Precondition : Authenticator must be Reset, has PIN Set, Create 99 Credentials and Create PinUvAuthToken with pcmr persmission.
        Send getCredsMetadata (0x01) with valid parameters when exactly one resident credential slot remains available. The authenticator is expected to return CTAP2_OK, with maxPossibleRemainingResidentCredentialsCount = 1.""",
    
    "self_OnlyOneCredentialSlotRemainWithCMPermissionCase": """Test started: P-17 :
        Precondition : Authenticator must be Reset, has PIN Set, Create 99 Credentials and Create PinUvAuthToken with cm persmission.;
        Send getCredsMetadata (0x01) with valid parameters when exactly one resident credential slot remains available. The authenticator is expected to return CTAP2_OK, with maxPossibleRemainingResidentCredentialsCount = 1.""",
    
    "self_MultipleGetCredsMetaDataWithPCMRPermissionCase": """Test started: P-18 :
        Send getCredsMetadata (0x01) with pcmr permission multiple times consecutively without creating or deleting any discoverable credentials. The authenticator is expected to return CTAP2_OK each time, and the returned metadata values should remain unchanged.""",
    
    "self_MultipleGetCredsMetaDataWithCMPermissionCase": """Test started: P-19 :
        Send getCredsMetadata (0x01) with cm permission multiple times consecutively without creating or deleting any discoverable credentials. The authenticator is expected to return CTAP2_OK each time, and the returned metadata values should remain unchanged.""",
    
    "self_DeleteCredAndCheckReducedCredCountWithPCMRPermissionCase": """Test started: P-20 :
        Precondition : Authenticator must be Reset, has PIN Set, create 3 new discoverable credential and send getCredsMetadata (0x01) to check existingResidentCredentialsCount = 3.;
        Delete an existing discoverable credential. Send getCredsMetadata (0x01) by using persistentPinUvAuthToken with pcmr permission with valid parameters. The authenticator is expected to return CTAP2_OK, and existingResidentCredentialsCount = 2.""",
    
    "self_DeleteCredAndCheckReducedCredCountWithCMPermissionCase": """Test started: P-21 :
        Precondition : Authenticator must be Reset, has PIN Set, create 3 new discoverable credential and send getCredsMetadata (0x01) to check existingResidentCredentialsCount = 3.;
        Delete an existing discoverable credential. Send getCredsMetadata (0x01) by using pinUvAuthToken with cm permission with valid parameters .The authenticator is expected to return CTAP2_OK, and existingResidentCredentialsCount = 2.""",
    
    "self_DeleteOneCredAndCheckCredMetaDataWithPCMRPermissionCase": """Test started: P-22 :
        Precondition : Reset the Authenticator, Set a new PIN on the authenticator and Create one discoverable credential.;
        Send getCredsMetadata (0x01) with valid pinUvAuthParam obtain using  persistentPinUvAuthToken with correct permission. The authenticator is expected to return CTAP2_OK with existingResidentCredentialsCount = 1.
        Delete the discoverable credential. Send getCredsMetadata (0x01) again with valid parameters. The authenticator is expected to return CTAP2_OK with existingResidentCredentialsCount = 0.""",
    
    "self_DeleteOneCredAndCheckCredMetaDataWithCMPermissionCase": """Test started: P-23 :
        Precondition : Reset the Authenticator, Set a new PIN on the authenticator and Create one discoverable credential.;
        Send getCredsMetadata (0x01) with valid pinUvAuthParam obtain using  pinUvAuthToken with correct permission. The authenticator is expected to return CTAP2_OK with existingResidentCredentialsCount = 1.
        Delete the discoverable credential. Send getCredsMetadata (0x01) again with valid parameters. The authenticator is expected to return CTAP2_OK with existingResidentCredentialsCount = 0.""",
    
    "self_CheckPowerCycleEffectAfterDeleteCredMetaDataWithPCMRPermissionCase": """Test started: P-24 :
        Precondition : Reset the Authenticator, Set a PIN and create one discoverable credential.;
        Send getCredsMetadata (0x01) using pcmr permission with valid parameters. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 1. Delete the credential. Perform a power cycle without reset the authenticator. Send getCredsMetadata (0x01) using pcmr permission with valid parameters. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 0.""",
    
    "self_CheckPowerCycleEffectAfterDeleteCredMetaDataWithCMPermissionCase": """Test started: P-25 :
        Precondition : Reset the Authenticator, Set a PIN and create one discoverable credential.;
        Send getCredsMetadata (0x01) using cm permission with valid parameters. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 1. Delete the credential. Perform a power cycle without reset the authenticator. Send getCredsMetadata (0x01) using cm permission with valid parameters. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 0.""",
    
    "self_CredStorageFull_DeleteOneCredPCMRPermissionCase": """Test started: P-26 :
        Precondition : Reset the Authenticator, Set a PIN and create 100 discoverable credentials.;
        [Perform getCredsMetaData Commands with pcmr permission]
        Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK, with maxPossibleRemainingResidentCredentialsCount = 0.
        Delete one discoverable credential and send getCredsMetadata (0x01) again. The authenticator is expected to return CTAP2_OK, with maxPossibleRemainingResidentCredentialsCount = 1.""",
    
    "self_CredStorageFull_DeleteOneCredCMPermissionCase": """Test started: P-27 :
        Precondition : Reset the Authenticator, Set a PIN and create 100 discoverable credentials.;
        [Perform getCredsMetaData Commands with cm permission]
        Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK, with maxPossibleRemainingResidentCredentialsCount = 0.
        Delete one discoverable credential and send getCredsMetadata (0x01) again. The authenticator is expected to return CTAP2_OK, with maxPossibleRemainingResidentCredentialsCount = 1.""",
    
    "self_MakeMaxPossibleRemainingResidentCredentialsCountZeroCase": """Test started: P-28 :
        Precondition : Reset the authenticator, ensure a PIN is set, and create a new discoverable credentials.;
        Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK with correctly encoded values  i.e existingResidentCredentialsCount = maximum, maxPossibleRemainingResidentCredentialsCount =  0.
        Again make one credential and send getCredsMetaData(0x01) with correct parameters. The authenticator must return CTAP2_ERR_KEY_STORE_FULL.""",

    "self_CheckPowerCycleEffectAfterTwoCredMetaDataWithPCMRPermissionCase": """Test started: P-29 :
        Precondition : Authenticator must be Reset, has PIN Set and Create new discoverable credential.;
        [Use pcmr permission]
        Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK with credential counts.
        Again send getCredsMetadata (0x01) with valid parameters immediately after authenticator power-up or reset. The authenticator is expected to return CTAP2_OK with accurate credential counts (Same as previous).""",
    
    "self_CheckPowerCycleEffectAfterTwoCredMetaDataWithCMPermissionCase": """Test started: P-30 :
        Precondition : Authenticator must be Reset, has PIN Set and Create new discoverable credential.;
        [Use cm permission]
        Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK with credential counts.
        Again send getCredsMetadata (0x01) with valid parameters immediately after authenticator power-up or reset. The authenticator is expected to return CTAP2_OK with accurate credential counts (Same as previous).""",
    
    "self_InvalidPermissionCase": """Test started: P-31 :
        Send getCredsMetadata (0x01) using a pinUvAuthToken scoped to permissions other than cm and pcmr but supported permission, while all other parameters are valid. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_MalformedOrderCBORCase": """Test started: P-32 :
        Send getCredsMetadata (0x01) using a CBOR map that includes required fields but has malformed ordering or additional nested structures. The authenticator is expected to return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
    
    "self_WithoutCredentialGetCredMetaDataWithCMPermissionCase": """Test started: P-33 :
        Precondition : Reset the authenticator, ensure a PIN is set and has no credential.;
        Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK with correctly encoded values i.e existingResidentCredentialsCount = 0, maxPossibleRemainingResidentCredentialsCount =  maximum.""",
    
    "self_NoPINSetWithoutCredentialGetCredMetaDataWithCMPermissionCase": """Test started: P-34 :
        Precondition : Reset the Authenticator.;
        Send getCredsMetadata (0x01) when no PIN is set on the authenticator and no discoverable credentials exist, ensuring all required parameters are provided. The authenticator is expected to return CTAP2_ERR_PIN_NOT_SET.""",
    
    "self_ResetNewPINAndGetCredMetaDataWithCMPermissionCase": """Test started: P-35 :
        Precondition : Reset the Authenticator.;
        Set a PIN and create one discoverable credential. Perform an authenticator reset. Re-set a new PIN. Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 0.""",
    
    "self_ChangePINAndGetCredMetaDataWithCMPermissionCase": """Test started: P-36 :
        Change the existing PIN to new PIN,  create one discoverable credential. Send getCredsMetadata (0x01) with valid parameters. The authenticator is expected to return CTAP2_OK, with existingResidentCredentialsCount = 1.""",
    
    "self_ProtocolSwappingForKeyAgreementAndGetCredsMetaDataCase": """Test started: P-37 :
        Attempt to Send getCredsMetadata (0x01) with a pinUvAuthProtocol that does not match the protocol used to derive the keyAgreement, while all other parameters are valid. But the authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID for getPINToken command.
        > Swap the Protocols and Perform Again. Expected result will be same.""",
    
    "self_MakeCredWithoutPINAlwaysUvFalseCase": """Test started: P-38 :
        Precondition: No PIN is set and create credential with rk without PIN (make sure alwaysUV is false).;
        Send getCredsMetadata (0x01) without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04) as Authenticator does not have PIN set.
        Expected output: CTAP2_ERR_PUAT_REQUIRED.""",

    "self_MakeCredWithPINSetGetPINToken_05": """Test started: P-39 :
        Precondition: PIN is set and card having atleast one rk credential.;
        get PIN Token using getPinToken (0x05) then Send getCredsMetadata (0x01)  with all valid parameters. Authenticator must return CTAP2_ERR_PIN_AUTH_INVALID.""",
        
    "self_MakeCredChangeRKValueEachTime": """Test started: P-40 :
        Get maxPossibleRemainingResidentCredentialsCount and existingResidentCredentialsCount (XX and YY)
        Create credentials without rk and make sure maxPossibleRemainingResidentCredentialsCount and existingResidentCredentialsCount remains same/did not decrease  (XX and YY).""",
    }

    clientDataHashRandom1 = os.urandom(32)
    RP_domainRandom1 = randomRPId(10)
    userRandom1 = randomUser(8)

    clientDataHashRandom2 = os.urandom(32)
    RP_domainRandom2 = randomRPId(10)
    userRandom2 = randomUser(8)

    
    clientDataHashRandom3 = os.urandom(32)
    RP_domainRandom3 = randomRPId(10)
    userRandom3 = randomUser(8)

    global MODE
    MODE = mode
    
    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])
    util.ResetCardPower()
    util.ConnectJavaCard()

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    pin = "12121212"
    
    if reset_required == "yes":
        util.ResetCardPower()
        util.ConnectJavaCard()

        util.APDUhex("00A4040008A0000006472F0001", "Select applet")
        util.ResetCardPower()
        util.ConnectJavaCard()
        util.APDUhex("00A4040008A0000006472F0001", "Select applet")
        response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        if status == "00":
            util.printcolor(util.GREEN,f"FIDO RESET DONE")
        else:
            util.printcolor(util.RED,f"FIDO RESET FAILED WITH STATUS CODE: {status}")
            exit(0)
        


        # util.APDUhex("80100000010400", "GetInfo")

    if set_pin_required == "yes":
        if protocol == "PROTOCOL_ONE":
            response, status =  setpinProtocol1(pin)  #Set new pin 12121212
            if status == "00":
                util.printcolor(util.GREEN,f"SET PIN ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"SET PIN ({protocol}) FAILED WITH STATUS CODE: {status}")
        elif protocol == "PROTOCOL_TWO":
            response, status = setpinProtocol2(pin)  #Set new pin 12121212
            if status == "00":
                util.printcolor(util.GREEN,f"SET PIN ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"SET PIN ({protocol}) FAILED WITH STATUS CODE: {status}")

    util.APDUhex("80100000010400", "GetInfo")

    if make_cred_required == "yes":
        if mode == "self_CredStorageFull_DeleteOneCredPCMRPermissionCase" or mode == "self_CredStorageFull_DeleteOneCredCMPermissionCase": #or mode == "self_MakeMaxPossibleRemainingResidentCredentialsCountZeroCase":
            for y2 in range(maxCredCount):
                    time1 = y2+1
                    clientDataHash = os.urandom(32)
                    RP_domain = randomRPId(10)+".com"
                    user = randomUser(8)
                    util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred {time1} -> {util.toHex(clientDataHash)}")
                    util.printcolor(util.YELLOW,f"RP Id for Make Cred {time1} -> {RP_domain}")
                    util.printcolor(util.YELLOW,f"User for Make Cred {time1} -> {user}")
                    
                    response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user)  #Make cred by protocol 2
                    global makeCredResponse
                    makeCredResponse = response
                    if status == "00":
                        util.printcolor(util.GREEN,f"{time1} Time MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED,f"{time1} Time MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
                    resetPowerCycle(True)   
        elif mode == "self_OnlyOneCredentialSlotRemainWithPCMRPermissionCase" or mode == "self_OnlyOneCredentialSlotRemainWithCMPermissionCase":
                for y3 in range(maxCredCount-1): 
                    time2 = y3+1
                    clientDataHash = os.urandom(32)
                    RP_domain = randomRPId(10)+".com"
                    user = randomUser(8)
                    util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred {time2} -> {util.toHex(clientDataHash)}")
                    util.printcolor(util.YELLOW,f"RP Id for Make Cred {time2} -> {RP_domain}")
                    util.printcolor(util.YELLOW,f"User for Make Cred {time2} -> {user}")

                    response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user)  #Make cred by protocol 2
                    if status == "00":
                        util.printcolor(util.GREEN,f"{time2} Time MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED,f"{time2} Time MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
                    resetPowerCycle(True)
        elif mode == "self_DeleteCredAndCheckReducedCredCountWithPCMRPermissionCase" or mode == "self_DeleteCredAndCheckReducedCredCountWithCMPermissionCase":
            #MakeCred -- 1
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 1 -> {util.toHex(clientDataHashRandom1)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 1 -> {RP_domainRandom1}")
            util.printcolor(util.YELLOW,f"User for Make Cred 1 -> {userRandom1}")
            # response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom1, RP_domainRandom1, userRandom1)  #Make cred by protocol 2
            response, status = makeCredProtocol2(pin, clientDataHashRandom1, RP_domainRandom1, userRandom1)  #Make cred by protocol 2
            if status == "00":
                util.printcolor(util.GREEN,f"1 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"1 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            resetPowerCycle(True)

            #MakeCred -- 2
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 2 -> {util.toHex(clientDataHashRandom2)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 2 -> {RP_domainRandom2}")
            util.printcolor(util.YELLOW,f"User for Make Cred 2 -> {userRandom2}")
            # response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom2, RP_domainRandom2, userRandom2)  #Make cred by protocol 2

            response, status = makeCredProtocol2(pin, clientDataHashRandom2, RP_domainRandom2, userRandom2)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"2 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"2 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            resetPowerCycle(True)

            #MakeCred -- 3
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 3 -> {util.toHex(clientDataHashRandom3)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 3 -> {RP_domainRandom3}")
            util.printcolor(util.YELLOW,f"User for Make Cred 3 -> {userRandom3}")
            # response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2

            response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"3 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"3 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            resetPowerCycle(True)
            util.printcolor(util.BLUE,f"3 CREDENTIALS CREATED SUCCESSFULLY !!!")

        elif mode == "self_MakeCredWithoutPINCase1":
             #MakeCred -- 1
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 1 -> {util.toHex(clientDataHashRandom1)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 1 -> {RP_domainRandom1}")
            util.printcolor(util.YELLOW,f"User for Make Cred 1 -> {userRandom1}")
            response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom1, RP_domainRandom1, userRandom1)  #Make cred by protocol 2
            # response, status = makeCredProtocol2(pin, clientDataHashRandom1, RP_domainRandom1, userRandom1)  #Make cred by protocol 2
            if status == "00":
                util.printcolor(util.GREEN,f"1 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"1 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
                exit(0)
            resetPowerCycle(True)

            #MakeCred -- 2
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 2 -> {util.toHex(clientDataHashRandom2)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 2 -> {RP_domainRandom2}")
            util.printcolor(util.YELLOW,f"User for Make Cred 2 -> {userRandom2}")
            response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom2, RP_domainRandom2, userRandom2)  #Make cred by protocol 2

            # response, status = makeCredProtocol2(pin, clientDataHashRandom2, RP_domainRandom2, userRandom2)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"2 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"2 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
                    exit(0)
            resetPowerCycle(True)

            #MakeCred -- 3
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 3 -> {util.toHex(clientDataHashRandom3)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 3 -> {RP_domainRandom3}")
            util.printcolor(util.YELLOW,f"User for Make Cred 3 -> {userRandom3}")
            response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2

            # response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"3 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"3 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
                    exit(0)
            resetPowerCycle(True)

            ###### REMOVE AFTER TEST
            # #MakeCred -- 4
            # util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 4 -> {util.toHex(clientDataHashRandom3)}")
            # util.printcolor(util.YELLOW,f"RP Id for Make Cred 4 -> {RP_domainRandom3}")
            # util.printcolor(util.YELLOW,f"User for Make Cred 4 -> {userRandom3}")
            # response, status = makeCredWithoutPINSetProtocol2(clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2
            
            ### response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2
            # if status == "00":
            #         util.printcolor(util.GREEN,f"4 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            # else:
            #         util.printcolor(util.RED,f"4 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            ########################

            # response, status = setpinProtocol2(pin)  #Set new pin 12121212
            # if status == "00":
            #     util.printcolor(util.GREEN,f"SET PIN ({protocol}) DONE")
            # else:
            #     util.printcolor(util.RED,f"SET PIN ({protocol}) FAILED WITH STATUS CODE: {status}")
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            util.APDUhex("80100000010400", "GetInfo")

            subCommand = 0x01
            pinUvAuthParam = ""
            apdu = getCredsMetadata_APDU_Protocol2(subCommand, pinUvAuthParam, mode)
            response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
            # response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")

            resetPowerCycle(True)
        elif mode == "self_MakeCredWithPINCase2":
             #MakeCred -- 1
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 1 -> {util.toHex(clientDataHashRandom1)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 1 -> {RP_domainRandom1}")
            util.printcolor(util.YELLOW,f"User for Make Cred 1 -> {userRandom1}")
            response, status = makeCredProtocol2(pin, clientDataHashRandom1, RP_domainRandom1, userRandom1)  #Make cred by protocol 2
            # response, status = makeCredProtocol2(pin, clientDataHashRandom1, RP_domainRandom1, userRandom1)  #Make cred by protocol 2
            if status == "00":
                util.printcolor(util.GREEN,f"1 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"1 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            resetPowerCycle(True)

            #MakeCred -- 2
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 2 -> {util.toHex(clientDataHashRandom2)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 2 -> {RP_domainRandom2}")
            util.printcolor(util.YELLOW,f"User for Make Cred 2 -> {userRandom2}")
            response, status = makeCredProtocol2(pin, clientDataHashRandom2, RP_domainRandom2, userRandom2)  #Make cred by protocol 2

            # response, status = makeCredProtocol2(pin, clientDataHashRandom2, RP_domainRandom2, userRandom2)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"2 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"2 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            resetPowerCycle(True)

            #MakeCred -- 3
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 3 -> {util.toHex(clientDataHashRandom3)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 3 -> {RP_domainRandom3}")
            util.printcolor(util.YELLOW,f"User for Make Cred 3 -> {userRandom3}")
            response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2

            # response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"3 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"3 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            resetPowerCycle(True)

            ###### REMOVE AFTER TEST
            #MakeCred -- 4
            util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred 4 -> {util.toHex(clientDataHashRandom3)}")
            util.printcolor(util.YELLOW,f"RP Id for Make Cred 4 -> {RP_domainRandom3}")
            util.printcolor(util.YELLOW,f"User for Make Cred 4 -> {userRandom3}")
            response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2

            # response, status = makeCredProtocol2(pin, clientDataHashRandom3, RP_domainRandom3, userRandom3)  #Make cred by protocol 2
            if status == "00":
                    util.printcolor(util.GREEN,f"4 MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            else:
                    util.printcolor(util.RED,f"4 MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")

            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")

            resetPowerCycle(True)
        elif mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
                   
                    clientDataHash = os.urandom(32)
                    RP_domain = randomRPId(10)+".com"
                    user = randomUser(8)
                    util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred -> {util.toHex(clientDataHash)}")
                    util.printcolor(util.YELLOW,f"RP Id for Make Cred -> {RP_domain}")
                    util.printcolor(util.YELLOW,f"User for Make Cred -> {user}")

                    response, status = makeCredWithoutPINSetProtocol2(clientDataHash, RP_domain, user)  #Make cred by protocol 2
                    if status == "00":
                        util.printcolor(util.GREEN,f"MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED,f"MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
                        exit(0)
                    resetPowerCycle(True)
                    
        else:
            resetPowerCycle(True)
            clientDataHash = os.urandom(32)
            RP_domain = "localhost"
            user = "bobsmith"
            response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user)  #Make cred by protocol 2
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED DONE")
            else:
                util.printcolor(util.RED,f"MAKE CRED FAILED WITH STATUS CODE: {status}")
                exit(0)
            resetPowerCycle(True)
    old_pin = pin

    # ------------------------------
    #  MODE → PIN VALUE
    # ------------------------------

    if protocol == "PROTOCOL_ONE":
        PROTOCOL = 1
    else:
        PROTOCOL = 2

    if mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        scenarioCount += 1
        subCommand = 0x01
        pinUvAuthParam = ""
        util.APDUhex("00a4040008a0000006472f0001","Select applet")

        if protocol == "PROTOCOL_ONE":
            apdu = getCredsMetadata_APDU_Protocol1(subCommand, pinUvAuthParam, mode)
            response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
            if status == "36":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            apdu = getCredsMetadata_APDU_Protocol2(subCommand, pinUvAuthParam, mode)
            response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)

            if status == "36":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MakeCredWithPINSetGetPINToken_05":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MakeCredChangeRKValueEachTime":
        scenarioCount += 1

        clientDataHash = os.urandom(32)
        RP_domain = "localhost.com"
        user = "bobsmith2"
        if protocol == "PROTOCOL_ONE":
            
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                resetPowerCycle(True)
                response, status = makeCredProtocol2(pin,clientDataHash,RP_domain, user)
                resetPowerCycle(True)
                if status == "00":
                    util.printcolor(util.GREEN,f"MAKE CRED WITH RK FALSE DONE")
                    response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == exist:
                            util.printcolor(util.GREEN,f"TEST PASSED CREDS COUNT IS SAME AS PREVIOUS")
                        else:
                            util.printcolor(util.RES,f"TEST FAILED CREDS COUNT IS NOT SAME AS PREVIOUS")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"MAKE CRED WITH RK FALSE FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                resetPowerCycle(True)
                response, status = makeCredProtocol2(pin,clientDataHash,RP_domain, user)  
                resetPowerCycle(True)
                if status == "00":
                    util.printcolor(util.GREEN,f"MAKE CRED WITH RK FALSE DONE")
                    response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == exist:
                            util.printcolor(util.GREEN,f"TEST PASSED CREDS COUNT IS SAME AS PREVIOUS")
                        else:
                            util.printcolor(util.RES,f"TEST FAILED CREDS COUNT IS NOT SAME AS PREVIOUS")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"MAKE CRED WITH RK FALSE FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
   
    if mode == "fidoTool_PositiveCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            clientDataHash1 = os.urandom(32)
            response, status = makeCredProtocol2(pin, clientDataHash1, RP_domain1_2, user1_2)  #Make cred by protocol 1
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"MAKE CRED ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            clientDataHash1 = os.urandom(32)
            response, status = makeCredProtocol2(pin, clientDataHash1, RP_domain2_2, user2_2)  #Make cred by protocol 2
                
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"MAKE CRED ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) DONE")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
    



    if mode == "fidoDoc_WithoutPinUvAuthParamCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "36":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "36":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "fidoDoc_MissingMandatoryParamCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "fidoDoc_UnsupportedProtocolCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "02":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP1_ERR_INVALID_PARAMETER)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "02":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP1_ERR_INVALID_PARAMETER)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_PersistenTokenWithoutPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_IncorrectPinUvAuthParamCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_UsingPersistentPinUvAuthTokenWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_UsingPinUvAuthTokenWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_InvalidSubcommandCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "3E":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_INVALID_SUBCOMMAND)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "3E":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_INVALID_SUBCOMMAND)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_TruncatedPinUvAuthParamFromPersistentTokenCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_TruncatedPinUvAuthParamFromPinUvAuthTokenCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_ExpiredPersistenPinUvAuthTokenCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_ExpiredPinUvAuthTokenCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_OnlyOneCredentialSlotRemainWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_OnlyOneCredentialSlotRemainWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_MultipleGetCredsMetaDataWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = 0, 0
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status != "00":
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)

            for a1 in range(10):
                attempt = a1+1
                response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = getCredCountsInteger(response)
                    if existingResidentCredentialsCount != existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount != maxPossibleRemainingResidentCredentialsCount1:
                        util.printcolor(util.RED,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are changed after {attempt} attempt")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            if existingResidentCredentialsCount == existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount == maxPossibleRemainingResidentCredentialsCount1:
                util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount remain unchanged after {attempt} attempt without creating or deleting dicoverable credential")

    
        elif protocol == "PROTOCOL_TWO":
            existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = 0, 0
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status != "00":
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)

            for a2 in range(10):
                attempt = a2+1
                response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = getCredCountsInteger(response)
                    if existingResidentCredentialsCount != existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount != maxPossibleRemainingResidentCredentialsCount1:
                        util.printcolor(util.RED,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are changed after {attempt} attempt")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            
            if existingResidentCredentialsCount == existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount == maxPossibleRemainingResidentCredentialsCount1:
                        util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount remain unchanged after {attempt} attempt without creating or deleting dicoverable credential")
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_MultipleGetCredsMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = 0, 0
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status != "00":
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)

            for a1 in range(10):
                attempt = a1+1
                response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = getCredCountsInteger(response)
                    if existingResidentCredentialsCount != existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount != maxPossibleRemainingResidentCredentialsCount1:
                        util.printcolor(util.RED,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are changed after {attempt} attempt")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            if existingResidentCredentialsCount == existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount == maxPossibleRemainingResidentCredentialsCount1:
                util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount remain unchanged after {attempt} attempt without creating or deleting dicoverable credential")


    
        elif protocol == "PROTOCOL_TWO":
            existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = 0, 0
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status != "00":
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)

            for a2 in range(10):
                attempt = a2+1
                response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    existingResidentCredentialsCount1, maxPossibleRemainingResidentCredentialsCount1 = getCredCountsInteger(response)
                    if existingResidentCredentialsCount != existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount != maxPossibleRemainingResidentCredentialsCount1:
                        util.printcolor(util.RED,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are changed after {attempt} attempt")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            if existingResidentCredentialsCount == existingResidentCredentialsCount1 and maxPossibleRemainingResidentCredentialsCount == maxPossibleRemainingResidentCredentialsCount1:
                        util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount remain unchanged after {attempt} attempt without creating or deleting dicoverable credential")
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_DeleteCredAndCheckReducedCredCountWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHashRandom3,RP_domainRandom3, userRandom3)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHashRandom3,RP_domainRandom3, userRandom3)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_DeleteCredAndCheckReducedCredCountWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            util.printcolor(util.BLUE,f"GET CREDS META DATA BEFORE 4TH CREDENTIAL TO BE CREATE !!!")
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHashRandom3,RP_domainRandom3, userRandom3)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHashRandom3,RP_domainRandom3, userRandom3)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_DeleteOneCredAndCheckCredMetaDataWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_DeleteOneCredAndCheckCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_CheckPowerCycleEffectAfterDeleteCredMetaDataWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    resetPowerCycle(True)
                    response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    resetPowerCycle(True)
                    response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_CheckPowerCycleEffectAfterDeleteCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    resetPowerCycle(True)
                    response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                credentialManagement.deleteCredentialdataProtocol2(pin,clientDataHash,RP_domain, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    resetPowerCycle(True)
                    response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if exist1 == (exist-1):
                            util.printcolor(util.GREEN,f"existingResidentCredentialsCount reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                        else:
                            util.printcolor(util.RED,f"existingResidentCredentialsCount not reduced by 1 i.e. Before delete existingResidentCredentialsCount = {exist} and after delete existingResidentCredentialsCount = {exist1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_CredStorageFull_DeleteOneCredPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                response, status = credentialManagement.deleteCredentialdataWithMakeCredResponseProtocol2(pin,clientDataHash,RP_domain, user, makeCredResponse)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if max1 == 1:
                            util.printcolor(util.GREEN,f"maxPossibleRemainingResidentCredentialsCount is 1 i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                        else:
                            util.printcolor(util.RED,f"not expected maxPossibleRemainingResidentCredentialsCount i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                response, status = credentialManagement.deleteCredentialdataWithMakeCredResponseProtocol2(pin,clientDataHash,RP_domain, user, makeCredResponse)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if max1 == 1:
                            util.printcolor(util.GREEN,f"maxPossibleRemainingResidentCredentialsCount is 1 i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                        else:
                            util.printcolor(util.RED,f"not expected maxPossibleRemainingResidentCredentialsCount i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_CredStorageFull_DeleteOneCredCMPermissionCase":
        scenarioCount += 1

        clientDataHash = os.urandom(32)
        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                response, status = credentialManagement.deleteCredentialdataWithMakeCredResponseProtocol2(pin,clientDataHash,RP_domain, user, makeCredResponse)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if max1 == 1:
                            util.printcolor(util.GREEN,f"maxPossibleRemainingResidentCredentialsCount is 1 i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                        else:
                            util.printcolor(util.RED,f"not expected maxPossibleRemainingResidentCredentialsCount i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                response, status = credentialManagement.deleteCredentialdataWithMakeCredResponseProtocol2(pin,clientDataHash,RP_domain, user, makeCredResponse)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL DONE -> {status}(CTAP2_OK)")
                    response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist1, max1 = getCredCountsInteger(response)
                        if max1 == 1:
                            util.printcolor(util.GREEN,f"maxPossibleRemainingResidentCredentialsCount is 1 i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                        else:
                            util.printcolor(util.RED,f"not expected maxPossibleRemainingResidentCredentialsCount i.e. Before delete maxPossibleRemainingResidentCredentialsCount = {max} and after delete maxPossibleRemainingResidentCredentialsCount = {max1}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_CheckPowerCycleEffectAfterTwoCredMetaDataWithPCMRPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                util.printcolor(util.YELLOW,"PERFORMING POWER CYCLE RESET...")
                resetPowerCycle(True)
                response, status = getCredsMetadataProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    exist1, max1 = getCredCountsInteger(response)
                    if exist == exist1 and max == max1:
                        util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are same as previous")
                    else:
                        util.printcolor(util.RED,f"not expected existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount ")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                util.printcolor(util.YELLOW,"PERFORMING POWER CYCLE RESET...")
                resetPowerCycle(True)

                response, status = getCredsMetadataProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    exist1, max1 = getCredCountsInteger(response)
                    if exist == exist1 and max == max1:
                        util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are same as previous")
                    else:
                        util.printcolor(util.RED,f"not expected existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount ")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_CheckPowerCycleEffectAfterTwoCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                util.printcolor(util.YELLOW,"PERFORMING POWER CYCLE RESET...")
                resetPowerCycle(True)
                response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    exist1, max1 = getCredCountsInteger(response)
                    if exist == exist1 and max == max1:
                        util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are same as previous")
                    else:
                        util.printcolor(util.RED,f"not expected existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount ")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                util.printcolor(util.YELLOW,"PERFORMING POWER CYCLE RESET...")
                resetPowerCycle(True)

                response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                    exist1, max1 = getCredCountsInteger(response)
                    if exist == exist1 and max == max1:
                        util.printcolor(util.GREEN,f"existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount are same as previous")
                    else:
                        util.printcolor(util.RED,f"not expected existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount ")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_InvalidPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, INVALID_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, INVALID_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MalformedOrderCBORCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "11":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "11":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MakeMaxPossibleRemainingResidentCredentialsCountZeroCase":
        scenarioCount += 1

        rp = randomRPId(8)+"entra.com."
        us_er = "Piyush@"+randomUser(8)
        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                if max == 0:
                    util.printcolor(util.GREEN,f"Expected maxPossibleRemainingResidentCredentialsCount = {max}")
                    response, status = makeCredProtocol2(pin, clientDataHash, rp, us_er)
                    if status == "28":
                        util.printcolor(util.GREEN,f"After maxPossibleRemainingResidentCredentialsCount = {max}, Can not create credential. Expected Status Code : {status}(CTAP2_ERR_KEY_STORE_FULL)")
                    else:
                        util.printcolor(util.RED,f"After maxPossibleRemainingResidentCredentialsCount = {max}, Can not create credential. Got Unexpected Status Code : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"Unexpected maxPossibleRemainingResidentCredentialsCount = {max}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                exist, max = getCredCountsInteger(response)
                if max == 0:
                    util.printcolor(util.GREEN,f"Expected maxPossibleRemainingResidentCredentialsCount = {max}")
                    response, status = makeCredProtocol2(pin, clientDataHash, rp, us_er)
                    if status == "28":
                        util.printcolor(util.GREEN,f"After maxPossibleRemainingResidentCredentialsCount = {max}, Can not create credential. Expected Status Code : {status}(CTAP2_ERR_KEY_STORE_FULL)")
                    else:
                        util.printcolor(util.RED,f"After maxPossibleRemainingResidentCredentialsCount = {max}, Can not create credential. Got Unexpected Status Code : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"Unexpected maxPossibleRemainingResidentCredentialsCount = {max}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_WithoutCredentialGetCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)

    if mode == "self_NoPINSetWithoutCredentialGetCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataWithoutPINSetProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "35":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_NOT_SET)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataWithoutPINSetProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "35":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_NOT_SET)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_ResetNewPINAndGetCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
            if status == "00":
                util.printcolor(util.GREEN,f"FIDO RESET DONE")
                response, status =  setpinProtocol1(pin)  #Set new pin 12121212
                if status == "00":
                    util.printcolor(util.GREEN,f"SET PIN ({protocol}) DONE")
                    response, status = getCredsMetadataProtocol1(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist, max = getCredCountsInteger(response)
                        if exist == 0:
                            util.printcolor(util.GREEN,f"Expected existingResidentCredentialsCount")
                        else:
                            util.printcolor(util.RED,f"Unexpected existingResidentCredentialsCount")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"SET PIN ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"FIDO RESET FAILED WITH STATUS CODE: {status}")
                exit(0)

        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
            if status == "00":
                util.printcolor(util.GREEN,f"FIDO RESET DONE")
                response, status =  setpinProtocol2(pin)  #Set new pin 12121212
                if status == "00":
                    util.printcolor(util.GREEN,f"RESET PIN ({protocol}) DONE")
                    response, status = getCredsMetadataProtocol2(pin, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist, max = getCredCountsInteger(response)
                        if exist == 0:
                            util.printcolor(util.GREEN,f"Expected existingResidentCredentialsCount")
                        else:
                            util.printcolor(util.RED,f"Unexpected existingResidentCredentialsCount")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"RESET PIN ({protocol}) FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"FIDO RESET FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_ChangePINAndGetCredMetaDataWithCMPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            newPIN = "12121212"
            response, status = changePINProtocol1(pin, newPIN)
            if status == "00":
                util.printcolor(util.GREEN,f"CHANGE PIN BY ({protocol}) RETURN EXPECTED -> {status}(CTAP2_OK)")
                clientDataHashPro1 = os.urandom(32)
                RP_id = "localhost1"
                userName = "bobsmith1"
                response, status = makeCredProtocol2(newPIN, clientDataHashPro1, RP_id, userName)  #Make cred by protocol 2
                resetPowerCycle(True)
                if status == "00":
                    util.printcolor(util.GREEN,f"MAKE CRED DONE")
                    response, status = getCredsMetadataProtocol1(newPIN, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist, max = getCredCountsInteger(response)
                        if exist == 1:
                            util.printcolor(util.GREEN,f"Expected existingResidentCredentialsCount")
                        else:
                            util.printcolor(util.RED,f"Unexpected existingResidentCredentialsCount")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"MAKE CRED FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"CHANGE PIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            newPIN = "12121212"
            response, status = changePINProtocol2(pin, newPIN)
            if status == "00":
                util.printcolor(util.GREEN,f"CHANGE PIN BY ({protocol}) RETURN EXPECTED -> {status}(CTAP2_OK)")
                clientDataHashPro1 = os.urandom(32)
                RP_id = "localhost1"
                userName = "bobsmith1"
                response, status = makeCredProtocol2(newPIN, clientDataHashPro1, RP_id, userName)  #Make cred by protocol 2
                resetPowerCycle(True)
                if status == "00":
                    util.printcolor(util.GREEN,f"MAKE CRED DONE")
                    response, status = getCredsMetadataProtocol2(newPIN, CM_PERMISSION_BYTE, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET CREDS META DATA ({protocol}) EXPECTED -> {status}(CTAP2_OK)")
                        exist, max = getCredCountsInteger(response)
                        if exist == 1:
                            util.printcolor(util.GREEN,f"Expected existingResidentCredentialsCount")
                        else:
                            util.printcolor(util.RED,f"Unexpected existingResidentCredentialsCount")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET CREDS META DATA ({protocol}) FAILED WITH STATUS CODE: {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"MAKE CRED FAILED WITH STATUS CODE: {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"CHANGE PIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_ProtocolSwappingForKeyAgreementAndGetCredsMetaDataCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = getCredsMetadataWithoutPINSetProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"GET PIN TOKEN ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET PIN TOKEN ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = getCredsMetadataWithoutPINSetProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"GET PIN TOKEN ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"GET PIN TOKEN ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

############################################################################################################################################
############################################################################################################################################
############################################################################################################################################
############################################################################################################################################
############################################################################################################################################
#################################################### BELOW ARE THE HELPER METHODS ##########################################################
############################################################################################################################################
############################################################################################################################################
############################################################################################################################################
############################################################################################################################################
############################################################################################################################################
############################################################################################################################################





def extractCBORMap(response):
    if len(response) > 6:
        result = response[2:]
    else:
        result = ""
    return result


def getCredCountsInteger(response):
    cborData = extractCBORMap(response)
    print("cborData => ",cborData)
    data = bytes.fromhex(cborData)
    decoded = cbor2.loads(data)

    # Ensure CBOR is a map
    if not isinstance(decoded, dict):
        raise TypeError(f"Expected CBOR map, got {type(decoded).__name__}")

    existingResidentCredentialsCount = decoded.get(1)
    maxPossibleRemainingResidentCredentialsCount = decoded.get(2)

    # Ensure integer output
    if existingResidentCredentialsCount is not None:
        existingResidentCredentialsCount = int(existingResidentCredentialsCount)

    if maxPossibleRemainingResidentCredentialsCount is not None:
        maxPossibleRemainingResidentCredentialsCount = int(maxPossibleRemainingResidentCredentialsCount)

    return existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount

def getInfoMaximumCredsCountsInteger(response: str) -> int:
    cbor_hex = extractCBORMap(response)
    decoded = cbor2.loads(bytes.fromhex(cbor_hex))

    if not isinstance(decoded, dict):
        raise TypeError("Top-level CBOR object is not a map")

    # Get last (key, value) pair
    last_key, maxPossibleRemainingResidentCredentialsCount = next(reversed(decoded.items()))

    if not isinstance(maxPossibleRemainingResidentCredentialsCount, int):
        raise TypeError("Last CBOR value is not an integer")

    return maxPossibleRemainingResidentCredentialsCount


# def getCredCountsInteger(response):

#     data = bytes.fromhex(response)
#     # if data[]
#     existingResidentCredentialsCount = data[3] # int(data[3], 16)
#     maxPossibleRemainingResidentCredentialsCount = data[6] # int(data[6], 16)
#     return existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount

def getCredsMetadataWithoutPINSetProtocol1(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    response, status = getPINTokenWithPermissionWithoutPINSetProtocol1(pin, permission, mode)
    return response, status

def getCredsMetadataWithoutPINSetProtocol2(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    response, status = getPINTokenWithPermissionWithoutPINSetProtocol2(pin, permission, mode)
    return response, status


def getCredsMetadataProtocol1(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")

    if mode == "fidoDoc_PersistenTokenWithoutPCMRPermissionCase" or mode == "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase" or mode == "self_MakeCredWithPINSetGetPINToken_05":
        pinToken = getPINtokenPubkeyProtocol1(pin)
    elif mode == "self_ExpiredPersistenPinUvAuthTokenCase" or mode == "self_ExpiredPinUvAuthTokenCase":
        pinToken, pubKey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
        pinToken1, pubKey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
    else:
        pinToken, pubKey = getPINTokenWithPermissionProtocol1(pin, permission, mode)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    subCommand = 0x01  # getCredsMetadata
    if mode == "fidoDoc_IncorrectPinUvAuthParamCase":
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([0x0A]))[:16]
    elif mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        pinUvAuthParam = util.hmac_sha256(pinUvAuthTokenAssociatedRPID, bytes([subCommand]))[:16]
    elif mode == "self_TruncatedPinUvAuthParamFromPersistentTokenCase" or mode == "self_TruncatedPinUvAuthParamFromPinUvAuthTokenCase":
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:15]
    else:
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]

    apdu = getCredsMetadata_APDU_Protocol1(subCommand, pinUvAuthParam, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
    data = bytes.fromhex(response)
    resLength = len(data)
    if resLength > 3:
        existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)
        util.printcolor(util.YELLOW,f"existingResidentCredentialsCount = {existingResidentCredentialsCount}")
        util.printcolor(util.YELLOW,f"maxPossibleRemainingResidentCredentialsCount = {maxPossibleRemainingResidentCredentialsCount}")

    return response, status


def getCredsMetadataProtocol2(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")

    if mode == "fidoDoc_PersistenTokenWithoutPCMRPermissionCase" or mode == "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase" or mode == "self_MakeCredWithPINSetGetPINToken_05":
        pinToken, pubkey = getPINtokenPubkeyProtocol2(pin)
    elif mode == "self_ExpiredPersistenPinUvAuthTokenCase" or mode == "self_ExpiredPinUvAuthTokenCase":
        pinToken, pubKey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
        pinToken1, pubKey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
    else:
        pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin, permission, mode)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    subCommand = 0x01  # getCredsMetadata
    if mode == "fidoDoc_IncorrectPinUvAuthParamCase":
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([0x0A]))[:32]

    elif mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        pinUvAuthParam = util.hmac_sha256(pinUvAuthTokenAssociatedRPID, bytes([subCommand]))[:32]

    elif mode == "self_TruncatedPinUvAuthParamFromPersistentTokenCase" or mode == "self_TruncatedPinUvAuthParamFromPinUvAuthTokenCase":
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:31]

    else:
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]

    apdu = getCredsMetadata_APDU_Protocol2(subCommand, pinUvAuthParam, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
    data = bytes.fromhex(response)
    resLength = len(data)
    if resLength > 3:
        existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)
        util.printcolor(util.YELLOW,f"existingResidentCredentialsCount = {existingResidentCredentialsCount}")
        util.printcolor(util.YELLOW,f"maxPossibleRemainingResidentCredentialsCount = {maxPossibleRemainingResidentCredentialsCount}")

    return response, status


def getCredsMetadata_APDU_Protocol1(subCommand, pinUvAuthParam, mode):

    if mode == "fidoDoc_WithoutPinUvAuthParamCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: 1,                   # pinUvAuthProtocol =  1
            # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "fidoDoc_MissingMandatoryParamCase":
        cbor_map = {
            # 0x01: subCommand,          # subCommand
            0x03: 1,                   # pinUvAuthProtocol =  1
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "fidoDoc_UnsupportedProtocolCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: 3,                   # pinUvAuthProtocol =  3
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "self_InvalidSubcommandCase":
        cbor_map = {
            0x01: 0x0A,          # subCommand
            0x03: 1,                   # pinUvAuthProtocol =  1
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "self_MalformedOrderCBORCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: pinUvAuthParam,                  # pinUvAuthProtocol =  1
            0x04: 1       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
        }
    else:
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: 1,                   # pinUvAuthProtocol =  1
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu

def getCredsMetadata_APDU_Protocol2(subCommand, pinUvAuthParam, mode):

    if mode == "fidoDoc_WithoutPinUvAuthParamCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: 2,                   # pinUvAuthProtocol = 2
            # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "fidoDoc_MissingMandatoryParamCase":
        cbor_map = {
            # 0x01: subCommand,          # subCommand
            0x03: 2,                   # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "fidoDoc_UnsupportedProtocolCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: 3,                   # pinUvAuthProtocol =  3
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "self_InvalidSubcommandCase":
        cbor_map = {
            0x01: 0x0A,          # Invalid subCommand
            0x03: 2,                   # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "self_MalformedOrderCBORCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: pinUvAuthParam,                   # pinUvAuthProtocol = 2
            0x04: 2      # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    elif mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        cbor_map = {
            0x01: subCommand,          # subCommand
            # 0x03: 2,                   # pinUvAuthProtocol = 2
            # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }
    else:
        cbor_map = {
            0x01: subCommand,          # subCommand
            0x03: 2,                   # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex + "00"
    return apdu


def resetPowerCycle(resetRequired):
    if resetRequired == True:
        util.ResetCardPower()
        util.ConnectJavaCard()
    

def getPINRetriesProtocol1():
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        value = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value," ***************")
        return response, status


def getPINRetriesProtocol2():
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        value = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value," ***************")
        return response, status


def getRetryCountInInteger(response):
    # Convert to bytes
    data = bytes.fromhex(response)

    # Find index of key 0x03
    key = 0x03
    index = data.index(key)

    # Get value after key
    value_hex = data[index + 1]

    # Convert to int
    value_int = int(value_hex)
    return value_int




def createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper() + "00"
    return apdu







def verifyChangePIN(mode, curpin, rp, user):
    util.printcolor(util.YELLOW, "")
    # ------------------------------
    #   TEST DESCRIPTIONS
    # ------------------------------

    descriptions = {
        "pinVerify": """Test started: P-5:
Initiate a protected operation—such as credential management—to verify the newly updated PIN. Ensure all parameters in the verification command are correct. The authenticator should respond with CTAP2_OK.""",

}

    if mode == "pinVerify":
        util.printcolor(util.YELLOW, descriptions[mode])

    # ------------------------------
    #   SELECT + GETINFO
    # ------------------------------
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------
    #   COMMON FIELDS
    # ------------------------------
    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkeyTemp(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    # ------------------------------
    #   RP FEILD
    # ------------------------------
    rp_entity = {"id": rp, "name": rp}
    # ------------------------------
    #   USER FEILD
    # ------------------------------
    user_entity = {
        "id": user.encode(),
        "name": user,
        "displayName": user
    }
    # ----------------------------------------------------
    #        pubKeyCredParams 
    # ----------------------------------------------------
    pubKeyCredParams = [
            {"alg": -7, "type": "public-key"}
        ]

    makeCredAPDU = build_make_cred_apdu(
        clientDataHash,
        rp_entity,
        user_entity,
        pubKeyCredParams,
        pubkey,
        pinAuthToken)
    

    # ----------------------------------------------------
    #   SEND APDU (single or chained)
    # ----------------------------------------------------
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, f"Client PIN command as subcmd 0x01 make Credential: ", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                "Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result, status



# =================================================================
#    UPDATED build_make_cred_apdu()  (INCLUDES excludeList)
# =================================================================

def build_make_cred_apdu(clientDataHash, rp_entity, user_entity,
                         pubKeyCredParams,  pubkey, pinAuthToken):

    options = {"rk": True}

    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(user_entity).hex().upper()
    cbor_params  = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    # CBOR MAP (A8 = 8 entries)
    dataCBOR  = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params
    dataCBOR += "07" + cbor_options
    dataCBOR += "08" + cbor_pinAuth
    dataCBOR += "09" + "02"

    finalPayload = "01" + dataCBOR
    payload = bytes.fromhex(finalPayload)

    # Single APDU
    if len(payload) <= 255:
        lc = f"{len(payload):02X}"
        return "80100000" + lc + finalPayload

    # Chained APDU
    return util.build_chained_apdus(payload)

def getPINtokenPubkeyTemp(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    #print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey

def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    #print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey

def getPINtokenPubkeyProtocol2(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtokenProtocol2(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    #print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey

def changePINOnly(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

def createCBORchangePIN_protocol1(pinHashEnc, newPINenc, pinAuth, keyAgreement):
    """
    Constructs a CBOR-encoded APDU command for ClientPIN ChangePIN (subCommand = 0x04)
    """
    cbor_map = {
        1: 1,               # pinProtocol = 1
        2: 4,               # subCommand = 0x04 (change PIN)
        3: keyAgreement,    # keyAgreement (MAP)
        4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
        5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
        6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
    }

    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper() + "00"
    return apdu

def changePINProtocol1(current_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
    
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    padded_new_pin = pad_pin(new_pin)
    util.printcolor(util.ORANGE, f"Current PIN : {current_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(padded_new_pin)}")
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol2(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    util.printcolor(util.ORANGE, f"Current PIN : {old_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(newPinPadded)}")
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status



def changePINOnlyWithPinAuthToken(old_pin, new_pin, pinAuth):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    # combined = newPinEnc + pinHashEnc
    # hmac_value = util.hmac_sha256(sharedSecret[:32], combined)

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

def createCBORchangePIN(pinHashenc, newPINenc, auth, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
    cbor_auth        = cbor2.dumps(auth).hex().upper()
    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "04" # changePIN
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "04"+ cbor_auth
    dataCBOR = dataCBOR + "05"+ cbor_newPINenc
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createGetPINtoken(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def createGetPINtokenProtocol2(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
        "id": rp,  # id: unique identifier
         "name": rp  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    if MODE != "self_MakeCredChangeRKValueEachTime":    
        option  = {"rk": True}
    else:
        option  = {"rk": False}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A7"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Final payload = 01 prefix + dataCBOR
    full_data = "01" + dataCBOR
    byte_len = len(full_data) // 2
    

    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len <= 256:
        lc = format(byte_len, '02X')
        return "80100000" + lc + full_data  # single string

    # ========================
    # CASE 2: > 256 → Chain
    # ========================
    else:
        max_chunk_size = 255 * 2  # 510 hex chars
        chunks = wrap(full_data, max_chunk_size)
        apdus = []

        for i, chunk in enumerate(chunks):
            cla = "90" if i < len(chunks) - 1 else "80"
            ins = "10"
            p1 = "00"
            p2 = "00"
            lc = format(len(chunk) // 2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)

        return apdus  # list of chained APDUs


def createCBORmakeCredWithoutPINSet(clientDataHash, rp, user, credParam):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
        "id": rp,  # id: unique identifier
         "name": rp  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    if MODE == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        option  = {"alwaysUv": False, "rk": True}
    else:
        option = {"rk": True}
    
    

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    # cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    #uv                 = cbor2.dumps(extension).hex().upper()
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    #dataCBOR = dataCBOR + "05" + uv
    dataCBOR = dataCBOR + "07" + rk
    # dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    # dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Final payload = 01 prefix + dataCBOR
    full_data = "01" + dataCBOR
    byte_len = len(full_data) // 2
    

    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len <= 256:
        lc = format(byte_len, '02X')
        return "80100000" + lc + full_data  # single string

    # ========================
    # CASE 2: > 256 → Chain
    # ========================
    else:
        max_chunk_size = 255 * 2  # 510 hex chars
        chunks = wrap(full_data, max_chunk_size)
        apdus = []

        for i, chunk in enumerate(chunks):
            cla = "90" if i < len(chunks) - 1 else "80"
            ins = "10"
            p1 = "00"
            p2 = "00"
            lc = format(len(chunk) // 2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)

        return apdus  # list of chained APDUs




#############
#  [Info]
#    params:
#            curpin:  pin as string
#    clientDataHash: Is this the challenge hashed?
#                rp: This is the relying party (domain) as a string
#              user: The user to be at that RP
#  result: 009000 success
################################

def makeCred(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken);
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result, status

def makeCredProtocol2(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    global pinUvAuthTokenAssociatedRPID 
    pinUvAuthTokenAssociatedRPID = pinToken

    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken)
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result, status

def makeCredWithoutPINSetProtocol2(clientDataHash, rp, user):
    # util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    # pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)

    # pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    # global pinUvAuthTokenAssociatedRPID 
    # pinUvAuthTokenAssociatedRPID = pinAuthToken

    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCredWithoutPINSet(clientDataHash, rp, user, pubkey) + "00"
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result, status

import credBlob
import getAsseration
def extract_authdata_from_makecredential_response(hex_response):
    response_bytes = bytes.fromhex(hex_response)

    # Check status byte
    if response_bytes[0] != 0x00:
        raise ValueError(f"CTAP error: 0x{response_bytes[0]:02X}")

    # Decode CBOR response
    cbor_payload = response_bytes[1:]
    decoded_cbor = cbor2.loads(cbor_payload)

    print("Decoded CBOR keys:", decoded_cbor.keys())  # Should show [1, 2, 3]

    # Extract authData (it's under key 2)
    authdata = decoded_cbor.get(2)
    if not isinstance(authdata, bytes):
        raise TypeError("authData must be of type bytes")

    print("authdata (hex):", authdata.hex())
    return authdata

def authParsing(response):
    print("response",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info = getAsseration.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credid",credentialId)
    return credentialId


def makeAssertionProtocol2(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    
    apdu = createCBORmakeAssertionProtocol2(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status


def createCBORmakeAssertionProtocol2(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80100000" + format(length, '02X') + full_payload
    return apdu


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

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand 

def setpinProtocol2(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    response , status  = util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response, status

def encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 1,   # crv: P-256
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret

def wrong_Encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    # b = int2bytes(pub.x, 32)
    # str = util.toHex(b)
    # str = "123456" + str[6:]
    # b = bytes.fromhex(str)
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 3,   # crv: P-256
        -2: int2bytes(pub.x, 32),      #int2bytes(pub.x, 32),
        -3: int2bytes(pub.x, 32),      #int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret

# --- Utility Functions ---
def int2bytes(val, length):
    return val.to_bytes(length, 'big')

def bytes2int(b):
    return int.from_bytes(b, 'big')

def pad_pin1(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')
    if len(pin_bytes) < 6:
        raise ValueError("PIN must be at least 6 bytes")
    if len(pin_bytes) > 64:
        raise ValueError("PIN must not exceed 64 bytes")
    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def pad_pin(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    # if validate:
    #     if len(pin_bytes) < 6:
    #         raise ValueError("PIN must be at least 6 bytes")
    #     if len(pin_bytes) > 64:
    #         raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def wrong_pad_pin(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    # if validate:
    #     if len(pin_bytes) < 6:
    #         raise ValueError("PIN must be at least 6 bytes")
    #     if len(pin_bytes) > 64:
    #         raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(67, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def setpinProtocol1(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Re-select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = encapsulate_protocol1(decoded[1])
    padded_pin = pad_pin(pin, validate=False)  # skips min length check
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = hmac_sha256(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response , status

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def aes256_cbc_encrypt(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement):
    cose_key = cbor2.dumps(key_agreement).hex().upper()
    cbor_newpin = cbor2.dumps(new_pin_enc).hex().upper()
    cbor_auth = cbor2.dumps(pin_auth).hex().upper()

    data_cbor = "A5"
    data_cbor += "01" + "01"            # pinProtocol = 1
    data_cbor += "02" + "03"            # subCommand = 3 (SetPIN)
    data_cbor += "03" + cose_key        # keyAgreement
    data_cbor += "04" + cbor_auth       # pinAuth
    data_cbor += "05" + cbor_newpin     # newPinEnc

    length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor
    return apdu


def getAsserationProtocol2(curpin, clientDataHash, rp,response):
    credId =authParsing(response)
    response, status  = makeAssertionProtocol2(curpin, clientDataHash, rp, credId)
    return response, status

def makeCredProtocol1(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken = getPINtokenPubkeyProtocol1(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    global pinUvAuthTokenAssociatedRPID
    pinUvAuthTokenAssociatedRPID = pinToken
  
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCredProtocol1(clientDataHash, rp, user, pinAuthToken)
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result , status
   
def createCBORmakeCredProtocol1(clientDataHash, rp, user, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
           "id": rp,  # id: unique identifier
         "name": rp,  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        
    ]

    option  = {"rk": True}

    extension={"credProtect": 1, 
                "hmac-secret": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()

    ex                = cbor2.dumps(extension).hex().upper()

    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "06" + ex
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand

def getPINtokenPubkeyProtocol1(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = aes256_cbc_decrypt(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token

def aes256_cbc_decrypt(shared_secret: bytes, encrypted: bytes) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()
   #make credential


def getAsserationProtocol1(pin, username, rp,response):
    hashchallenge = os.urandom(32)
    credId = authParsing(response)
    result, status = authenticateUser(pin, hashchallenge, rp, credId)
    return result, status

def authenticateUser(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken = getPINtokenPubkeyProtocol1(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertionProtocol1(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result, status


def createCBORmakeAssertionProtocol1(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]


    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "01"                                        # 0x07: pinProtocol = 1

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80100000" + format(length, '02X') + full_payload
    return apdu

def newMinPinLength_forcechangePin_Protocol1(pinToken, subCommand, forceChangePIN):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    pinUvAuthParam = pinUvAuthParam[:16]

    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 1
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status


def newMinPinLength_forcechangePin_withMinLength_Protocol1(pinToken, subCommand, minimumLength, forceChangePIN):

    subCommandParams = {
        0x01: minimumLength,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True/False
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    pinUvAuthParam = pinUvAuthParam[:16]

    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 1
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status

def newMinPinLength_forcechangePin_withMinLength_Protocol2(pinToken, subCommand, minimumLength, forceChangePIN):

    subCommandParams = {
        0x01: minimumLength,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True/False
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
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status

def newMinPinLength_forcechangePin_Protocol2(pinToken, subCommand, forceChangePIN):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True
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
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status


def createGetPINtokenWithPermisionProtocol2(pinHashenc, key_agreement, permission, mode):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  

    if mode != "fidoDoc_PersistenTokenWithoutPCMRPermissionCase":
        dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createGetPINtokenWithPermisionProtocol1(pinHashenc, key_agreement, permission, mode):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "01" # Fido2 protocol 1
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    if mode != "fidoDoc_PersistenTokenWithoutPCMRPermissionCase":
        dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def getPINTokenWithPermissionWithoutPINSetProtocol2(curpin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    if mode == "self_ProtocolSwappingForKeyAgreementAndGetCredsMetaDataCase":
        cardPublickey, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    else:
        cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    getPINTokenAPDU = createGetPINtokenWithPermisionProtocol2(pinHashEnc, key_agreement, permission, mode)

    hexstring, status= util.APDUhex(getPINTokenAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);
    return hexstring, status

def getPINTokenWithPermissionProtocol2(curpin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    getPINTokenAPDU = createGetPINtokenWithPermisionProtocol2(pinHashEnc, key_agreement, permission, mode)

    hexstring, status= util.APDUhex(getPINTokenAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if status == "00":
        util.printcolor(util.GREEN, f"GET PIN TOKEN DONE")
    else:
        util.printcolor(util.RED, f"GET PIN TOKEN FAILED WITH STATUS CODE -> '{status}'")
        os._exit(0)
    print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey

def getPINTokenWithPermissionWithoutPINSetProtocol1(curpin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    if mode == "self_ProtocolSwappingForKeyAgreementAndGetCredsMetaDataCase":
        response, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    else:
        response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    pubkey = response[6:]
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(curpin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)


    getPinTokenAPDU = createGetPINtokenWithPermisionProtocol1(pinHashEnc, key_agreement, permission, mode)

    response, status= util.APDUhex(getPinTokenAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)

    return response, status

def getPINTokenWithPermissionProtocol1(curpin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    pubkey = response[6:]
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(curpin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)


    getPinTokenAPDU = createGetPINtokenWithPermisionProtocol1(pinHashEnc, key_agreement, permission, mode)

    response, status= util.APDUhex(getPinTokenAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)

    if status == "00":
        util.printcolor(util.GREEN, f"GET PIN TOKEN DONE")
    else:
        util.printcolor(util.RED, f"GET PIN TOKEN FAILED WITH STATUS CODE -> '{status}'")
        os._exit(0)
    
    print(f"getToken success: {response}")

    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = aes256_cbc_decrypt(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token, pubkey


def randomRPId(length):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def randomUser(length):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))
