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

oldPinUvAuthParam_Protocol1 = b""
oldPinUvAuthParam_Protocol2 = b""
oldPinUvAuthToken_Protocol1 = b""
oldPinUvAuthToken_Protocol2 = b""

duplicateDeleteCommandProtocol1 = ""
duplicateDeleteCommandProtocol2 = ""



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

globalRpIDBegin = ""
globalRpIDNext = ""
globalRPCollection = {}
globalUserEntityCollection = {}
globalCredentialIDCollection = {}
globalPublicKeyCollection = {}

new_Pin = ""
clientDataHash = os.urandom(32)
CM_PERMISSION_BYTE = 0x04
INVALID_PERMISSION_BYTE = 0x20
UNSUPPORTED_PERMISSION_BYTE = 0x8F
WRONG_PERMISSION_BYTE = 0x10
PCMR_PERMISSION_BYTE = 0x40
pinUvAuthTokenAssociatedRPID = b""
userEntity = ""
makeCredResponse = ""
MODE = ""

PK_1 = "PUBLIC_KEY_1"
PK_2 = "PUBLIC_KEY_2"
PK_3 = "PUBLIC_KEY_3"
PK_4 = "PUBLIC_KEY_4"
PK_5 = "PUBLIC_KEY_5"

US_1 = "USER_1"
US_2 = "USER_2"
US_3 = "USER_3"
US_4 = "USER_4"
US_5 = "USER_5"

CRED_1 = "CREDENTIAL_ID_1"
CRED_2 = "CREDENTIAL_ID_2"
CRED_3 = "CREDENTIAL_ID_3"
CRED_4 = "CREDENTIAL_ID_4"
CRED_5 = "CREDENTIAL_ID_5"


curpin="11223344"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "DELETE CREDENTIAL"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def executeDeleteCredentials(mode, reset_required, set_pin_required, make_cred_required, protocol):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL
    # maxCredCount = 50; #Comment it after static max cred count usage   
    maxCredCount = util.maxAllowedCredCount   #Remove Comment if you want dynamic max Cred Count and uncomment the resetCard and getInfo Command in fidoApplication.py
    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {

    "fidoTool_PositiveCase_with_CM": """Test started: P-1 :
        Precondition: Reset Authenticator, Set PIN and Create one discoverable credential
        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06) with pinUvAuthToken with cm permission, and check that authenticator succeds . 
        Send subsequent GetAssertion request with deleted credential credID specified in allow list and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""",

    "fidoDoc_PositiveCase": """Test started: P-2 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using valid parameters including credentialId, pinUvAuthProtocol, and pinUvAuthParam. The authenticator is expected to return CTAP2_OK.
        Send subsequent GetAssertion request with deleted credential credID specified in allow list and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""",
    
    "self_PositiveCaseMaxCredForSingleRp": """Test started: P-3 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, make maximum number of discoverable credentials for single Rp and all credentials have already been enumerated.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) to delete all credentials. The authenticator is expected to return CTAP2_OK each time.
        Send authenticatorCredentialManagement with subCommand enumerateCredentialsBegin (0x04) with correct RpIDHash. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",

    "self_PositiveCaseMaxCredForDifferentRp": """Test started: P-4 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, make maximum number of discoverable credentials for different Rp each time(i.e. 100 RPs = 100 Credentials) and all credentials have already been enumerated.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) to delete all credentials. The authenticator is expected to return CTAP2_OK each time.
        Send authenticatorCredentialManagement with subCommand enumerateCredentialsBegin (0x04) for each correct RpIDHash. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",

    "fidoDoc_MissingPinUvAuthParamCase": """Test started: P-5 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) without pinUvAuthParam. The authenticator is expected to return CTAP2_ERR_PUAT_REQUIRED.""",

    "fidoDoc_MissingMandatoryParamInSubCommandParamsCase": """Test started: P-6 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a valid pinUvAuthToken has been obtained.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) without mandatory parameters in subCommandParams. The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",

    "fidoDoc_UnsupportedPinUvAuthProtocolCase": """Test started: P-7 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using an unsupported pinUvAuthProtocol.
        The authenticator is expected to return CTAP1_ERR_INVALID_PARAMETER.""",
    
    "fidoDoc_InvalidPinUvAuthParamCase": """Test started: P-8 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) with an invalid pinUvAuthParam. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

    "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase": """Test started: P-9 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a pinUvAuthToken has been obtained without the cm permission.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a pinUvAuthToken without cm permission.
The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase": """Test started: P-10 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has an existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a pinUvAuthToken whose permissions RP ID does not match the RP ID of the credential. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_CredentialIDNotMatchCase": """Test started: P-11 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a valid pinUvAuthToken with cm permission has been obtained.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a credentialId that does not match any existing credential. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",
            
    "self_PinUvAuthParamWithDifferentSubCommandCase": """Test started: P-12 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) where pinUvAuthParam is computed using a different subCommand value. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_PinUvAuthParamExcludesSubCommandParamsCase": """Test started: P-13 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) where pinUvAuthParam is computed only over deleteCredential (0x06) and excludes subCommandParams. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

    "self_PinUvAuthParamWithDifferentCredentialIdCase": """Test started: P-14 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) where pinUvAuthParam is computed using one credentialId but a different credentialId is sent in subCommandParams. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_TruncatedPinUvAuthParamCase": """Test started: P-15 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a truncated pinUvAuthParam. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_LongerPinUvAuthParamCase": """Test started: P-16 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a pinUvAuthParam longer than the expected length. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_DifferentProcotolForPinUvAuthTokenCase": """Test started: P-17 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a pinUvAuthToken derived from a different shared secret than the one implied by pinUvAuthProtocol.
The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_PermissionOtherThanCMForPinUvAuthTokenCase": """Test started: P-18 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a pinUvAuthToken that includes permissions other than cm but excludes cm.
The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_OldPinUvAuthTokenCase": """Test started: P-19 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a pinUvAuthToken was obtained before permissions were updated.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using the already obtained pinUvAuthToken.
The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

    "self_IncorrectHashAlgorithmForPinUvAuthParamCase": """Test started: P-20 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and has at least one existing credential.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) where pinUvAuthParam is calculated using an incorrect hash algorithm for the selected pinUvAuthProtocol. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_CredentialIDIncorrectTypeCase": """Test started: P-21 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a credentialId of an incorrect CBOR type.
The authenticator is expected to return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
    
    "self_EmptyCredentialIDCase": """Test started: P-22 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using an empty credentialId. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",
    
    "self_VeryLargeCredentialIDCase": """Test started: P-23 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a credentialId exceeding supported size limits. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",
    
    
    "self_UnsupportedParamInSubCommandParamsCase": """Test started: P-24 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) including unsupported or unknown parameters in subCommandParams.
The authenticator is expected to return CTAP2_OK(if correct credential id is given in supported map and ignore unsupported map).""",


"self_UnsupportedTypeInSubCommandParamsCase": """Test started: P-25 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) including unsupported type(use different than "public-key") in subCommandParams.
        The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS(0x2E).""",

    
    "self_InvalidSubCommandValueCase": """Test started: P-26 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with an invalid subCommand value instead of deleteCredential (0x06).
The authenticator is expected to return CTAP2_ERR_INVALID_SUBCOMMAND.""",

    "self_MultipleCredentialIdEntriesCase": """Test started: P-27 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) providing multiple same credentialId entries.
        The authenticator is expected to return CTAP2_OK.
        Send subsequent GetAssertion request with deleted credential credID specified in allow list and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""",
    
    "self_AlreadyDeletedCredentialIdCase": """Test started: P-28 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and the credential has already been deleted.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using the same credentialId.
The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",
    
    "self_InvalidCBORMapOrderCase": """Test started: P-29 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
        Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using an invalid CBOR encoding(CBOR Map Ordering). The authenticator is expected to return CTAP2_OK.
        Send subsequent GetAssertion request with deleted credential credID specified in allow list and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""",
    
    "self_DuplicateDeleteCommandCase": """Test started: P-30 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a deleteCredential request was already processed.
Send the same authenticatorCredentialManagement deleteCredential (0x06) request again (exact same command previously processed)
The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_MissingPinUvAuthProtocolCase": """Test started: P-31 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) without pinUvAuthProtocol. The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",

    "self_SwapProtocolsForPinUvAuthTokenAndDeleteCommand": """Test started: P-32 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a pinUvAuthToken was generated using a different protocol.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using a mismatched pinUvAuthProtocol.
The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.
NOTE: Swap the protocols and perform again.""",
    
    "self_WithoutPinSetPinUvAuthTokenAndDelete": """Test started: P-33 :
        Precondition: Authenticator must be Reset, has No PIN Set, supports authenticatorCredentialManagement, and a pinUvAuthToken was generated without successful user verification/PIN. 
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06). The authenticator is expected to return CTAP2_ERR_PUAT_REQUIRED.""",

    "self_NonBytePinUvAuthParam": """Test started: P-34 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) providing pinUvAuthParam as a non-byte-string CBOR type.The authenticator is expected to return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",

    "self_NonIntegerPinUvAuthProtocol": """Test started: P-35 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) providing pinUvAuthProtocol as a non-integer CBOR type. The authenticator is expected to return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",

    "self_EmptySubCommandParamsMap": """Test started: P-36 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) with an empty subCommandParams map.
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",

    "self_IncorrectConcatenationOrderToComputePinUvAuthParam": """Test started: P-37 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) where pinUvAuthParam is computed using an incorrect concatenation order. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

    "self_PinUvAuthParamComputeOverOnlySubCommandParams": """Test started: P-38 :
        Precondition: Authenticator must be Reset, has PIN Set, and supports authenticatorCredentialManagement.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) where pinUvAuthParam is computed over only part of subCommandParams. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

    "self_PinUvAuthTokenAfterPowerCycleReset": """Test started: P-39 :
        Precondition: Authenticator must be power-cycled after a pinUvAuthToken was generated, has PIN Set, and supports authenticatorCredentialManagement. 
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) using the stale pinUvAuthToken. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

    "self_CredentialCreateWithoutPINSetAndDeleteCredCommandWithPinUvAuthParam": """Test started: P-40 :
        Precondition: Authenticator must be Reset, no PIN is set, supports authenticatorCredentialManagement, and the credential was created without PIN / user verification.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) including pinUvAuthProtocol. The authenticator is expected to return  CTAP2_ERR_PUAT_REQUIRED.""",

    "self_MissingSubCommand": """Test started: P-41 :
        Precondition: Authenticator must be Reset, PIN is set, supports authenticatorCredentialManagement, and the credential was created.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06) with missing subCommand. The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",

    "self_DeleteCredWithPersistentPinUvAuthTokenWithPCMRPermission": """Test started: P-42 :
        Precondition: Authenticator must be Reset, has PIN Set, supports authenticatorCredentialManagement, and a persistentPinUvAuthToken has been obtained with the pcmr permission.
Send authenticatorCredentialManagement with subCommand deleteCredential (0x06), all command parameters must be valid but use persistentPinUvAuthToken. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",

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
    pin = "11223344"
    
    if reset_required == "yes":
        response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        if status == "00":
            util.printcolor(util.GREEN,f"FIDO RESET DONE")
        else:
            util.printcolor(util.RED,f"FIDO RESET FAILED WITH STATUS CODE: {status}")
            # exit(0)
        


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
        if mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
            resetPowerCycle(True)
            clientDataHash = os.urandom(32)
            RP_domain = "localhost.com"
            user = "bobsmith234"
            response, status = makeCredWithoutPINSetProtocol2(clientDataHash, RP_domain, user)  #Make cred by protocol 2
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED DONE")
            else:
                util.printcolor(util.RED,f"MAKE CRED FAILED WITH STATUS CODE: {status}")
                exit(0)
            resetPowerCycle(True)
        else:
            resetPowerCycle(True)
            clientDataHash = os.urandom(32)
            RP_domain = "localhost.com"
            user = "bobsmith"
            response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user)  #Make cred by protocol 2
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED DONE")
            else:
                util.printcolor(util.RED,f"MAKE CRED FAILED WITH STATUS CODE: {status}")
                exit(0)
            resetPowerCycle(True)
    old_pin = pin

    if protocol == "PROTOCOL_ONE":
        PROTOCOL = 1
    else:
        PROTOCOL = 2
    # ------------------------------
    #  MODE → PIN VALUE
    # ------------------------------

    ########################################################################################
    ########################################################################################
    ######################### SCENARIOS EXECUTION STARTS FROM HERE #########################
    ########################################################################################
    ########################################################################################

    if mode == "fidoTool_PositiveCase_with_CM":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)
            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)

    if mode == "fidoDoc_PositiveCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entraIO.com"
            user = "Shubham"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)
            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1



    if mode == "self_PositiveCaseMaxCredForSingleRp":
            scenarioCount += 1
            makeCredCount = maxCredCount
            isRpIdSame = True
            rpId = "entra.com"
            makeCredentialNumberOfTimes(pin, makeCredCount, rpId, isRpIdSame)
            if protocol == "PROTOCOL_ONE":
                response, status = enumerateCredentialsBeginProtocol1(pin, CM_PERMISSION_BYTE, rpId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    totalCreds = getTotalCredentialsFromEnumerateCredentialsBeginCBOR(response)
                    if totalCreds == makeCredCount:
                        for j in range(totalCreds - 1):
                            n = j+1
                            response, status = enumerateCredentialsGetNextCredential(mode)
                            if status == "00":
                                util.printcolor(util.GREEN,f"{n} TIME - ENUMERATE CREDENTIALS GET NEXT CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                            else:
                                util.printcolor(util.RED,f"{n} TIME - ENUMERATE CREDENTIALS GET NEXT CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                                exit(0)
                    else:
                        util.printcolor(util.RED,f"TOTAL CREDS COUNT IS INCORRECT >> {totalCreds}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)

                for i in range(makeCredCount):
                    n = i+1
                    credKey = "CREDENTIAL_ID_" + str(n)
                    credId = getCredentialID(credKey)
                    response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    else:
                        util.printcolor(util.RED,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                
                response, status = enumerateCredentialsBeginProtocol1(pin, CM_PERMISSION_BYTE, rpId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = enumerateCredentialsBeginProtocol2(pin, CM_PERMISSION_BYTE, rpId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    totalCreds = getTotalCredentialsFromEnumerateCredentialsBeginCBOR(response)
                    if totalCreds == makeCredCount:
                        for j in range(totalCreds - 1):
                            n = j+1
                            response, status = enumerateCredentialsGetNextCredential(mode)
                            if status == "00":
                                util.printcolor(util.GREEN,f"{n} TIME - ENUMERATE CREDENTIALS GET NEXT CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                            else:
                                util.printcolor(util.RED,f"{n} TIME - ENUMERATE CREDENTIALS GET NEXT CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                                exit(0)
                    else:
                        util.printcolor(util.RED,f"TOTAL CREDS COUNT IS INCORRECT >> {totalCreds}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)

                for i in range(makeCredCount):
                    n = i+1
                    credKey = "CREDENTIAL_ID_" + str(n)
                    credId = getCredentialID(credKey)
                    response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    else:
                        util.printcolor(util.RED,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                
                response, status = enumerateCredentialsBeginProtocol2(pin, CM_PERMISSION_BYTE, rpId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    if mode == "self_PositiveCaseMaxCredForDifferentRp":
            scenarioCount += 1
            makeCredCount = maxCredCount
            isRpIdSame = False
            rpId = "entra.com"
            makeCredentialNumberOfTimes(pin, makeCredCount, rpId, isRpIdSame)
            if protocol == "PROTOCOL_ONE":
                for i in range(makeCredCount):
                    n = i+1
                    rpIdKey = "RP_" + str(n)
                    rpId = getRpID(rpIdKey)
                    response, status = enumerateCredentialsBeginProtocol1(pin, CM_PERMISSION_BYTE, rpId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                        totalCreds = getTotalCredentialsFromEnumerateCredentialsBeginCBOR(response)
                        if totalCreds != 1:
                            util.printcolor(util.RED,f"{n} TIME - TOTAL CREDS COUNT IS INCORRECT >> {totalCreds}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)

                for j in range(makeCredCount):
                    n = j+1
                    credKey = "CREDENTIAL_ID_" + str(n)
                    credId = getCredentialID(credKey)
                    response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    else:
                        util.printcolor(util.RED,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                
                for k in range(makeCredCount):
                    n = k+1
                    rpIdKey = "RP_" + str(n)
                    rpId = getRpID(rpIdKey)
                    response, status = enumerateCredentialsBeginProtocol1(pin, CM_PERMISSION_BYTE, rpId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                    else:
                        util.printcolor(util.RED,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                for i in range(makeCredCount):
                    n = i+1
                    rpIdKey = "RP_" + str(n)
                    rpId = getRpID(rpIdKey)
                    response, status = enumerateCredentialsBeginProtocol2(pin, CM_PERMISSION_BYTE, rpId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                        totalCreds = getTotalCredentialsFromEnumerateCredentialsBeginCBOR(response)
                        if totalCreds != 1:
                            util.printcolor(util.RED,f"{n} TIME - TOTAL CREDS COUNT IS INCORRECT >> {totalCreds}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)

                for j in range(makeCredCount):
                    n = j+1
                    credKey = "CREDENTIAL_ID_" + str(n)
                    credId = getCredentialID(credKey)
                    response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    else:
                        util.printcolor(util.RED,f"{n} TIME - DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                
                for k in range(makeCredCount):
                    n = k+1
                    rpIdKey = "RP_" + str(n)
                    rpId = getRpID(rpIdKey)
                    response, status = enumerateCredentialsBeginProtocol2(pin, CM_PERMISSION_BYTE, rpId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                    else:
                        util.printcolor(util.RED,f"{n} TIME - ENUMERATE CREDENTIALS BEGIN {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    if mode == "fidoDoc_MissingPinUvAuthParamCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PUAT_REQUIRED({status})")
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PUAT_REQUIRED({status})")
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "fidoDoc_MissingMandatoryParamInSubCommandParamsCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "fidoDoc_UnsupportedPinUvAuthProtocolCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "02":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP1_ERR_INVALID_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "02":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP1_ERR_INVALID_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "fidoDoc_InvalidPinUvAuthParamCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "fidoDoc_CredentialIDNotMatchCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
                util.printcolor(util.YELLOW,f"VALID CREDENTIAL ID >> {credId}")

                credId = "333333" + credId[6:]
                util.printcolor(util.YELLOW,f"INVALID CREDENTIAL ID >> {credId}")
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_PinUvAuthParamWithDifferentSubCommandCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1
            
    if mode == "self_PinUvAuthParamExcludesSubCommandParamsCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_PinUvAuthParamWithDifferentCredentialIdCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_TruncatedPinUvAuthParamCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_LongerPinUvAuthParamCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_DifferentProcotolForPinUvAuthTokenCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_PermissionOtherThanCMForPinUvAuthTokenCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, PCMR_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, PCMR_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_OldPinUvAuthTokenCase":
            scenarioCount += 1
            modeAgain = "self_OldPinUvAuthTokenCase_Again"
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)

                clientDataHash = os.urandom(32)
                rpId = "entraIO.com"
                user = "Shubham"
                credId = ""
                response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                    credId = getCredentialIDFromResponse(response)
                else:
                    util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                    exit(0)

                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, modeAgain)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)

                clientDataHash = os.urandom(32)
                rpId = "entraIO.com"
                user = "Shubham"
                credId = ""
                response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
                if status == "00":
                    util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                    credId = getCredentialIDFromResponse(response)
                else:
                    util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                    exit(0)

                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, modeAgain)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_IncorrectHashAlgorithmForPinUvAuthParamCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_CredentialIDIncorrectTypeCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_EmptyCredentialIDCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
                credId = ""
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_VeryLargeCredentialIDCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
                credId = credId + ("0"*80)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
                credId = credId + credId
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    if mode == "self_UnsupportedParamInSubCommandParamsCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_UnsupportedTypeInSubCommandParamsCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_InvalidSubCommandValueCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "3E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_INVALID_SUBCOMMAND({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "3E":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_INVALID_SUBCOMMAND({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_MultipleCredentialIdEntriesCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

        
    if mode == "self_AlreadyDeletedCredentialIdCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                        util.printcolor(util.YELLOW,f"AGAIN PERFORMING DELETE OPERATION FOR SAME DELETED CREDENTIAL_ID >> {credId}")
                        response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                        if status == "2E":
                            util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        else:
                            util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                        util.printcolor(util.YELLOW,f"AGAIN PERFORMING DELETE OPERATION FOR SAME DELETED CREDENTIAL_ID >> {credId}")
                        response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                        if status == "2E":
                            util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        else:
                            util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    
    if mode == "self_InvalidCBORMapOrderCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                    if status == "2E":
                        util.printcolor(util.GREEN,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> CTAP2_ERR_NO_CREDENTIALS({status})")
                        util.printcolor(util.CYAN,f"CREDENTIAL DELETE SUCCESSFULL FOR CREDENTIAL_ID >> {credId}")
                    else:
                        util.printcolor(util.RED,f"GET ASSERTION {protocol} RETURNED STATUS CODE >> ({status})")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_DuplicateDeleteCommandCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)

                modeAgain = "self_DuplicateDeleteCommandCase_Again"
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, modeAgain)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_OK({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)

                modeAgain = "self_DuplicateDeleteCommandCase_Again"
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, modeAgain)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_MissingPinUvAuthProtocolCase":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_SwapProtocolsForPinUvAuthTokenAndDeleteCommand":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_WithoutPinSetPinUvAuthTokenAndDelete":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredWithoutPINSetProtocol2(clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsWithoutPinProtocol1(CM_PERMISSION_BYTE, credId, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PUAT_REQUIRED({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsWithoutPinProtocol2(CM_PERMISSION_BYTE, credId, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PUAT_REQUIRED({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    if mode == "self_NonBytePinUvAuthParam":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_NonIntegerPinUvAuthProtocol":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_CBOR_UNEXPECTED_TYPE({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_EmptySubCommandParamsMap":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_IncorrectConcatenationOrderToComputePinUvAuthParam":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_PinUvAuthParamComputeOverOnlySubCommandParams":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_PinUvAuthTokenAfterPowerCycleReset":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    if mode == "self_CredentialCreateWithoutPINSetAndDeleteCredCommandWithPinUvAuthParam":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredWithoutPINSetProtocol2(clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsWithoutPinProtocol1(CM_PERMISSION_BYTE, credId, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PUAT_REQUIRED({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsWithoutPinProtocol2(CM_PERMISSION_BYTE, credId, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PUAT_REQUIRED({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_MissingSubCommand":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, credId, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_MISSING_PARAMETER({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    if mode == "self_DeleteCredWithPersistentPinUvAuthTokenWithPCMRPermission":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            credId = ""
            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user)
            if status == "00":
                util.printcolor(util.GREEN,f"MAKE CRED RETURNED STATUS CODE >> CTAP2_OK({status})")
                credId = getCredentialIDFromResponse(response)
            else:
                util.printcolor(util.RED,f"MAKE CRED RETURNED STATUS CODE >> ({status})")
                exit(0)

            if protocol == "PROTOCOL_ONE":
                response, status = deleteCredentialsProtocol1(pin, PCMR_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
                    exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = deleteCredentialsProtocol2(pin, PCMR_PERMISSION_BYTE, credId, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> CTAP2_ERR_PIN_AUTH_INVALID({status})")
                else:
                    util.printcolor(util.RED,f"DELETE CREDENTIAL {protocol} RETURNED STATUS CODE >> ({status})")
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

def checkEntityMatching(authUserEntity, recordedUserEntity, authCredentialID, recordedCredentialID, authPublicKey, recordedPublicKey):
    util.printcolor(util.BLUE,f"recordedUserEntity >> {recordedUserEntity}")
    util.printcolor(util.BLUE,f"currentUserEntity >> {authUserEntity}")
    if recordedUserEntity == authUserEntity:
        util.printcolor(util.GREEN,f"user (0x06): PublicKeyCredentialUserEntity, matching previously recorded")
    else:
        util.printcolor(util.RED,f"user (0x06): PublicKeyCredentialUserEntity, not matching previously recorded")
        exit(0)

    util.printcolor(util.BLUE,f"recordedCredentialID >> {recordedCredentialID}")
    util.printcolor(util.BLUE,f"currentCredentialID >> {authCredentialID}")
    if recordedCredentialID == authCredentialID:
        util.printcolor(util.GREEN,f"credentialID (0x07): PublicKeyCredentialDescriptor, matching previously recorded credentialID")
    else:
        util.printcolor(util.RED,f"credentialID (0x07): PublicKeyCredentialDescriptory, not matching previously recorded credentialID")
        exit(0)

    util.printcolor(util.BLUE,f"recordedPublicKey >> {recordedPublicKey}")
    util.printcolor(util.BLUE,f"currentPublicKey >> {authPublicKey}")
    is_valid_cose_key(authPublicKey)
    if recordedPublicKey == authPublicKey:
        util.printcolor(util.GREEN,f"publicKey (0x08): public key of the credential in COSE_Key format, matching previously recorded")
    else:
        util.printcolor(util.RED,f"publicKey (0x08): public key of the credential in COSE_Key format, not matching previously recorded")
        exit(0)

def is_valid_cose_key(hex_key: str):
    try:
        cbor_bytes = binascii.unhexlify(hex_key)
        cose = cbor2.loads(cbor_bytes)
    except Exception:
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)
  
    # Must be a CBOR map
    if not isinstance(cose, dict):
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    # COSE key labels
    KTY = 1
    ALG = 3
    CRV = -1
    X = -2
    Y = -3

    # Required for EC2 public key
    required_fields = {KTY, CRV, X, Y}

    # All keys must be integers
    if not all(isinstance(k, int) for k in cose.keys()):
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)

    # Must have required fields
    if not required_fields.issubset(cose.keys()):
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    # Validate key type
    if cose[KTY] != 2:  # EC2
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    # Validate curve
    if cose[CRV] != 1:  # P-256
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    # Validate coordinates
    x = cose[X]
    y = cose[Y]

    if not isinstance(x, bytes) or not isinstance(y, bytes):
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    if len(x) != 32 or len(y) != 32:
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    # Optional: validate alg if present
    if ALG in cose and not isinstance(cose[ALG], int):
        util.printcolor(util.RED,"COSE key format looks incorrect!")
        exit(0)


    util.printcolor(util.GREEN,"COSE key format looks correct!")


def checkCOSEKeyFormat(resp_hex):

    # Convert from hex → bytes
    resp = bytes.fromhex("A101"+resp_hex)

    cbor_payload = resp  # remaining bytes

    # 2. Decode CBOR
    decoded = cbor2.loads(cbor_payload)
    util.printcolor(util.BLUE,f"Decoded CBOR: {decoded}")

    # 3. Extract keyAgreement structure
    key_agreement = decoded.get(0x01)  # field "1" → keyAgreement

    if not key_agreement:
        raise ValueError("Missing keyAgreement field in response")

    util.printcolor(util.BLUE,f"\nkeyAgreement structure:  {key_agreement}")

    # 4. Validate required COSE key fields for ECDH (P-256)
    required_fields = {
    1: "kty",   # Key Type
    3: "alg",   # Algorithm
   -1: "crv",   # Curve
   -2: "x",     # X-coordinate
   -3: "y",     # Y-coordinate
    }

    missing = []
    for field in required_fields:
        if field not in key_agreement:
            missing.append(required_fields[field])

    if missing:
        raise ValueError(f"Missing COSE fields: {missing}")

    util.printcolor(util.YELLOW,"\nAll required COSE fields are present.")

    # 5. Additional correctness checks
    if key_agreement[1] != 2:
        raise ValueError("Invalid kty: expected 2 (EC2)")

    if key_agreement[3] not in [-25, -257]:
        util.printcolor(util.RED,"Warning: alg is unusual (expected -25 = ECDH-ES-HKDF-256)")
        exit(0)

    if key_agreement[-1] != 1:
        raise ValueError("Invalid crv: expected 1 (P-256)")
    

    util.printcolor(util.GREEN,"COSE key format looks correct!")


def extract_tag_58_value(hex_str):
    data = ""
    hex_str = hex_str[8:].upper()
    tag = hex_str[:2]
    if tag == "58":
        hex_str = hex_str[2:].upper()
        hexDataLen = hex_str[:2]
        dataLen = int(hexDataLen,16)
        hex_str = hex_str[2:].upper()
        if dataLen > 0:
            data = hex_str[:dataLen*2]
        else:
            ValueError("Found Zero bytes for CredentialID")
    else:
        ValueError("Key 58 Not found for extracting CredentialID")
    return data
    



from io import BytesIO

def parse_cbor_top_level_hex(hex_str):
    data_bytes = binascii.unhexlify(hex_str)
    stream = BytesIO(data_bytes)
    result = {}

    while stream.tell() < len(data_bytes):
        # Save start position
        start = stream.tell()

        # Decode one CBOR item (key)
        key = cbor2.load(stream)

        # Save position after key
        key_end = stream.tell()

        # Decode one CBOR item (value)
        value_start = stream.tell()
        value = cbor2.load(stream)
        value_end = stream.tell()

        # Slice raw bytes for value
        value_bytes = data_bytes[value_start:value_end]
        value_hex = value_bytes.hex().upper()

        # Store key and its full hex value
        result[key] = value_hex

    return result

def extractCredentialCBOR(hex_str):
    userEntity_0x06 = ""
    credentialID_0x07 = ""
    publicKey_0x08 = ""
    # Convert hex → bytes
    raw_bytes = bytes.fromhex(hex_str)

    # Remove CTAP status byte (0x00)
    cbor_bytes = raw_bytes[2:]

    hex_str = cbor_bytes.hex().upper()

    parsed = parse_cbor_top_level_hex(hex_str)
    for k, v in parsed.items():
        key = "0x"+f"{k:02X}"
        if key == "0x06":
            userEntity_0x06 = v
        if key == "0x07":
            credentialID_0x07 = extract_tag_58_value(v)
        if key == "0x08":
            publicKey_0x08 = v
        print(f"{key}: {v}")

    return userEntity_0x06, credentialID_0x07, publicKey_0x08

def extractAnyFieldFromResponseCBOR(hex_str, EXTRACTION_KEY):
    if EXTRACTION_KEY == "0x06":
        util.printcolor(util.CYAN,f"Extract and Return >> {EXTRACTION_KEY} Value")
    elif EXTRACTION_KEY == "0x07":
        util.printcolor(util.CYAN,f"Extract and Return >> {EXTRACTION_KEY} Value")
    elif EXTRACTION_KEY == "0x08":
        util.printcolor(util.CYAN,f"Extract and Return >> {EXTRACTION_KEY} Value")
    elif EXTRACTION_KEY == "0x09":
        util.printcolor(util.CYAN,f"Extract and Return >> {EXTRACTION_KEY} Value")
    elif EXTRACTION_KEY == "0x0A":
        util.printcolor(util.CYAN,f"Extract and Return >> {EXTRACTION_KEY} Value")
    elif EXTRACTION_KEY == "0x0C":
        util.printcolor(util.CYAN,f"Extract and Return >> {EXTRACTION_KEY} Value")
    else:
        util.printcolor(util.RED,f"Key - {EXTRACTION_KEY} Not Found in Response")
        exit(0)

    Extracted_Value = ""
    # Convert hex → bytes
    raw_bytes = bytes.fromhex(hex_str)

    # Remove CTAP status byte (0x00)
    cbor_bytes = raw_bytes[2:]

    hex_str = cbor_bytes.hex().upper()

    parsed = parse_cbor_top_level_hex(hex_str)
    for k, v in parsed.items():
        key = "0x"+f"{k:02X}"
        if key == EXTRACTION_KEY:
            Extracted_Value = v
        print(f"{key}: {v}")

    return Extracted_Value



def verifyEnumerateNextCredentialResponseCBOR(hex_str):
    checkFields = "678ABC"
    validateFields = ""
    # Convert hex → bytes
    raw_bytes = bytes.fromhex(hex_str)

    # Remove CTAP status byte (0x00)
    cbor_bytes = raw_bytes[2:]

    hex_str = cbor_bytes.hex().upper()

    parsed = parse_cbor_top_level_hex(hex_str)
    for k, v in parsed.items():
        key = "0x"+f"{k:02X}"
        if key == "0x06":
            validateFields = validateFields + "6"
            util.printcolor(util.CYAN,f"Response Contains >> [user (0x06): PublicKeyCredentialUserEntity]")
        elif key == "0x07":
            validateFields = validateFields + "7"
            util.printcolor(util.CYAN,f"Response Contains >> [credentialID (0x07): PublicKeyCredentialDescriptor]")
        elif key == "0x08":
            validateFields = validateFields + "8"
            util.printcolor(util.CYAN,f"Response Contains >> [publicKey (0x08): public key of the credential in COSE_Key format]")    
        elif key == "0x0A":
            validateFields = validateFields + "A"
            util.printcolor(util.CYAN,f"Response Contains >> [credProtect (0x0A): credential protection policy]")  
        elif key == "0x0B":
            validateFields = validateFields + "B"
            util.printcolor(util.CYAN,f"Response Contains >> [largeBlobKey (0x0B): the contents, if any, of the stored largeBlobKey]")            
        elif key == "0x0C":
            validateFields = validateFields + "C"
            util.printcolor(util.CYAN,f"Response Contains >> [thirdPartyPayment (0x0C): present only if the authenticator supports the thirdPartyPayment extension. True if the credential is third-party payment enabled, false otherwise.]")
        util.printcolor(util.YELLOW, f"{key}: {v}")
    validationMsgForMissingFieldInNextCred(missing_chars(validateFields, checkFields))


def validationMsgForMissingFieldInNextCred(missingFields):
    result = ""
    for ch in missingFields:
        result = ch
        if result == "6":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [user (0x06): PublicKeyCredentialUserEntity]")
            exit(0)
        if result == "7":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [credentialID (0x07): PublicKeyCredentialDescriptor]")
            exit(0)
        if result == "8":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [publicKey (0x08): public key of the credential in COSE_Key format]")
            exit(0)
        if result == "A":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [credProtect (0x0A): credential protection policy]")
            exit(0)
        if result == "B":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [largeBlobKey (0x0B): the contents, if any, of the stored largeBlobKey]")
        if result == "C":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [thirdPartyPayment (0x0C): present only if the authenticator supports the thirdPartyPayment extension. True if the credential is third-party payment enabled, false otherwise]")


def verifyEnumerateCredentialResponseCBOR(hex_str):
    checkFields = "6789ABC"
    validateFields = ""
    # Convert hex → bytes
    raw_bytes = bytes.fromhex(hex_str)

    # Remove CTAP status byte (0x00)
    cbor_bytes = raw_bytes[2:]

    hex_str = cbor_bytes.hex().upper()

    parsed = parse_cbor_top_level_hex(hex_str)
    for k, v in parsed.items():
        key = "0x"+f"{k:02X}"
        if key == "0x06":
            validateFields = validateFields + "6"
            util.printcolor(util.CYAN,f"Response Contains >> [user (0x06): PublicKeyCredentialUserEntity]")
        elif key == "0x07":
            validateFields = validateFields + "7"
            util.printcolor(util.CYAN,f"Response Contains >> [credentialID (0x07): PublicKeyCredentialDescriptor]")
        elif key == "0x08":
            validateFields = validateFields + "8"
            util.printcolor(util.CYAN,f"Response Contains >> [publicKey (0x08): public key of the credential in COSE_Key format]")
        elif key == "0x09":
            validateFields = validateFields + "9"
            util.printcolor(util.CYAN,f"Response Contains >> [totalCredentials (0x09): total number of credentials for this RP]")            
        elif key == "0x0A":
            validateFields = validateFields + "A"
            util.printcolor(util.CYAN,f"Response Contains >> [credProtect (0x0A): credential protection policy]")  
        elif key == "0x0B":
            validateFields = validateFields + "B"
            util.printcolor(util.CYAN,f"Response Contains >> [largeBlobKey (0x0B): the contents, if any, of the stored largeBlobKey]")            
        elif key == "0x0C":
            validateFields = validateFields + "C"
            util.printcolor(util.CYAN,f"Response Contains >> [thirdPartyPayment (0x0C): present only if the authenticator supports the thirdPartyPayment extension. True if the credential is third-party payment enabled, false otherwise.]")
        util.printcolor(util.YELLOW, f"{key}: {v}")
    validationMsgForMissingField(missing_chars(validateFields, checkFields))


def validationMsgForMissingField(missingFields):
    result = ""
    for ch in missingFields:
        result = ch
        if result == "6":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [user (0x06): PublicKeyCredentialUserEntity]")
            exit(0)
        if result == "7":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [credentialID (0x07): PublicKeyCredentialDescriptor]")
            exit(0)
        if result == "8":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [publicKey (0x08): public key of the credential in COSE_Key format]")
            exit(0)
        if result == "9":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [totalCredentials (0x09): total number of credentials for this RP]")
            exit(0)
        if result == "A":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [credProtect (0x0A): credential protection policy]")
            exit(0)
        if result == "B":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [largeBlobKey (0x0B): the contents, if any, of the stored largeBlobKey]")
        if result == "C":
            util.printcolor(util.RED,f"MISSING FIELD IN RESPONSE >> [thirdPartyPayment (0x0C): present only if the authenticator supports the thirdPartyPayment extension. True if the credential is third-party payment enabled, false otherwise]")

            


def missing_chars(str1, str2):
    result = ""
    for ch in str2:
        if ch not in str1:
            result += ch
    return result.upper()

    

def storeRpID(key, value):
    print("RpID : ",value,"; Stored with Key : ",key)
    globalRPCollection[key] = value
    print("Length after store:", len(globalRPCollection))

def getRpID(key):
    print("Getting RpID for Key : "+key)
    return globalRPCollection.get(key)  # None if not found

def storeUserEntity(key, value):
    print("User Entity : ",value,"; Stored with Key : ",key)
    globalUserEntityCollection[key] = value
    print("Length after store:", len(globalUserEntityCollection))

def getUserEntity(key):
    print("Getting User Entity for Key : "+key)
    return globalUserEntityCollection.get(key)  # None if not found

def storeCredentialID(key, value):
    print("CredentialID : ",value,"; Stored with Key : ",key)
    globalCredentialIDCollection[key] = value
    print("Length after store:", len(globalCredentialIDCollection))

def getCredentialID(key):
    print("Getting CredentialID for Key : "+key)
    return globalCredentialIDCollection.get(key)  # None if not found

def storePublicKey(key, value):
    print("PublicKey : ",value,"; Stored with Key : ",key)
    globalPublicKeyCollection[key] = value
    print("Length after store:", len(globalPublicKeyCollection))

def getPublicKey(key):
    print("Getting PublicKey for Key : "+key)
    return globalPublicKeyCollection.get(key)  # None if not found



def verifyRpIDHash(rpID, authenticatorRpIDHash):
    check = False
    generatedRpIDHash = generateRpIDHash(rpID)
    if authenticatorRpIDHash == generatedRpIDHash:
        util.printcolor(util.GREEN,f"authenticatorRpIDHash and generatedRpIDHash macthed for the rpID: {rpID}")
        check = True
    else:
        util.printcolor(util.RED,f"authenticatorRpIDHash and generatedRpIDHash NOT macthed for the rpID: {rpID}")
    
    return check


def extractCBORRpIDAndHash(hex_string: str):
    """
    Extract CBOR from framed hex input and return values of keys 0x03 and 0x04
    as hex strings.
    """

    raw = bytes.fromhex(hex_string)

    # Find CBOR map start (A0–BF)
    cbor_start = next(
        (i for i, b in enumerate(raw) if 0xA0 <= b <= 0xBF),
        None
    )

    if cbor_start is None:
        raise ValueError("CBOR map not found")

    cbor_map = cbor2.loads(raw[cbor_start:])

    if not isinstance(cbor_map, dict):
        raise ValueError("Decoded CBOR is not a map")

    if 0x03 not in cbor_map or 0x04 not in cbor_map:
        raise KeyError("Keys 0x03 and/or 0x04 not found")

    # 🔑 Key 0x03 → CBOR-encode → hex
    val_03 = cbor_map[0x03]
    hex_03 = cbor2.dumps(val_03).hex()  #### This is 0x03 value in Hex format


    ########### FOR CONVERTING HEX STRING INTO TEXT #############
    # hex_03 = cbor2.dumps(val_03).hex()
    cbor_bytes = bytes.fromhex(hex_03)

    # 1️⃣ Decode CBOR
    decoded_obj = cbor2.loads(cbor_bytes)

    # 2️⃣ Extract the text safely
    if isinstance(decoded_obj, str):
        text_03 = decoded_obj
    elif isinstance(decoded_obj, dict):
        # extract first string value
        text_03 = next(v for v in decoded_obj.values() if isinstance(v, str))
    else:
        raise ValueError("No UTF-8 text found in CBOR")
    
    ########################################################


    # 🔑 Key 0x04 → bytes → hex
    val_04 = cbor_map[0x04]
    if not isinstance(val_04, bytes):
        raise TypeError("Value for key 0x04 is not bytes")

    hex_04 = val_04.hex()
    text_03_Len = len(text_03)
    hex_04_Len = int(len(hex_04)/2)


    
    util.printcolor(util.YELLOW,f"rp (0x03) : {text_03}({text_03_Len} bytes)")
    util.printcolor(util.YELLOW,f"rpIDHash (0x04) : {hex_04}({hex_04_Len} Bytes)")

    return text_03, hex_04


def enumerateCredentialsGetNextCredential(mode):
    # util.APDUhex("00a4040008a0000006472f0001","Select applet")
    response, status = util.APDUhex("80100000040aa1010500", "enumerateCredentialsGetNextCredential(0x05)")
    return response, status

def getTotalCredentialsFromEnumerateCredentialsBeginCBOR(response):
    # text_03, hex_04 = extractCBORRpIDAndHash(response)
    hexCBOR = extractCBORMap(response)
    # Decode CBOR
    cbor_bytes = binascii.unhexlify(hexCBOR)
    decoded = cbor2.loads(cbor_bytes)

    # Print all components
    # util.printcolor(util.YELLOW,f"Decoded CBOR components:")
    # for k, v in decoded.items():
    #     util.printcolor(util.YELLOW,f"{k}: {v}")

    total_credentials = decoded.get(9)

    # Return only the last component
    totalCredentials = int(total_credentials)
    util.printcolor(util.YELLOW,f"totalCredentials(0x09) : {totalCredentials}")
    if totalCredentials > 1:
        util.printcolor(util.YELLOW,f"Allowed to Send enumerateCredentialsGetNextCredential (0x05)")

    return totalCredentials


def makeCredentialNumberOfTimes(pin, maxCredCount, rp, isRpIDSame):
    for x1 in range(maxCredCount): 
        nTime = x1+1
        clientDataHash = os.urandom(32)
        if isRpIDSame == True:
            RP_domain = rp
        else:
            rpKey = "RP_" + str(nTime)    #key format ----> RP_X   (X will be number)
            RP_domain = randomRPId(10)+".com"
            storeRpID(rpKey, RP_domain)
        if MODE == "self_UserEntityTruncationCheck":
            user = randomUser(150)
        else:
            user = randomUser(8)
        util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred {nTime} -> {util.toHex(clientDataHash)}")
        util.printcolor(util.YELLOW,f"RP Id for Make Cred {nTime} -> {RP_domain}")
        util.printcolor(util.YELLOW,f"User for Make Cred {nTime} -> {user}")

        response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user)  #Make cred by protocol 2
        global makeCredResponse
        makeCredResponse = response
        if status == "00":
            util.printcolor(util.GREEN,f"{nTime} Time MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
            userKey = "USER_" + str(nTime)    #key format ----> USER_X   (X will be number)
            storeUserEntity(userKey, userEntity)
            
            credID = getCredentialIDFromResponse(response)
            credentialID = str(credID).upper()
            credKey = "CREDENTIAL_ID_" + str(nTime)    #key format ----> CREDENTIAL_ID_X   (X will be number)
            storeCredentialID(credKey, credentialID)

            publicKey = getPublicKeyFromResponse(response)
            credentialPublicKey = str(publicKey).upper()
            publicKey_Key = "PUBLIC_KEY_" + str(nTime)    #key format ----> PUBLIC_KEY_X   (X will be number)
            storePublicKey(publicKey_Key, credentialPublicKey)
        else:
            util.printcolor(util.RED,f"{nTime} Time MAKE CRED BY PROTOCOL FAILED WITH STATUS CODE -> {status}")
            exit(0)
        resetPowerCycle(True)
    return response, status

def makeCredentialNumberOfTimesWithRPsParam(pin, maxCredCount, rpIDLen, rpNameLen):
    for x1 in range(maxCredCount): 
        nTime = x1+1
        clientDataHash = os.urandom(32)
        user = randomUser(14)
        userLen = int(len(user))
        rpID = randomRPId(rpIDLen-4)+".com"
        if rpIDLen == 0:
            rpID = ""
        if x1 == 0:
            global globalRpIDBegin
            globalRpIDBegin = rpID
        else:
            global globalRpIDNext
            globalRpIDNext = rpID
        rpName = randomRPId(rpNameLen) 
        util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred {nTime} -> {util.toHex(clientDataHash)}(32 Bytes)")
        util.printcolor(util.YELLOW,f"RP Id for Make Cred {nTime} -> {rpID}({rpIDLen})")
        util.printcolor(util.YELLOW,f"RP Name for Make Cred {nTime} -> {rpName}({rpNameLen})")
        util.printcolor(util.YELLOW,f"User for Make Cred {nTime} -> {user}({userLen})")

        response, status = makeCredProtocol2WithRPsParam(pin,clientDataHash, rpID, rpName, user)  #Make cred by protocol 2
        global makeCredResponse
        makeCredResponse = response
        if status == "00":
            util.printcolor(util.GREEN,f"{nTime} Time MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED,f"{nTime} Time MAKE CRED FAILED WITH STATUS CODE -> {status}")
            exit(0)
        resetPowerCycle(True)
    return response, status


def makeCredentialNumberOfTimesWithRPsParamWithNoResultCheck(pin, maxCredCount, rpIDLen, rpNameLen):
    for x1 in range(maxCredCount): 
        nTime = x1+1
        clientDataHash = os.urandom(32)
        user = randomUser(14)
        userLen = int(len(user))
        rpID = randomRPId(rpIDLen-4)+".com"
        if rpIDLen == 0:
            rpID = ""
        if x1 == 0:
            global globalRpIDBegin
            globalRpIDBegin = rpID
        else:
            global globalRpIDNext
            globalRpIDNext = rpID
        rpName = randomRPId(rpNameLen) 
        util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred {nTime} -> {util.toHex(clientDataHash)}(32 Bytes)")
        util.printcolor(util.YELLOW,f"RP Id for Make Cred {nTime} -> {rpID}({rpIDLen})")
        util.printcolor(util.YELLOW,f"RP Name for Make Cred {nTime} -> {rpName}({rpNameLen})")
        util.printcolor(util.YELLOW,f"User for Make Cred {nTime} -> {user}({userLen})")

        response, status = makeCredProtocol2WithRPsParam(pin,clientDataHash, rpID, rpName, user)  #Make cred by protocol 2
        global makeCredResponse
        makeCredResponse = response
    return response, status




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


def enumerateCredentialsBeginProtocol2(pin, permission, rp, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin,  permission, mode)

    if mode == "fidoDoc_InvalidPinUvAuthParamWithoutPermission" or mode == "self_GetPINTokenWith0x05":
        pinToken, pubkey = getPINtokenPubkeyProtocol2(pin)
    subCommand = 0x04  # enumerateCredentialsBegin

    if mode == "fidoDoc_PinAuthTokenAssociatedRpID":
        apdu = enumerateCredentialsBegin_APDU_Procotol2(subCommand, pinUvAuthTokenAssociatedRPID, rp, mode)
    else:
        apdu = enumerateCredentialsBegin_APDU_Procotol2(subCommand, pinToken, rp, mode)

    if mode == "self_ProtocolSwapping":
        apdu = enumerateCredentialsBegin_APDU_Procotol1(subCommand, pinToken, rp, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)
    return response, status

def enumerateCredentialsBeginProtocol1(pin, permission, rp, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")

   
    pinToken, pubkey = getPINTokenWithPermissionProtocol1(pin,  permission, mode)
    
        
    if mode == "fidoDoc_InvalidPinUvAuthParamWithoutPermission" or mode == "self_GetPINTokenWith0x05":
        pinToken = getPINtokenPubkeyProtocol1(pin)
    subCommand = 0x04  # enumerateCredentialsBegin
    if mode == "fidoDoc_PinAuthTokenAssociatedRpID":
        apdu = enumerateCredentialsBegin_APDU_Procotol1(subCommand, pinUvAuthTokenAssociatedRPID, rp, mode)
    else:
        apdu = enumerateCredentialsBegin_APDU_Procotol1(subCommand, pinToken, rp, mode)

    if mode == "self_ProtocolSwapping":
        apdu = enumerateCredentialsBegin_APDU_Procotol2(subCommand, pinToken, rp, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)
    return response, status



def deleteCredentialsProtocol1(pin, permission, credId, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    if mode == "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase":
        pinToken = getPINtokenPubkeyProtocol1(pin)
    elif mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        pinToken = pinUvAuthTokenAssociatedRPID
    elif mode == "self_DifferentProcotolForPinUvAuthTokenCase":
        pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
    else:
        pinToken, pubkey = getPINTokenWithPermissionProtocol1(pin, permission, mode)

    if mode == "self_OldPinUvAuthTokenCase":
        global oldPinUvAuthToken_Protocol1
        oldPinUvAuthToken_Protocol1 = pinToken
    
    subCommand = 0x06  #delecredential credential 
    if mode == "self_InvalidSubCommandValueCase":
        subCommand = 0x0A
    util.printcolor(util.YELLOW,f"DELETING CREDENTIAL WITH CREDENTIAL_ID >> {credId}")
    if mode == "self_OldPinUvAuthTokenCase_Again":
        apdu = deleteCredInfoProtocol1(oldPinUvAuthToken_Protocol1,subCommand, credId, mode)
    elif mode == "self_DuplicateDeleteCommandCase":
        apdu = deleteCredInfoProtocol1(pinToken,subCommand, credId, mode)
        global duplicateDeleteCommandProtocol1
        duplicateDeleteCommandProtocol1 = apdu
    elif mode == "self_DuplicateDeleteCommandCase_Again":
        apdu = duplicateDeleteCommandProtocol1
    elif mode == "self_SwapProtocolsForPinUvAuthTokenAndDeleteCommand":
        apdu = deleteCredInfoProtocol2(pinToken,subCommand, credId, mode)
    else:
        if mode == "self_PinUvAuthTokenAfterPowerCycleReset":
            resetPowerCycle(True)
            util.APDUhex("00a4040008a0000006472f0001", "Select applet")
        apdu = deleteCredInfoProtocol1(pinToken,subCommand, credId, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status

def deleteCredentialsProtocol2(pin, permission, credId, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    if mode == "fidoDoc_PinUvAuthTokenWithoutCMPermissionCase":
        pinToken, pubkey = getPINtokenPubkeyProtocol2(pin)
    elif mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        pinToken = pinUvAuthTokenAssociatedRPID
    elif mode == "self_DifferentProcotolForPinUvAuthTokenCase":
        pinToken, pubkey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
    else:
        pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
        


    if mode == "self_OldPinUvAuthTokenCase":
        global oldPinUvAuthToken_Protocol2
        oldPinUvAuthToken_Protocol2 = pinToken

    subCommand = 0x06  #delecredential credential 
    if mode == "self_InvalidSubCommandValueCase":
        subCommand = 0x0A
    util.printcolor(util.YELLOW,f"DELETING CREDENTIAL WITH CREDENTIAL_ID >> {credId}")
    if mode == "self_OldPinUvAuthTokenCase_Again":
        apdu = deleteCredInfoProtocol2(oldPinUvAuthToken_Protocol2,subCommand, credId, mode)
    elif mode == "self_DuplicateDeleteCommandCase":
        apdu = deleteCredInfoProtocol2(pinToken,subCommand, credId, mode)
        global duplicateDeleteCommandProtocol2
        duplicateDeleteCommandProtocol2 = apdu
    elif mode == "self_DuplicateDeleteCommandCase_Again":
        apdu = duplicateDeleteCommandProtocol2
    elif mode == "self_SwapProtocolsForPinUvAuthTokenAndDeleteCommand":
        apdu = deleteCredInfoProtocol1(pinToken,subCommand, credId, mode)
    else:
        if mode == "self_PinUvAuthTokenAfterPowerCycleReset":
            resetPowerCycle(True)
            util.APDUhex("00a4040008a0000006472f0001", "Select applet")
        apdu = deleteCredInfoProtocol2(pinToken,subCommand, credId, mode)


    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status


def deleteCredentialsWithoutPinProtocol2(permission, credId, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    subCommand = 0x06  #delecredential credential 
    apdu = deleteCredInfoWithoutPinProtocol2(subCommand, credId, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status

def deleteCredentialsWithoutPinProtocol1(permission, credId, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    subCommand = 0x06  #delecredential credential 
    apdu = deleteCredInfoWithoutPinProtocol1(subCommand, credId, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status

def getAssertionProtocol1(curpin, clientDataHash, rp, credId, mode):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken = getPINtokenPubkeyProtocol1(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    
    apdu = createCBORmakeAssertion_Protocol1(clientDataHash, rp, pinAuthToken, credId, mode)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status

def getAssertionProtocol2(curpin, clientDataHash, rp, credId, mode):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    
    apdu = createCBORmakeAssertion_Protocol2(clientDataHash, rp, pinAuthToken, credId, mode)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status

def createCBORmakeAssertion_Protocol1(cryptohash, rp, pinAuthToken, credId, mode):
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

def createCBORmakeAssertion_Protocol2(cryptohash, rp, pinAuthToken, credId, mode):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 1

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


def deleteCredInfoProtocol1(pinToken, subCommand, credential_id, mode):
    
    if mode == "self_CredentialIDIncorrectTypeCase":
        #delete credential
        subCommandParams = {
            0x02: [
                { # credentialId descriptor
                1: bytes.fromhex(credential_id),
                2: "public-key"
                }
            ]
        }
    elif mode == "self_UnsupportedParamInSubCommandParamsCase":
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key",
            },
            0x04: {  # credentialId descriptor
                "id": "piyush".encode(),
                "name": "abcdef.com",
            }
        }
    elif mode == "self_UnsupportedTypeInSubCommandParamsCase":
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "private-key"
            }
        }
    elif mode == "self_MultipleCredentialIdEntriesCase":
         #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id), "id": bytes.fromhex(credential_id), "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }
    elif mode == "self_EmptySubCommandParamsMap":
        #delete credential
        subCommandParams = {
            # 0x02: {  # credentialId descriptor
            #     "id": bytes.fromhex(credential_id),
            #     "type": "public-key"
                
            # }
        }
    else:
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }

    if mode == "self_PinUvAuthParamWithDifferentCredentialIdCase":
        util.printcolor(util.YELLOW,f"VALID CREDENTIAL ID FOR pinUvAuthParam IN subCommandParams >> {credential_id}")
        credential_id = "333333" + credential_id[6:]
        util.printcolor(util.YELLOW,f"INVALID CREDENTIAL ID FOR pinUvAuthParam IN subCommandParams >> {credential_id}")
        #delete credential
        diSubCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }
        cbor_params = cbor2.dumps(diSubCommandParams)
    else:
        # Compute pinUvAuthParam
        cbor_params = cbor2.dumps(subCommandParams)
    if mode == "self_PinUvAuthParamWithDifferentSubCommandCase":
        auth_message = bytes([0x05]) + cbor_params
    elif mode == "self_PinUvAuthParamExcludesSubCommandParamsCase":
        auth_message = bytes([subCommand])
    elif mode == "self_PinUvAuthParamComputeOverOnlySubCommandParams":
        auth_message = cbor_params
    else:
        auth_message = bytes([subCommand]) + cbor_params
    
    if mode == "self_IncorrectHashAlgorithmForPinUvAuthParamCase":
        pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha224).digest()[:16]
    elif mode == "self_IncorrectConcatenationOrderToComputePinUvAuthParam":
        pinUvAuthParam = hmac.new(auth_message, pinToken, hashlib.sha256).digest()[:16]
    else:
        pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:16]

    if mode == "fidoDoc_InvalidPinUvAuthParamCase":
        pinUvAuthParam = bytes.fromhex("ABCD" + pinUvAuthParam.hex()[4:])

    if mode == "self_TruncatedPinUvAuthParamCase":
        pinUvAuthParam = bytes.fromhex(pinUvAuthParam.hex()[4:])

    if mode == "self_LongerPinUvAuthParamCase":
        pinUvAuthParam = bytes.fromhex("ABCD" + pinUvAuthParam.hex())


    if mode == "fidoDoc_MissingPinUvAuthParamCase":
            cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,  # pinUvAuthProtocol = 1
            # 0x04: pinUvAuthParam
        }
    elif mode == "fidoDoc_UnsupportedPinUvAuthProtocolCase":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 3,  # pinUvAuthProtocol = 3
            0x04: pinUvAuthParam
        }
    elif mode == "fidoDoc_MissingMandatoryParamInSubCommandParamsCase":
        cbor_map = {
            0x01: subCommand,
            # 0x02: subCommandParams,
            0x03: 1,  # pinUvAuthProtocol = 1
            0x04: pinUvAuthParam
        }
    elif mode == "self_InvalidCBORMapOrderCase":
        cbor_map = {
            0x02: subCommandParams,
            0x01: subCommand,
            0x04: pinUvAuthParam,
            0x03: 1,  # pinUvAuthProtocol = 1
        }
    elif mode == "self_MissingPinUvAuthProtocolCase":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            # 0x03: 1,  # pinUvAuthProtocol = 1
            0x04: pinUvAuthParam,
        }
    elif mode == "self_NonBytePinUvAuthParam":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,  # pinUvAuthProtocol = 1
            0x04: pinUvAuthParam.hex()[:16],
        }
    elif mode == "self_NonIntegerPinUvAuthProtocol":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: "One",  # pinUvAuthProtocol = 1
            0x04: pinUvAuthParam,
        }
    elif mode == "self_MissingSubCommand":
        cbor_map = {
            # 0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,  # pinUvAuthProtocol = 1
            0x04: pinUvAuthParam
        }
    else:
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,  # pinUvAuthProtocol = 1
            0x04: pinUvAuthParam
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    #util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu


def deleteCredInfoProtocol2(pinToken, subCommand, credential_id, mode):
    
    if mode == "self_CredentialIDIncorrectTypeCase":
        #delete credential
        subCommandParams = {
            0x02: [ 
                { # credentialId descriptor
                1: bytes.fromhex(credential_id),
                2: "public-key"
                }
            ]
        }
    elif mode == "self_UnsupportedParamInSubCommandParamsCase":
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key",
            },
            0x04: {  # credentialId descriptor
                "id": "piyush".encode(),
                "name": "abcdef.com",
            }
        }
    elif mode == "self_UnsupportedTypeInSubCommandParamsCase":
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "private-key"
            }
        }
    elif mode == "self_MultipleCredentialIdEntriesCase":
         #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id), "id": bytes.fromhex(credential_id), "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }
    elif mode == "self_EmptySubCommandParamsMap":
        #delete credential
        subCommandParams = {
            # 0x02: {  # credentialId descriptor
            #     "id": bytes.fromhex(credential_id),
            #     "type": "public-key"
                
            # }
        }
    else:
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }

    if mode == "self_PinUvAuthParamWithDifferentCredentialIdCase":
        util.printcolor(util.YELLOW,f"VALID CREDENTIAL ID FOR pinUvAuthParam IN subCommandParams >> {credential_id}")
        credential_id = "333333" + credential_id[6:]
        util.printcolor(util.YELLOW,f"INVALID CREDENTIAL ID FOR pinUvAuthParam IN subCommandParams >> {credential_id}")
        #delete credential
        diSubCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }
        cbor_params = cbor2.dumps(diSubCommandParams)
    else:
        # Compute pinUvAuthParam
        cbor_params = cbor2.dumps(subCommandParams)

    if mode == "self_PinUvAuthParamWithDifferentSubCommandCase":
        auth_message = bytes([0x05]) + cbor_params
    elif mode == "self_PinUvAuthParamExcludesSubCommandParamsCase":
        auth_message = bytes([subCommand])
    elif mode == "self_PinUvAuthParamComputeOverOnlySubCommandParams":
        auth_message = cbor_params
    else:
        auth_message = bytes([subCommand]) + cbor_params
    
    if mode == "self_IncorrectHashAlgorithmForPinUvAuthParamCase":
        pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha224).digest()[:32]
    elif mode == "self_IncorrectConcatenationOrderToComputePinUvAuthParam":
        pinUvAuthParam = hmac.new(auth_message, pinToken, hashlib.sha256).digest()[:32]
    else:
        pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

    if mode == "fidoDoc_InvalidPinUvAuthParamCase":
        pinUvAuthParam = bytes.fromhex("ABCD" + pinUvAuthParam.hex()[4:])

    if mode == "self_TruncatedPinUvAuthParamCase":
        pinUvAuthParam = bytes.fromhex(pinUvAuthParam.hex()[4:])

    if mode == "self_LongerPinUvAuthParamCase":
        pinUvAuthParam = bytes.fromhex("ABCD" + pinUvAuthParam.hex())

   
    if mode == "fidoDoc_MissingPinUvAuthParamCase":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,  # pinUvAuthProtocol = 2
            # 0x04: pinUvAuthParam
        }
    elif mode == "fidoDoc_UnsupportedPinUvAuthProtocolCase":
        cbor_map = {
                    0x01: subCommand,
                    0x02: subCommandParams,
                    0x03: 3,  # pinUvAuthProtocol = 3
                    0x04: pinUvAuthParam
        }
    elif mode == "fidoDoc_MissingMandatoryParamInSubCommandParamsCase":
        cbor_map = {
            0x01: subCommand,
            # 0x02: subCommandParams,
            0x03: 2,  # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
        }
    elif mode == "self_InvalidCBORMapOrderCase":
        cbor_map = {
            0x02: subCommandParams,
            0x01: subCommand,
            0x04: pinUvAuthParam,
            0x03: 2,  # pinUvAuthProtocol = 2
        }
    elif mode == "self_MissingPinUvAuthProtocolCase":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            # 0x03: 2,  # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam,
        }
    elif mode == "self_NonBytePinUvAuthParam":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,  # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam.hex()[:32],
        }
    elif mode == "self_NonIntegerPinUvAuthProtocol":
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: "Two",  # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam,
        }
    elif mode == "self_MissingSubCommand":
        cbor_map = {
            # 0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,  # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam,
        }
    else:
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,  # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam,
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    #util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex + "00"
    return apdu

def deleteCredInfoWithoutPinProtocol2(subCommand, credential_id, mode):
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }

        # Compute pinUvAuthParam
        cbor_params = cbor2.dumps(subCommandParams)
    
   
   
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,  # pinUvAuthProtocol = 2
        }

        cbor_bytes = cbor2.dumps(cbor_map)
        cbor_hex = cbor_bytes.hex().upper()
        lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

        #util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
        #util.hex_string_to_cbor_diagnostic(cbor_hex)

        apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex + "00"
        return apdu

def deleteCredInfoWithoutPinProtocol1(subCommand, credential_id, mode):
        #delete credential
        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id": bytes.fromhex(credential_id),
                "type": "public-key"
                
            }
        }

        # Compute pinUvAuthParam
        cbor_params = cbor2.dumps(subCommandParams)
    
   
   
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,  # pinUvAuthProtocol = 1
        }

        cbor_bytes = cbor2.dumps(cbor_map)
        cbor_hex = cbor_bytes.hex().upper()
        lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

        #util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
        #util.hex_string_to_cbor_diagnostic(cbor_hex)

        apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex + "00"
        return apdu


def enumerateCredentialsBegin_APDU_Procotol2(subCommand, pinToken, rp, mode):
    rpIDHash = hashlib.sha256(rp.encode('utf-8')).digest()

    if mode == "self_MoreThan32BytesRpIDHash":
        rpIDHashStr = rpIDHash.hex() + "abcd"
        rpIDHash = bytes.fromhex(rpIDHashStr)

    subCommandParams = {
        0x01: rpIDHash
    }


    if mode == "fidoDoc_MissingRpIDHash":
        subCommandParams = {
        # 0x01: rpIDHash
    }

    subCommandParamsBytes = cbor2.dumps(subCommandParams)
    message = bytes([subCommand]) + subCommandParamsBytes

    if mode != "self_PINotSetMakeCredAndWithoutPinAuthParamEnumerateCredential" and mode != "self_PINotSetMakeCredAndWithRkAlwaysUvFalse":
        pinUvAuthParam = hmac.new(pinToken, message, digestmod='sha256').digest()[:32]
        pinUvAuthParamStr = pinUvAuthParam.hex()
        pinUvAuthParamStr = "ABCD" + pinUvAuthParamStr[4:]

    if mode == "fidoDoc_InvalidPinUvAuthParamWithPCMR" or mode == "fidoDoc_InvalidPinUvAuthParamWithCM":
        print("Invalid pinUvAuthParam : ", pinUvAuthParamStr)
        pinUvAuthParam = bytes.fromhex(pinUvAuthParamStr)
    
    if mode == "self_OldPinUvAuthParam":
        pinUvAuthParam = oldPinUvAuthParam_Protocol2


    if mode == "self_PINotSetMakeCredAndWithoutPinAuthParamEnumerateCredential":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,
            # 0x04: pinUvAuthParam
        }
    
    elif mode == "self_PINotSetMakeCredAndWithRkAlwaysUvFalse":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            # 0x03: 2,
            # 0x04: pinUvAuthParam
        }

    elif mode == "fidoDoc_InvalidProtocol":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 3,
            0x04: pinUvAuthParam
        }

    elif mode == "fidoDoc_MissingPinUvAuthParam":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,
            # 0x04: pinUvAuthParam
        }
    
    elif mode == "self_MissingPinUvAuthProtocol":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            # 0x03: 2,
            0x04: pinUvAuthParam
        }
    
    else:
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 2,
            0x04: pinUvAuthParam
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu

def enumerateCredentialsBegin_APDU_Procotol1(subCommand, pinToken, rp, mode):
    rpIDHash = hashlib.sha256(rp.encode('utf-8')).digest()

    if mode == "self_MoreThan32BytesRpIDHash":
        rpIDHashStr = rpIDHash.hex() + "abcd"
        rpIDHash = bytes.fromhex(rpIDHashStr)

    subCommandParams = {
        0x01: rpIDHash
    }

    if mode == "fidoDoc_MissingRpIDHash":
        subCommandParams = {
        # 0x01: rpIDHash
    }


    subCommandParamsBytes = cbor2.dumps(subCommandParams)
    message = bytes([subCommand]) + subCommandParamsBytes
    if mode != "self_PINotSetMakeCredAndWithoutPinAuthParamEnumerateCredential" and mode != "self_PINotSetMakeCredAndWithRkAlwaysUvFalse":
        pinUvAuthParam = hmac.new(pinToken, message, digestmod='sha256').digest()[:16]
        pinUvAuthParamStr = pinUvAuthParam.hex()
        pinUvAuthParamStr = "ABCD" + pinUvAuthParamStr[4:]

    if mode == "fidoDoc_InvalidPinUvAuthParamWithPCMR" or mode == "fidoDoc_InvalidPinUvAuthParamWithCM":
        print("Invalid pinUvAuthParam : ", pinUvAuthParamStr)
        pinUvAuthParam = bytes.fromhex(pinUvAuthParamStr)

    if mode == "self_OldPinUvAuthParam":
        pinUvAuthParam = oldPinUvAuthParam_Protocol1


    if mode == "self_PINotSetMakeCredAndWithoutPinAuthParamEnumerateCredential":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,
            # 0x04: pinUvAuthParam
        }

    elif mode == "self_PINotSetMakeCredAndWithRkAlwaysUvFalse":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            # 0x03: 1,
            # 0x04: pinUvAuthParam
        }

    elif mode == "fidoDoc_InvalidProtocol":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 3,
            0x04: pinUvAuthParam
        }

    elif mode == "fidoDoc_MissingPinUvAuthParam":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,
            # 0x04: pinUvAuthParam
        }

    elif mode == "self_MissingPinUvAuthProtocol":
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            # 0x03: 1,
            0x04: pinUvAuthParam
        }        

    else:
        # Step 5: Final CBOR map
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: 1,
            0x04: pinUvAuthParam
        }


    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu


def enumerateRPsBegin_APDU_Protocol2(subCommand, pinUvAuthParam, mode):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 2,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:32]
    }

    if mode == "fidoDoc_WithoutPinUvAuthParamCase":
        cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 2,                   # pinUvAuthProtocol = 2
        # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:32]
    }

    elif mode == "fidoDoc_MissingMandatoryParamCase" or mode == "self_MissingSubCommandRPBegin":
        cbor_map = {
        # 0x01: subCommand,          # subCommand
        0x03: 2,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:32]
    }
        
    elif mode == "self_MissingProtocolRPBegin":
        cbor_map = {
        0x01: subCommand,          # subCommand
        # 0x03: 2,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:32]
    }
        
    elif mode == "fidoDoc_UnsupportedProtocolCase":
        cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 4,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:32]
    }
        
    elif mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        cbor_map = {
        0x01: subCommand,          # subCommand
        # 0x03: 2,                   # pinUvAuthProtocol =  2
        # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    } 
        
    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex
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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR + "00"
    return APDUcommand


def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

    n = len(user)
    if MODE == "self_AbsentOptionalUserFields":
        PublicKeyCredentialUserEntity = {
                    "id": user.encode(), # id: byte sequence
        #         "name": randomUser(n),  # name 
        # "displayName": randomUser(n),  # displayName
        #       "icon": "https://example.com/redpath.png"  # icon (optional)
        }
    else:
        PublicKeyCredentialUserEntity = {
                    "id": user.encode(), # id: byte sequence
                "name": randomUser(n),  # name 
        "displayName": randomUser(n),  # displayName
        #       "icon": "https://example.com/redpath.png"  # icon (optional)
        }
        
    PublicKeyCredentialRpEntity = {
        "id": rp,  # id: unique identifier
         "name": randomRPId(8)  # name
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

    if MODE == "self_MakeCredChangeRKValueEachTime" or MODE == "fidoDoc_NoDiscoverableCredential":
        option  = {"rk": False}
    else:
        option  = {"rk": True}


    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    global userEntity
    userEntity = cbor_user

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
        return "80100000" + lc + full_data  + "00" # single string + ""

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
    
def generateRpIDHash(rpID):
    rpIDHashBytes = hashlib.sha256(rpID.encode("utf-8")).digest()
    length = len(rpIDHashBytes)     # should be 32
    if length != 32:
        return ValueError("rpIDHash Length: Not 32 bytes")

    rpIDHash = rpIDHashBytes.hex()
    util.printcolor(util.YELLOW,f"Generated rpIDHash : {rpIDHash}({length} Bytes)")
    return rpIDHash

def getRpIDHashAndLength(rpID):
    rpIDHash = hashlib.sha256(rpID.encode("utf-8")).digest()
    length = len(rpIDHash)     # should be 32
    if length != 32:
        return ValueError("rpIDHash Length: Not 32 bytes")
    
    return rpIDHash, length

    

def makeCredCBORWithRPsParam(clientDataHash, rpID, rpName, user, credParam, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": randomUser(64),  # name 
       "displayName": randomUser(80),  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    PublicKeyCredentialRpEntity = {
        "id": rpID,  # id: unique identifier
         "name": rpName  # name
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

    option  = {"rk": True}

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

    if MODE == "self_PINotSetMakeCredAndWithRkAlwaysUvFalse":
        option  = {"alwaysUv": False, "rk": True}
    else:
        option = {"rk": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    # cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
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

    pinAuthParam = util.hmac_sha256(pinToken, clientDataHash)
    global pinUvAuthTokenAssociatedRPID 
    pinUvAuthTokenAssociatedRPID = pinToken

    global oldPinUvAuthParam_Protocol2
    oldPinUvAuthParam_Protocol2 = pinAuthParam 

    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthParam)
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(apdu,f"Make Cred Chaining data:",checkflag=(i == len(makeCredAPDU) - 1))

    return result, status

def makeCredProtocol2WithRPsParam(curpin, clientDataHash, rpID, rpName, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    global pinUvAuthTokenAssociatedRPID 
    pinUvAuthTokenAssociatedRPID = pinToken

    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = makeCredCBORWithRPsParam(clientDataHash, rpID, rpName, user, pubkey, pinAuthToken)
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(apdu,f"Make Cred Chaining data:",checkflag=(i == len(makeCredAPDU) - 1))

    return result, status

def makeCredWithoutPINSetProtocol2(clientDataHash, rp, user):
    # util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    makeCredAPDU = createCBORmakeCredWithoutPINSet(clientDataHash, rp, user, pubkey)
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

def getCredentialIDFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    credentialId = auth_Data["credentialId"]
    return credentialId

def getPublicKeyFromResponse(response):
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    credentialPublicKey = auth_Data["credentialPublicKey"]
    return credentialPublicKey



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

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR + "00"
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
    credId = authParsing(response)
    response, status  = makeAssertionProtocol2(curpin, clientDataHash, rp, credId)
    return response, status

def makeCredProtocol1(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken = getPINtokenPubkeyProtocol1(curpin)

    pinAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:16]
    global pinUvAuthTokenAssociatedRPID
    pinUvAuthTokenAssociatedRPID = pinToken

    global oldPinUvAuthParam_Protocol1
    oldPinUvAuthParam_Protocol1 = pinAuthParam 
  
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCredProtocol1(clientDataHash, rp, user, pinAuthParam)
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
    # # Remove first byte if length > 2
    # if len(permission_hex) > 2:
    #     permission_hex = permission_hex[2:]
    
    
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

    hexstring, status= util.APDUhex(getPINTokenAPDU,"Client PIN command as subcmd 0x09 getPINtokenWithPermission", checkflag=True);

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

    response, status= util.APDUhex(getPinTokenAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)

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

def extractBOR(hex_response):
    # Convert hex → bytes
    raw_bytes = bytes.fromhex(hex_response)

    # Remove CTAP status byte (0x00)
    cbor_bytes = raw_bytes[1:]

    # Decode CBOR
    decoded = cbor2.loads(cbor_bytes)

    print("Decoded CBOR object:")
    print(decoded)
