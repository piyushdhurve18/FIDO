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

globalRpIDBegin = ""
globalRpIDNext = ""

new_Pin = ""
clientDataHash = os.urandom(32)
CM_PERMISSION_BYTE = 0x04
INVALID_PERMISSION_BYTE = 0x20
UNSUPPORTED_PERMISSION_BYTE = 0x8F
WRONG_PERMISSION_BYTE = 0x10
PCMR_PERMISSION_BYTE = 0x40
pinUvAuthTokenAssociatedRPID = b""
makeCredResponse = ""
MODE = ""

curpin="11223344"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "ENUMERATE RPs"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def executeEnumerateRPsBeginAndEnumerateRPsGetNextRP(mode, reset_required, set_pin_required, make_cred_required, protocol):
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
    "fidoTool_PositiveCase_with_PCMR": """Test started: P-1 :
        Precondtion: pinUvAuthParam Generate with pcmr permission.;

        ٭ If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that result:;
                    (a) Result.rp is present and of type MAP.;
                    (b) Result.rp.id is present and is of type String.;
                    (c) Result.rp.id is in a list of known rpIDs.;
                    (d) Result.rpIDHash is a valid SHA-256 hash of Result.rp.id, and is of type BYTESTRING.;
                    (e) Result.totalRPs is a Number and is set to 2, same as a number of registered RPIDs.;;

        ٭ If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), and check that result:;
                    (a) Result.rp is present and of type MAP.;
                    (b) Result.rp.id is present and is of type String.;
                    (c) Result.rp.id is in a list of known rpIDs.;
                    (d) Result.rpIDHash is a valid SHA-256 hash of Result.rp.id, and is of type BYTESTRING.""",

    "fidoTool_PositiveCase_with_CM": """Test started: P-2 :
        Precondtion: pinUvAuthParam Generate with cm permission;

        ٭ If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that result:;
                    (a) Result.rp is present and of type MAP;
                    (b) Result.rp.id is present and is of type String.;
                    (c) Result.rp.id is in a list of known rpIDs.;
                    (d) Result.rpIDHash is a valid SHA-256 hash of Result.rp.id, and is of type BYTESTRING.;
                    (e) Result.totalRPs is a Number and is set to 2, same as a number of registered RPIDs.;;

        ٭ If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), and check that result:;
                    (a) Result.rp is present and of type MAP;
                    (b) Result.rp.id is present and is of type String.;
                    (c) Result.rp.id is in a list of known rpIDs.;
                    (d) Result.rpIDHash is a valid SHA-256 hash of Result.rp.id, and is of type BYTESTRING.""",

    "fidoDoc_WithoutPinUvAuthParamCase": """Test started: P-3 :
        Precondition : Authenticator must be Reset, has PIN Set and supports authenticatorCredentialManagement.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) without pinUvAuthParam while all other parameters are correct. The authenticator is expected to return CTAP2_ERR_PUAT_REQUIRED.""",
    
    "fidoDoc_MissingMandatoryParamCase": """Test started: P-4 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) missing one or more mandatory parameters (excluding pinUvAuthParam). The auhenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",
    
    "fidoDoc_UnsupportedProtocolCase": """Test started: P-5 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using an unsupported pinUvAuthProtocol while all other parameters are correct. The authenticator is expected to return CTAP1_ERR_INVALID_PARAMETER.""",
    
    "fidoDoc_PinUvAuthTokenWithoutPermissionCase": """Test started: P-6 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) with pinUvAuthParam but the pinUvAuthToken generate without permission . The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase": """Test started: P-7 :
        Precondition : Use a pinUvAuthToken without with an associated RP ID. 
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) with valid pinUvAuthParam. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "fidoDoc_NoDiscoverableCredWithPCMRPermission": """Test started: P-8 :
        Precondition : Authenticator must be Reset, has PIN Set and contains no discoverable credentials.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using valid pinUvAuthParam by persistenPinUvAuthToken with pcmr permission and supported pinUvAuthProtocol. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",
    
    "fidoDoc_NoDiscoverableCredWithCMPermission": """Test started: P-9 :
        Precondition : Authenticator must be Reset, has PIN Set and contains no discoverable credentials.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using valid pinUvAuthParam by pinUvAuthToken with cm permission and supported pinUvAuthProtocol. The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",
    
    "fidoDoc_OneRpWithPCMRPermission": """Test started: P-10 :
        Precondition : Authenticator must be Reset, has PIN Set, contains discoverable credentials for exactly one RP, and use a valid pinUvAuthToken with pcmr permission.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using valid parameters. The authenticator is expected to return CTAP2_OK with rp (0x03), rpIDHash (0x04), and totalRPs (0x05) set to 1.""",
    
    "fidoDoc_OneRpWithCMPermission": """Test started: P-11 :
        Precondition : Authenticator must be Reset, has PIN Set, contains discoverable credentials for exactly one RP, and use a valid pinUvAuthToken with cm permission.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using valid parameters. The authenticator is expected to return CTAP2_OK with rp (0x03), rpIDHash (0x04), and totalRPs (0x05) set to 1.""",
    
    "fidoDoc_MultipleRpWithPCMRPermission": """Test started: P-12 :
        Precondition : Authenticator must be Reset, has PIN Set, contains discoverable credentials for multiple RPs, and use a valid pinUvAuthToken with pcmr permission.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using valid parameters. The authenticator is expected to return CTAP2_OK with rp (0x03), rpIDHash (0x04), and totalRPs (0x05) greater than 1.""",
    
    "fidoDoc_MultipleRpWithCMPermission": """Test started: P-13 :
        Precondition : Authenticator must be Reset, has PIN Set, contains discoverable credentials for multiple RPs, and use a valid pinUvAuthToken with cm permission.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using valid parameters. The authenticator is expected to return CTAP2_OK with rp (0x03), rpIDHash (0x04), and totalRPs (0x05) greater than 1.""",
    
    "fidoDoc_EnumerateRpGetNextRpWithPCMRPermission": """Test started: P-14 :
        Precondition : Authenticator must be Reset, has PIN Set, enumerateRPsBegin (0x02) was successfully completed, and totalRPs is greater than 1.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03). The authenticator is expected to return CTAP2_OK with the next rp (0x03) and corresponding rpIDHash (0x04).""",
    
    "self_AlteredPinUvAuthParamWithPCMR": """Test started: P-15 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using an altered pinUvAuthParam generated with persistentPinUvAuthToken with pcmr permission. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_AlteredPinUvAuthParamWithCM": """Test started: P-16 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using an altered pinUvAuthParam generated with pinUvAuthToken with cm permission. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_MissingSubCommandRPBegin": """Test started: P-17 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) missing subCommand parameter. The auhenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",
    
    "self_MissingProtocolRPBegin": """Test started: P-18 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) missing pinUvAuthProtocol  parameter. The auhenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",
    
    "self_PinUvAuthParamWithoutAnyPermission": """Test started: P-19 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using an pinUvAuthParam generated without any permission. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_PinUvAuthParamWrongPermission": """Test started: P-20 :
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) using an pinUvAuthParam generated with different permission than cm or pcmr. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
     "self_DirectNextRPCommand": """Test started: P-21 :
        Precondition : Authenticator must be Reset, has PIN Set, make 2 discoverable credentials and enumerateRPsBegin (0x02) was not previously invoked.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03). The authenticator is expected to return CTAP2_ERR_NOT_ALLOWED.""",
    
    "self_RPsEnumeratedAlready": """Test started: P-22 :
        Precondition :  enumerateRPsBegin (0x02) was successfully completed, and all RPs have already been enumerated.; 
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03). The authenticator is expected to return CTAP2_ERR_NOT_ALLOWED.""",
    
    "self_CommandBetweenRPBeginAndRPNext": """Test started: P-23 :
        Precondition : EnumerateRPsBegin (0x02) was successfully completed, and a different CTAP command was sent in between, clearing the enumeration state.; 
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03). The authenticator is expected to return CTAP2_ERR_NOT_ALLOWED.""",
    
    "self_PowerResetBetweenRPBeginAndRPNext": """Test started: P-24 :
        Precondition : EnumerateRPsBegin (0x02) was successfully completed, and the authenticator was power-cycled or reset, clearing internal state.; 
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03). The authenticator is expected to return CTAP2_ERR_NOT_ALLOWED.""",
    
    "self_ExtraParameterRPNext": """Test started: P-25 :
        Precondition :EnumerateRPsBegin (0x02) was successfully completed, and enumerateRPsGetNextRP (0x03) is sent with extra or unexpected parameters.; 
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03) including unsupported parameter like pinUvAuthProtocol. The authenticator is expected to return CTAP1_ERR_INVALID_PARAMETER.""",
    
    "self_MissingSubCommandRPNext": """Test started: P-26 :
        Precondition : EnumerateRPsBegin (0x02) was successfully completed, and enumerateRPsGetNextRP (0x03) is sent with missing mandatory parameters.; 
        Send authenticatorCredentialManagement with subCommand enumerateRPsGetNextRP (0x03) missing required field. The authenticator is expected to return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
    
    "self_ProcotolSwappinPinUvAuthParam": """Test started: P-27 :
        Precondition : Authenticator must be Reset, has PIN Set, and contains discoverable credentials.;
        Send authenticatorCredentialManagement with subCommand enumerateRPsBegin (0x02) with protocol 2 using an pinUvAuthParam generated with protocol 1. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.;
        NOTE: Swap the procotols and test it again expected result will be same as above.""",
    
    
    "self_rpID32Bytes": """Test started: P-28 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with cm permission.;
        Send authenticatorMakeCredential (0x01) with 32 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Actual rp used for 1st Make Credential, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 32 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Actual rp used for 2nd Make Credential and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 32 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID64Bytes": """Test started: P-29 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with cm permission.;
        Send authenticatorMakeCredential (0x01) with 64 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 64 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 64 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID255Bytes": """Test started: P-30 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with cm permission.;        
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 255 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 255 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID255Bytes_Truncated": """Test started: P-31 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with cm permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes(ZZ), rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with Truncated rpID(ZZ), rpIDHash must not be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes(RR) and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with Truncated rpID(RR), rpIDHash must not be same as (YY).""",
    
    "self_rpID255Bytes_rpName64Bytes": """Test started: P-32 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with cm permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 64 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 255 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 255 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID255Bytes_rpName255Bytes": """Test started: P-33 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with cm permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 255 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 255 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 255 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_MakeCredWithoutPINAlwaysUvFalseCase": """Test started: P-34 :
        Precondition: No PIN is set and create credential with rk without PIN (make sure alwaysUV is false).;
        Send enumerateRPsBegin (0x02) without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04) as Authenticator does not have PIN set.;
        Expected output: CTAP2_ERR_PUAT_REQUIRED.""",
    
    "self_MakeCredWithPINSetGetPINToken_05": """Test started: P-35 :
        Precondition: PIN is set and card having atleast one rk credential.;
        get PIN Token using getPinToken (0x05) then Send enumerateRPsBegin (0x02)  with all valid parameters. Authenticator must return CTAP2_ERR_PIN_AUTH_INVALID.""",
    
    "self_MakeCredChangeRKValueEachTime": """Test started: P-36 :
        Get totalRPs (0x05) = 1 by  enumerateRPsBegin (0x02).;
        Create credentials without rk and make sure totalRPs (0x05) remains same 1.""",

    "self_rpID32Bytes_PCMR": """Test started: P-28 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with pcmr permission.;
        Send authenticatorMakeCredential (0x01) with 32 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Actual rp used for 1st Make Credential, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 32 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Actual rp used for 2nd Make Credential and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 32 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID64Bytes_PCMR": """Test started: P-29 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with pcmr permission.;
        Send authenticatorMakeCredential (0x01) with 64 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 64 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 64 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID255Bytes_PCMR": """Test started: P-30 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with pcmr permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 255 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 255 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID255Bytes_Truncated_PCMR": """Test started: P-31 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with pcmr permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 32 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes(ZZ), rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with Truncated rpID(ZZ), rpIDHash must not be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes(RR) and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with Truncated rpID(RR), rpIDHash must not be same as (YY).""",
    
    "self_rpID255Bytes_rpName64Bytes_PCMR": """Test started: P-32 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with pcmr permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 64 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 255 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 255 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    "self_rpID255Bytes_rpName255Bytes_PCMR": """Test started: P-33 :
        Precondition : Authenticator must be Reset , has PIN Set and perform enumerateRPsBegin(0x02) with pcmr permission.;
        Send authenticatorMakeCredential (0x01) with 255 bytes RpID and 255 bytes RpName, rk must be True, create 2 Credentials. The authenticator must return CTAP2_OK everytime.;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes, rpIDHash (0x04) - 32 bytes rpIDHash(XX) and totalRPs (0x05) - 2. Generate the rpIDHash with 255 bytes correct rpID(Given for 1st make credential), rpIDHash must be same as (XX).;
        Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), command must return CTAP2_OK with rp (0x03) - Truncated first 64 bytes and rpIDHash (0x04) - 32 bytes rpIDHash(YY). Generate the rpIDHash with 255 bytes correct rpID(Given for 2nd make credential), rpIDHash must be same as (YY).""",
    
    
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

    # ------------------------------
    #  MODE → PIN VALUE
    # ------------------------------

    if protocol == "PROTOCOL_ONE":
        PROTOCOL = 1
    else:
        PROTOCOL = 2

    ########################################################################################
    ########################################################################################
    ######################### SCENARIOS EXECUTION STARTS FROM HERE #########################
    ########################################################################################
    ########################################################################################


    if mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        scenarioCount += 1
        subCommand = 0x02
        pinUvAuthParam = ""
        util.APDUhex("00a4040008a0000006472f0001","Select applet")
        if protocol == "PROTOCOL_ONE":
            apdu = enumerateRPsBegin_APDU_Protocol1(subCommand, pinUvAuthParam, mode)
            response, status = util.APDUhex(apdu, "authenticatorCredentialManagement (0x0A) : subCommand enumerateRPsBegin (0x02)")
            if status == "36":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            apdu = enumerateRPsBegin_APDU_Protocol2(subCommand, pinUvAuthParam, mode)
            response, status = util.APDUhex(apdu, "authenticatorCredentialManagement (0x0A) : subCommand enumerateRPsBegin (0x02)")
            if status == "36":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MakeCredWithPINSetGetPINToken_05":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MakeCredChangeRKValueEachTime":
        scenarioCount += 1
        clientDataHash1 = os.urandom(32)
        RP_domain1 = "develop.com"
        user1 = "john"
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_OK)")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == 1:
                    response, status = makeCredProtocol2(pin,clientDataHash1,RP_domain1,user1)
                    if status == "00":
                        util.printcolor(util.GREEN,f"MAKE CRED WITH RK FALSE DONE")
                        response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_OK)")
                            text_031, hex_041, totalRPsPresentInAuthenticator1 = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                            
                            if text_03 == text_031:  
                                util.printcolor(util.GREEN,f"rp(0x03) is same as previous --> Previous : {text_03}; Current : {text_031}")
                            else:
                                util.printcolor(util.RED,f"rp(0x03) not same as previous --> Previous : {text_03}; Current : {text_031}")
                                exit(0)

                            if hex_04 == hex_041:
                                util.printcolor(util.GREEN,f"rpIDHash (0x04) is same as previous --> Previous : {hex_04}; Current : {hex_041}")
                            else:
                                util.printcolor(util.RED,f"rpIDHash (0x04) not same as previous --> Previous : {hex_04}; Current : {hex_041}")
                                exit(0)

                            if totalRPsPresentInAuthenticator == totalRPsPresentInAuthenticator1:  
                                util.printcolor(util.GREEN,f"totalRPs(0x05) is same as previous --> Previous : {totalRPsPresentInAuthenticator}; Current : {totalRPsPresentInAuthenticator1}")
                            else:
                                util.printcolor(util.RED,f"totalRPs(0x05) not same as previous --> Previous : {totalRPsPresentInAuthenticator}; Current : {totalRPsPresentInAuthenticator1}")
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"MAKE CRED WITH RK FALSE FAILED WITH STATUS CODE: {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_OK)")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == 1:
                    response, status = makeCredProtocol2(pin,clientDataHash1,RP_domain1,user1)
                    if status == "00":
                        util.printcolor(util.GREEN,f"MAKE CRED WITH RK FALSE DONE")
                        response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED - {status}(CTAP2_OK)")
                            text_031, hex_041, totalRPsPresentInAuthenticator1 = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                            
                            if text_03 == text_031:  
                                util.printcolor(util.GREEN,f"rp(0x03) is same as previous --> Previous : {text_03}; Current : {text_031}")
                            else:
                                util.printcolor(util.RED,f"rp(0x03) not same as previous --> Previous : {text_03}; Current : {text_031}")
                                exit(0)

                            if hex_04 == hex_041:
                                util.printcolor(util.GREEN,f"rpIDHash (0x04) is same as previous --> Previous : {hex_04}; Current : {hex_041}")
                            else:
                                util.printcolor(util.RED,f"rpIDHash (0x04) not same as previous --> Previous : {hex_04}; Current : {hex_041}")
                                exit(0)

                            if totalRPsPresentInAuthenticator == totalRPsPresentInAuthenticator1:  
                                util.printcolor(util.GREEN,f"totalRPs(0x05) is same as previous --> Previous : {totalRPsPresentInAuthenticator}; Current : {totalRPsPresentInAuthenticator1}")
                            else:
                                util.printcolor(util.RED,f"totalRPs(0x05) not same as previous --> Previous : {totalRPsPresentInAuthenticator}; Current : {totalRPsPresentInAuthenticator1}")
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"MAKE CRED WITH RK FALSE FAILED WITH STATUS CODE: {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
   
    if mode == "fidoTool_PositiveCase_with_PCMR":
        scenarioCount += 1
        response, status = makeCredentialNumberOfTimes(pin, 3)
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator - 1):
                        response, status = enumerateRPsGetNextRP(mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"{i+1} ENUMERATE RPs GET NEXT RP DONE")
                        else:
                            util.printcolor(util.RED,f"{i+1} ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i1 in range(totalRPsPresentInAuthenticator - 1):
                        response, status = enumerateRPsGetNextRP(mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"{i1+1} ENUMERATE RPs GET NEXT RP DONE")
                        else:
                            util.printcolor(util.RED,f"{i1+1} ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoTool_PositiveCase_with_CM":
        scenarioCount += 1
        response, status = makeCredentialNumberOfTimes(pin, 3)
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator - 1):
                        response, status = enumerateRPsGetNextRP(mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"{i+1} ENUMERATE RPs GET NEXT RP DONE")
                        else:
                            util.printcolor(util.RED,f"{i+1} ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i1 in range(totalRPsPresentInAuthenticator - 1):
                        response, status = enumerateRPsGetNextRP(mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"{i1+1} ENUMERATE RPs GET NEXT RP DONE")
                        else:
                            util.printcolor(util.RED,f"{i1+1} ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "fidoDoc_WithoutPinUvAuthParamCase":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "36":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "36":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PUAT_REQUIRED)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "fidoDoc_MissingMandatoryParamCase":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "fidoDoc_UnsupportedProtocolCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "02":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP1_ERR_INVALID_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "02":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP1_ERR_INVALID_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_PinUvAuthTokenWithoutPermissionCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_NoDiscoverableCredWithPCMRPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "2E":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_NO_CREDENTIALS)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "2E":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_NO_CREDENTIALS)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_NoDiscoverableCredWithCMPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "2E":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_NO_CREDENTIALS)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "2E":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_NO_CREDENTIALS)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "fidoDoc_OneRpWithPCMRPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == 1:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == 1:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "fidoDoc_OneRpWithCMPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == 1:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == 1:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "fidoDoc_MultipleRpWithPCMRPermission":
        scenarioCount += 1

        makeCredCount = 3
        if protocol == "PROTOCOL_ONE":
            response, status = makeCredentialNumberOfTimes(pin, makeCredCount)
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == makeCredCount:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = makeCredentialNumberOfTimes(pin, makeCredCount)
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == makeCredCount:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "fidoDoc_MultipleRpWithCMPermission":
        scenarioCount += 1

        makeCredCount = 3
        if protocol == "PROTOCOL_ONE":
            response, status = makeCredentialNumberOfTimes(pin, makeCredCount)
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == makeCredCount:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = makeCredentialNumberOfTimes(pin, makeCredCount)
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator == makeCredCount:
                    util.printcolor(util.GREEN,f"Recieved Expected No. of RPs ({totalRPsPresentInAuthenticator})")
                else:
                    util.printcolor(util.RED,f"Recieved Unxpected No. of RPs ({totalRPsPresentInAuthenticator})")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "fidoDoc_EnumerateRpGetNextRpWithPCMRPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = makeCredentialNumberOfTimes(pin, 3)
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator - 1):
                        response, status = enumerateRPsGetNextRP(mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"{i+1} ENUMERATE RPs GET NEXT RP DONE")
                        else:
                            util.printcolor(util.RED,f"{i+1} ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = makeCredentialNumberOfTimes(pin, 3)
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i1 in range(totalRPsPresentInAuthenticator - 1):
                        response, status = enumerateRPsGetNextRP(mode)
                        if status == "00":
                            util.printcolor(util.GREEN,f"{i1+1} ENUMERATE RPs GET NEXT RP DONE")
                        else:
                            util.printcolor(util.RED,f"{i1+1} ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_AlteredPinUvAuthParamWithPCMR":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_AlteredPinUvAuthParamWithCM":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MissingSubCommandRPBegin":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_MissingProtocolRPBegin":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "14":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_MISSING_PARAMETER)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_PinUvAuthParamWithoutAnyPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_PinUvAuthParamWrongPermission":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, WRONG_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, WRONG_PERMISSION_BYTE, mode)

            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_PIN_AUTH_INVALID)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_DirectNextRPCommand":
        scenarioCount += 1

        response, status = makeCredentialNumberOfTimes(pin, 2)
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsGetNextRP(mode)

            if status == "30":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_NOT_ALLOWED)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsGetNextRP(mode)

            if status == "30":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) EXPECTED -> {status}(CTAP2_ERR_NOT_ALLOWED)")
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_RPsEnumeratedAlready":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator):
                        response, status = enumerateRPsGetNextRP(mode)
                        if (i != totalRPsPresentInAuthenticator - 1):
                            if status == "00":
                                util.printcolor(util.GREEN,f"{i+1} ENUMERATE RPs GET NEXT RP DONE")
                            else:
                                util.printcolor(util.RED,f"{i+1} ENUMERATE RPs GET NEXT RP FAILED")
                                exit(0)
                        else:
                            if status == "30":
                                util.printcolor(util.GREEN,f"{i+1} ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED ->{status}(CTAP2_ERR_NOT_ALLOWED)")
                            else:
                                util.printcolor(util.RED,f"{i+1} ENUMERATE RPs GET NEXT RP FAILED")
                                exit(0)

            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    for i1 in range(totalRPsPresentInAuthenticator):
                        response, status = enumerateRPsGetNextRP(mode)
                        if (i1 != totalRPsPresentInAuthenticator - 1):
                            if status == "00":
                                util.printcolor(util.GREEN,f"{i1+1} ENUMERATE RPs GET NEXT RP DONE")
                            else:
                                util.printcolor(util.RED,f"{i1+1} ENUMERATE RPs GET NEXT RP FAILED")
                                exit(0)
                        else:
                            if status == "30":
                                util.printcolor(util.GREEN,f"{i1+1} ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED ->{status}(CTAP2_ERR_NOT_ALLOWED)")
                            else:
                                util.printcolor(util.RED,f"{i1+1} ENUMERATE RPs GET NEXT RP FAILED")
                                exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_CommandBetweenRPBeginAndRPNext":
        scenarioCount += 1

        # makeCredentialNumberOfTimes(pin, 2)
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    response, status = util.APDUhex("80100000010400", "GetInfo")
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET INFO DONE -> {status}")
                    else:
                        util.printcolor(util.RED,f"GET INFO FAILED")
                        exit(0)
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "30":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_ERR_NOT_ALLOWED)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)         
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    response, status = util.APDUhex("80100000010400", "GetInfo")
                    if status == "00":
                        util.printcolor(util.GREEN,f"GET INFO DONE -> {status}")
                    else:
                        util.printcolor(util.RED,f"GET INFO FAILED")
                        exit(0)
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "30":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_ERR_NOT_ALLOWED)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)     
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_PowerResetBetweenRPBeginAndRPNext":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    resetPowerCycle(True)
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "30":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_ERR_NOT_ALLOWED)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)         
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    resetPowerCycle(True)
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "30":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_ERR_NOT_ALLOWED)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)     
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_ExtraParameterRPNext":
        scenarioCount += 1

      
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "02":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP1_ERR_INVALID_PARAMETER )")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)         
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "02":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)     
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    
    if mode == "self_MissingSubCommandRPNext":
        scenarioCount += 1

        makeCredentialNumberOfTimes(pin,2)
        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "11":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_ERR_CBOR_UNEXPECTED_TYPE.)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)         
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                if totalRPsPresentInAuthenticator > 1:
                    response, status = enumerateRPsGetNextRP(mode)                       
                    if status == "11":
                        util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                        exit(0)     
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_ProcotolSwappinPinUvAuthParam":
        scenarioCount += 1

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN EXPECTED --> {status}(CTAP2_ERR_PIN_AUTH_INVALID) ")      
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "33":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN EXPECTED --> {status}(CTAP2_ERR_PIN_AUTH_INVALID) ")      
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
            

    if mode == "self_rpID32Bytes":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 32
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_rpID64Bytes":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 64
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID255Bytes":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID255Bytes_Truncated":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                isMatched = verifyRpIDHash(text_03, hex_04)
                if isMatched != False:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                            isMatched = verifyRpIDHash(text_03, hex_04)
                            if isMatched != False:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                isMatched = verifyRpIDHash(text_03, hex_04)
                if isMatched != False:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                            isMatched = verifyRpIDHash(text_03, hex_04)
                            if isMatched != False:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID255Bytes_rpName64Bytes":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 64
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_rpID255Bytes_rpName255Bytes":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 255
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, CM_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID32Bytes_PCMR":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 32
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID64Bytes_PCMR":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 64
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID255Bytes_PCMR":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID255Bytes_Truncated_PCMR":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 32
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                isMatched = verifyRpIDHash(text_03, hex_04)
                if isMatched != False:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                            isMatched = verifyRpIDHash(text_03, hex_04)
                            if isMatched != False:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                isMatched = verifyRpIDHash(text_03, hex_04)
                if isMatched != False:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                            isMatched = verifyRpIDHash(text_03, hex_04)
                            if isMatched != False:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    if mode == "self_rpID255Bytes_rpName64Bytes_PCMR":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 64
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    if mode == "self_rpID255Bytes_rpName255Bytes_PCMR":
        scenarioCount += 1

        makeCredCount = 2
        rpIDLen = 255
        rpNameLen = 255
        resetPowerCycle(True)
        makeCredentialNumberOfTimesWithRPsParam(pin, makeCredCount, rpIDLen, rpNameLen)  #Make cred by protocol 2

        if protocol == "PROTOCOL_ONE":
            response, status = enumerateRPsBeginProtocol1(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                       
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
                exit(0)
    
        elif protocol == "PROTOCOL_TWO":
            response, status = enumerateRPsBeginProtocol2(pin, PCMR_PERMISSION_BYTE, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"ENUMERATE RPs BEGIN BY ({protocol}) DONE")
                text_03, hex_04, totalRPsPresentInAuthenticator = getTotalRPsFromEnumerateRPsBeginCBOR(response)
                util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDBegin}")
                util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                    
                isMatched = verifyRpIDHash(globalRpIDBegin, hex_04)
                if isMatched != True:
                    exit(0)
                if totalRPsPresentInAuthenticator > 1:
                    for i2 in range(totalRPsPresentInAuthenticator-1):
                        response, status = enumerateRPsGetNextRP(mode)                   
                        if status == "00":
                            util.printcolor(util.GREEN,f"ENUMERATE RPs GET NEXT RP DONE WITH EXPECTED -> {status}(CTAP2_OK)")
                            text_03, hex_04 = extractCBORRpIDAndHash(response) 
                            util.printcolor(util.ORANGE,f"ACTUAL RP ID USED FOR MAKE CRED : {globalRpIDNext}")
                            util.printcolor(util.ORANGE,f"AUTHENTICATOR GIVES TRUNCATED RP ID : {text_03}")
                                
                            isMatched = verifyRpIDHash(globalRpIDNext, hex_04)
                            if isMatched != True:
                                exit(0)

                        else:
                            util.printcolor(util.RED,f"ENUMERATE RPs GET NEXT RP FAILED")
                            exit(0)  
                else:
                    util.printcolor(util.RED,f"RECIEVED INCORRECT NUMBER OF TOTAL RPs : {totalRPsPresentInAuthenticator}")
                    exit(0)   
            else:
                util.printcolor(util.RED,f"ENUMERATE RPs BEGIN BY ({protocol}) FAILED WITH STATUS CODE: {status}")
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


def enumerateRPsGetNextRP(mode):
    if mode == "self_DirectNextRPCommand" or mode == "self_PowerResetBetweenRPBeginAndRPNext":
        util.APDUhex("00a4040008a0000006472f0001","Select applet")
    if mode == "self_ExtraParameterRPNext":
        response, status = util.APDUhex("80100000060aa20103020200","enumerateRPsGetNextRP(0x03)")
    elif mode == "self_MissingSubCommandRPNext":
        response, status = util.APDUhex("80100000010a00","enumerateRPsGetNextRP(0x03)")
    else:
        response, status = util.APDUhex("80100000040aa1010300","enumerateRPsGetNextRP(0x03)")
    return response, status

def getTotalRPsFromEnumerateRPsBeginCBOR(response):
    text_03, hex_04 = extractCBORRpIDAndHash(response)
    hexCBOR = extractCBORMap(response)
    # Decode CBOR
    cbor_bytes = binascii.unhexlify(hexCBOR)
    decoded = cbor2.loads(cbor_bytes)

    # Print all components
    # util.printcolor(util.YELLOW,f"Decoded CBOR components:")
    # for k, v in decoded.items():
    #     util.printcolor(util.YELLOW,f"{k}: {v}")

    # Get last component
    last_component = list(decoded.values())[-1]

    # Return only the last component
    totalRPsPresentInAuthenticator = int(last_component)
    util.printcolor(util.YELLOW,f"totalRPs (0x05) : {totalRPsPresentInAuthenticator}")
    if totalRPsPresentInAuthenticator > 1:
        util.printcolor(util.YELLOW,f"Allowed to Send enumerateRPsGetNextRP (0x03)")

    return text_03, hex_04,totalRPsPresentInAuthenticator


def makeCredentialNumberOfTimes(pin, maxCredCount):
    for x1 in range(maxCredCount): 
        nTime = x1+1
        clientDataHash = os.urandom(32)
        RP_domain = randomRPId(10)+".com"
        user = randomUser(32)
        util.printcolor(util.YELLOW,f"Client Data Hash for Make Cred {nTime} -> {util.toHex(clientDataHash)}")
        util.printcolor(util.YELLOW,f"RP Id for Make Cred {nTime} -> {RP_domain}")
        util.printcolor(util.YELLOW,f"User for Make Cred {nTime} -> {user}")

        response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user)  #Make cred by protocol 2
        global makeCredResponse
        makeCredResponse = response
        if status == "00":
            util.printcolor(util.GREEN,f"{nTime} Time MAKE CRED DONE WITH  -> {status}(CTAP2_OK)")
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


def enumerateRPsBeginProtocol1(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    pinToken, pubKey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
    if mode == "fidoDoc_PinUvAuthTokenWithoutPermissionCase" or mode == "self_PinUvAuthParamWithoutAnyPermission" or mode == "self_MakeCredWithPINSetGetPINToken_05":
        pinToken = getPINtokenPubkeyProtocol1(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    subCommand = 0x02  # enumerateRPsBegin
    if mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        pinUvAuthParam = util.hmac_sha256(pinUvAuthTokenAssociatedRPID, bytes([subCommand]))[:16]
    else:
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]

    if mode == "self_AlteredPinUvAuthParamWithPCMR" or mode == "self_AlteredPinUvAuthParamWithCM":
                # Convert to mutable bytearray
        pinUvAuthParamArr = bytearray(pinUvAuthParam)

        # Change byte at index 0 and 1
        pinUvAuthParamArr[0] = 0xAA
        pinUvAuthParamArr[1] = 0xBB

        # Convert back to bytes if needed
        pinUvAuthParam = bytes(pinUvAuthParamArr)
        util.printcolor(util.YELLOW,f"Altered pinUvAuthParam ==> {pinUvAuthParam.hex()}")

    if mode == "self_ProcotolSwappinPinUvAuthParam":
        apdu = enumerateRPsBegin_APDU_Protocol2(subCommand, pinUvAuthParam, mode)    
    else:
        apdu = enumerateRPsBegin_APDU_Protocol1(subCommand, pinUvAuthParam, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)
    # data = bytes.fromhex(response)
    # resLength = len(data)
    # if resLength > 3:
    #     existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)
    #     util.printcolor(util.YELLOW,f"existingResidentCredentialsCount = {existingResidentCredentialsCount}")
    #     util.printcolor(util.YELLOW,f"maxPossibleRemainingResidentCredentialsCount = {maxPossibleRemainingResidentCredentialsCount}")

    return response, status


def enumerateRPsBeginProtocol2(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")

    
    pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
    if mode == "fidoDoc_PinUvAuthTokenWithoutPermissionCase" or mode == "self_PinUvAuthParamWithoutAnyPermission" or mode == "self_MakeCredWithPINSetGetPINToken_05":
        pinToken, pubkey = getPINtokenPubkeyProtocol2(pin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    subCommand = 0x02  # enumerateRPsBegin
    if mode == "fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase":
        pinUvAuthParam = util.hmac_sha256(pinUvAuthTokenAssociatedRPID, bytes([subCommand]))[:32]
    else:
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]

    if mode == "self_AlteredPinUvAuthParamWithPCMR" or mode == "self_AlteredPinUvAuthParamWithCM":
                # Convert to mutable bytearray
        pinUvAuthParamArr = bytearray(pinUvAuthParam)

        # Change byte at index 0 and 1
        pinUvAuthParamArr[0] = 0xAA
        pinUvAuthParamArr[1] = 0xBB

        # Convert back to bytes if needed
        pinUvAuthParam = bytes(pinUvAuthParamArr)
        util.printcolor(util.YELLOW,f"Altered pinUvAuthParam ==> {pinUvAuthParam.hex()}")

    if mode == "self_ProcotolSwappinPinUvAuthParam":
        apdu = enumerateRPsBegin_APDU_Protocol1(subCommand, pinUvAuthParam, mode)
    else:
        apdu = enumerateRPsBegin_APDU_Protocol2(subCommand, pinUvAuthParam, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)
    # data = bytes.fromhex(response)
    # resLength = len(data)
    # if resLength > 3:
    #     existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)
    #     util.printcolor(util.YELLOW,f"existingResidentCredentialsCount = {existingResidentCredentialsCount}")
    #     util.printcolor(util.YELLOW,f"maxPossibleRemainingResidentCredentialsCount = {maxPossibleRemainingResidentCredentialsCount}")

    return response, status


def enumerateRPsBegin_APDU_Protocol1(subCommand, pinUvAuthParam, mode):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 1,                   # pinUvAuthProtocol =  1
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    }

    if mode == "fidoDoc_WithoutPinUvAuthParamCase":
        cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 1,                   # pinUvAuthProtocol =  1
        # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    } 
    
    elif mode == "fidoDoc_MissingMandatoryParamCase" or mode == "self_MissingSubCommandRPBegin":
        cbor_map = {
        # 0x01: subCommand,          # subCommand
        0x03: 1,                   # pinUvAuthProtocol =  1
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    } 
        
    elif mode == "self_MissingProtocolRPBegin":
        cbor_map = {
        0x01: subCommand,          # subCommand
        # 0x03: 1,                   # pinUvAuthProtocol =  1
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    } 
        
    elif mode == "fidoDoc_UnsupportedProtocolCase":
        cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 3,                   # pinUvAuthProtocol =  1
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    } 
        
    elif mode == "self_MakeCredWithoutPINAlwaysUvFalseCase":
        cbor_map = {
        0x01: subCommand,          # subCommand
        # 0x03: 1,                   # pinUvAuthProtocol =  1
        # 0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    } 
        

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": randomUser(64),  # name 
       "displayName": randomUser(80),  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
        "id": rp,  # id: unique identifier
         "name": randomRPId(20)  # name
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

    if MODE == "self_MakeCredChangeRKValueEachTime":
        option  = {"rk": False}
    else:
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
    total_len = len(full_data) // 2
    

    apdus = []

    # ========================
    # CASE 1: Short APDU (≤ 255 bytes)
    # ========================
    if total_len <= 255:
        lc = f"{total_len:02X}"
        apdu = "80100000" + lc + full_data + "00"
        return apdu   # ✅ STRING

    # ========================
    # CASE 2: Chained APDUs (> 255 bytes)
    # ========================
    max_chunk_bytes = 255
    max_chunk_hex = max_chunk_bytes * 2

    chunks = wrap(full_data, max_chunk_hex)

    for idx, chunk in enumerate(chunks):
        is_last = (idx == len(chunks) - 1)

        cla = "80" if is_last else "90"
        ins = "10"
        p1  = "00"
        p2  = "00"
        lc  = f"{len(chunk) // 2:02X}"

        apdu = cla + ins + p1 + p2 + lc + chunk

        if is_last:
            apdu += "00"  # Le only for last APDU

        apdus.append(apdu)

    # 🔴 IMPORTANT:
    # Returned string is for LOGGING / FLOW only.
    # Actual sending must still be done per APDU.
    return "".join(apdus)
    
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
    total_len = len(full_data) // 2
    

    apdus = []

    # ========================
    # CASE 1: Short APDU (≤ 255 bytes)
    # ========================
    if total_len <= 255:
        lc = f"{total_len:02X}"
        apdu = "80100000" + lc + full_data + "00"
        return apdu   # ✅ STRING

    # ========================
    # CASE 2: Chained APDUs (> 255 bytes)
    # ========================
    max_chunk_bytes = 255
    max_chunk_hex = max_chunk_bytes * 2

    chunks = wrap(full_data, max_chunk_hex)

    for idx, chunk in enumerate(chunks):
        is_last = (idx == len(chunks) - 1)

        cla = "80" if is_last else "90"
        ins = "10"
        p1  = "00"
        p2  = "00"
        lc  = f"{len(chunk) // 2:02X}"

        apdu = cla + ins + p1 + p2 + lc + chunk

        if is_last:
            apdu += "00"  # Le only for last APDU

        apdus.append(apdu)

    # 🔴 IMPORTANT:
    # Returned string is for LOGGING / FLOW only.
    # Actual sending must still be done per APDU.
    return "".join(apdus)



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
    # pinAuthToken = 0
    # pubkey = 0
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
    # pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)

    # pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    # global pinUvAuthTokenAssociatedRPID 
    # pinUvAuthTokenAssociatedRPID = pinAuthToken

    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

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

def extractBOR(hex_response):
    # Convert hex → bytes
    raw_bytes = bytes.fromhex(hex_response)

    # Remove CTAP status byte (0x00)
    cbor_bytes = raw_bytes[1:]

    # Decode CBOR
    decoded = cbor2.loads(cbor_bytes)

    print("Decoded CBOR object:")
    print(decoded)
