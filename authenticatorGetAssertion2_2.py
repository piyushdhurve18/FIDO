import util
import secrets
import io
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
import getCredsMetadata2_2
import time
import DocumentCreation

oldPinUvAuthParam_Protocol1 = b""
oldPinUvAuthParam_Protocol2 = b""
oldPinUvAuthToken_Protocol1 = b""
oldPinUvAuthToken_Protocol2 = b""

duplicateDeleteCommandProtocol1 = ""
duplicateDeleteCommandProtocol2 = ""
maxCredentialCountInList = 8
maxCredentialIdLength = 128



RP_domain = "localhost"
RP_domain1_1 = "localhost1_1"
RP_domain1_2 = "localhost1_2"
RP_domain1_3 = "localhost1_3"
RP_domain1_4 = "localhost1_4"
RP_domain2_1 = "localhost2_1"
RP_domain2_2 = "localhost2_2"
RP_domain2_3 = "localhost2_3"
RP_domain2_4 = "localhost2_4"

maxLengthRPID = os.urandom(128).hex()


user="bobsmith"
user1_1="bobsmith1_1"
user1_2="bobsmith1_2"
user1_3="bobsmith1_3"
user1_4="bobsmith1_4"
user2_1="bobsmith2_1"
user2_2="bobsmith2_2"
user2_3="bobsmith2_3"
user2_4="bobsmith2_4"
globalUserName = ""
globalDisplayName = ""


globalCredentialID_Protocol1 = ""
globalCredentialID_Protocol2 = ""

globalRpIDBegin = ""
globalRpIDNext = ""
globalRPCollection = {}
globalUserEntityCollection = {}
globalCredentialIDCollection = {}
globalPublicKeyCollection = {}
GLOBAL_PUBLIC_KEY = ""

new_Pin = ""
clientDataHash = os.urandom(32)
MC_PERMISSION_BYTE = 0x01
GA_PERMISSION_BYTE = 0x02
CM_PERMISSION_BYTE = 0x04
PCMR_PERMISSION_BYTE = 0x40
MC_GA_CM_PERMISSION_BYTE = 0x07
MC_LBW_PERMISSION_BYTE = 0x11

INVALID_PERMISSION_BYTE = 0x20
UNSUPPORTED_PERMISSION_BYTE = 0x8F
WRONG_PERMISSION_BYTE = 0x10

pinUvAuthTokenAssociatedRPID = b""
oldPinUvAuthToken = b""
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
COMMAND_NAME = "AUTHENTICATOR GET ASSERTION"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def executeAuthenticatorGetAssertion(mode, reset_required, set_pin_required, make_cred_required, protocol):
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

    "fidoTool_1": """Test started: P-1 :
        Precondition: Reset Authenticator, Set PIN and create a Discoverable Credential.;
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoTool_2": """Test started: P-2 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "rpId" is missing, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_3": """Test started: P-3 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "rpId" is NOT of type STRING, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_4": """Test started: P-4 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "clientDataHash" is missing, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_5": """Test started: P-5 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "clientDataHash" is NOT of type BYTE ARRAY, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_6": """Test started: P-6 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" is NOT of type ARRAY, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_7": """Test started: P-7 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" contains a credential that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_8": """Test started: P-8 :
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, "options" containg an unknown option, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoTool_9": """Test started: P-9 :
        If authenticator supports "up" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.up set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UP flag set """,

    "fidoTool_10": """Test started: P-10 :
        If authenticator supports "uv" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.uv set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UV flag set.""",

    "fidoTool_11": """Test started: P-11 :
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT set to "public-key", wait for the response, and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoTool_12": """Test started: P-12 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains an element that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_13": """Test started: P-13 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is missing, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_14": """Test started: P-14 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_15": """Test started: P-15 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "id" field is missing, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_16": """Test started: P-16 :
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "id" field is NOT of type ARRAY BUFFER, wait for the response, and check that Authenticator returns an error.""",

    "fidoTool_17": """Test started: P-17 :
        If authenticator is Second-Factor only: Send CTAP2 authenticatorGetAssertion(0x02) message, with missing "allowList", and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E) error code.""",

    "fidoTool_18": """Test started: P-18 :
        Parse GetAssertion response, and check that: (a) response includes "signature" field, and it's of type BYTE STRING (b) response includes "authData" field, and it's of type BYTE STRING (c) response MUST not include "user", 'credential' and 'numberOfCredentials'""",

    "fidoTool_19": """Test started: P-19 :
        Parse GetAssertion_Response.authData and: (a) Check that it's exactly 37 bytes long (b) Check that authData.rpIdHash matches the hash of the GetAssertion_Request.rpId (c) Check that AT flag in authData.flags bitmap is not set.""",

    "fidoTool_20": """Test started: P-20 :
        Send three valid CTAP2 authenticatorGetAssertion(0x02) request, wait for the responses, and check that response2.counter is bigger than response1.counter, and response3.counter is bigger than response2.counter. Merge authData and clientDataHash, and using previously acquired publicKey verify signature from GetAssertion_Response""",

    "fidoStd_1": """Test started: P-21 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with rpId not matching stored credential RP, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_2": """Test started: P-22 :
        Precondition: Reset Authenticator and create maximum supported credentials for one RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) allowlist must be absent , check the response based on response.numberOfCredentials send  authenticatorGetNextAssertion(0x08) message response.numberOfCredentials -1 Times, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_3": """Test started: P-23 :
        Precondition: Reset Authenticator and create Discoverable Credential for RP1 and RP2.;
Send authenticatorGetAssertion(0x02) for RP1, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and does not expose RP2 credential.""",

    "fidoStd_4": """Test started: P-24 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send authenticatorGetAssertion(0x02) with very long rpId at maximum supported length, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_5": """Test started: P-25 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send authenticatorGetAssertion(0x02) with rpId exceeding maximum supported length, wait for the response, and check that Authenticator returns CTAP2_ERR_LIMIT_EXCEEDED error code.""",

    "fidoStd_6": """Test started: P-26 :
        Precondition: Reset Authenticator and create Discoverable Credential.;
Send authenticatorGetAssertion(0x02) with empty rpId string, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_LENGTH error code.""",

    "fidoStd_7": """Test started: P-27 :
        Precondition: Reset Authenticator, Set PIN and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with clientDataHash length less than 32 bytes, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_LENGTH error code.""",

    "fidoStd_8": """Test started: P-28 :
        Precondition: Reset Authenticator, Set PIN and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with clientDataHash length greater than 32 bytes, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_LENGTH error code.""",

    "fidoStd_9": """Test started: P-29 :
        Precondition: Reset Authenticator, Set PIN and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with pinUvAuthParam generated from different clientDataHash than given in clientDataHash (0x02), wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error code.""",

    "fidoStd_10": """Test started: P-30 :
        Precondition: Reset Authenticator, PIN not set and create a Non-Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with correct allowList, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_11": """Test started: P-31 :
        Precondition: Reset Authenticator, PIN not set and create a Non-Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_12": """Test started: P-32 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with empty credentialID in allowList, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_13": """Test started: P-33 :
        Precondition: Reset Authenticator, PIN Set and create Discoverable and Non-Discoverable Credentials.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList targeting Non - Discoverable credential, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E) error code.""",

    "fidoStd_14": """Test started: P-34 :
        Precondition: Reset Authenticator, PIN Set and create Discoverable and Non-Discoverable Credentials.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList targeting Non-Discoverable Credential, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_15": """Test started: P-35 :
        Precondition: Reset Authenticator, PIN Set and create multiple Discoverable Credentials for same RP with different user.id.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code each time.""",

    "fidoStd_16": """Test started: P-36 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with incorrect credentialId in allowList, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_17": """Test started: P-37 :
        Precondition: Reset Authenticator and create multiple Discoverable Credentials for same RP.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with allowList containing one valid and one invalid credentialId, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_18": """Test started: P-38 :
        Precondition: Reset Authenticator and create multiple Discoverable Credentials for different RPs.;
Send a CTAP2 authenticatorGetAssertion(0x02) message for RP1 with allowList containing credential for RP2, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_19": """Test started: P-39 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with duplicate allowList entries of same credentialId, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_20": """Test started: P-40 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with oversized allowList exceeding supported limit, wait for the response, and check that Authenticator returns CTAP2_ERR_LIMIT_EXCEEDED error code.""",

    "fidoStd_21": """Test started: P-41 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with credentialId of zero length in allowList, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_22": """Test started: P-42 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with a allowList contains maxCredentialCountList credentialIDs and every credentialID has length equals to maxCredentialIDLength from getInfo(0x04) but last credentialID in list having credentialID longer than maxCredentialIDLength, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_23": """Test started: P-43 :
        Precondition: Reset Authenticator and create multiple Non-Discoverable Credentials.;
Send authenticatorGetAssertion(0x02) with allowList containing no valid credentialId, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_24": """Test started: P-44 :
        Precondition: Reset Authenticator, Enable AlwaysUV, Set PIN and create a Discoverable Credential.;
Reset authenticator, send a CTAP2 authenticatorGetAssertion(0x02) message without pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP2_ERR_PUAT_REQUIRED error code.""",

    "fidoStd_25": """Test started: P-45 :
        Precondition: Reset Authenticator, Enable AlwaysUV, Set PIN and create a Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with valid UV/Pin, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_26": """Test started: P-46 :
        Precondition: Reset Authenticator and create a Non-Discoverable Credential using authenticatorMakeCredential with rk set to false.;
Send a CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_27": """Test started: P-47 :
        Precondition: Reset Authenticator and create a Discoverable Credential using authenticatorMakeCredential with rk set to true.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_28": """Test started: P-48 :
        Precondition: Reset Authenticator, Set PIN and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with invalid pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error code.""",

    "fidoStd_29": """Test started: P-49 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with incorrect pinUvAuthProtocol value, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error code.""",

    "fidoStd_30": """Test started: P-50 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message and verify response contains correct rpIdHash, signature and authData, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_31": """Test started: P-51 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message twice with different clientDataHash values, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and signCount increments every time.""",

    "fidoStd_32": """Test started: P-52 :
        Precondition: Reset Authenticator and create one Discoverable Credential.;
Send authenticatorGetAssertion(0x02) and verify numberOfCredentials field is omitted and Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_33": """Test started: P-53 :
        Precondition: Reset Authenticator and create Discoverable Credential.;
Send authenticatorGetAssertion(0x02) and verify signCount increases monotonically after reset power cycle after each authentincation, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_34": """Test started: P-54 :
        Precondition: Reset Authenticator and create Discoverable Credential.;
Send authenticatorGetAssertion(0x02) and verify that signature generated cannot be reused for different clientDataHash, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for valid request.""",

    "fidoStd_35": """Test started: P-55 :
        Precondition: Reset Authenticator and create Discoverable Credential.;
Send authenticatorGetAssertion(0x02) and verify that returned authData length matches specification, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_36": """Test started: P-56 :
        Precondition: Reset Authenticator and create multiple Non-Discoverable Credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList containing all valid credentialIds, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_37": """Test started: P-57 :
        Precondition: Reset Authenticator and create multiple Non-Discoverable Credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList containing some valid and some invalid credentialIds, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_38": """Test started: P-58 :
        Precondition: Reset Authenticator and create multiple Discoverable Credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code with numberOfCredentials; then send authenticatorGetNextAssertion(0x08) numberOfCredentials-1 times, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_39": """Test started: P-59 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential where user.name and displayName are long boundary values.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and returns stored user.id only.""",

    "fidoStd_40": """Test started: P-60 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential where user.name and displayName are empty.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and returns stored only user.id.""",

    "fidoStd_41": """Test started: P-61 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential with enterprise attestation enabled.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator does not expose enterprise attestation data during assertion.""",

    "fidoStd_42": """Test started: P-62 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential with initial signCount value set to zero.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and increments signCount correctly.""",

    "fidoStd_43": """Test started: P-63 :
        Precondition: Reset Authenticator and create maximum number of Discoverable Credentials using authenticatorMakeCredential until storage limit is reached.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message for each stored credential, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for valid credentials.""",

    "fidoStd_44": """Test started: P-64 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential with excludeList preventing duplicate credential creation.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message for original credential, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_45": """Test started: P-65 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential where PIN was not set during creation.;
Set PIN after creation and send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_46": """Test started: P-66 :
        Precondition: Reset Authenticator and create multiple Credentials using authenticatorMakeCredential for same user.id but different RP IDs.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message for one RP, wait for the response, and check that Authenticator returns only credentials bound to that RP.""",

    "fidoStd_47": """Test started: P-67 :
        Precondition: Reset Authenticator, create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that authenticatorData rpIdHash matches SHA-256 of rpId.""",

    "fidoStd_48": """Test started: P-68 :
        Precondition: Reset Authenticator, create a Credential.;
Case 1: Send a valid CTAP2 authenticatorGetAssertion(0x02) message with up is True, wait for the response, and check that UP flag is set in authenticatorData.
Case 2: Send a valid CTAP2 authenticatorGetAssertion(0x02) message with up is False, wait for the response, and check that UP flag is not set in authenticatorData.""",

    "fidoStd_49": """Test started: P-69 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with correct pinAuth, wait for the response, and check that UV flag is set.""",

    "fidoStd_50": """Test started: P-70 :
        Precondition: Reset Authenticator, PIN not set and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that UV flag is not set.""",

    "fidoStd_51": """Test started: P-71 :
        Precondition: Reset Authenticator, create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and verify that signCount is present.""",

    "fidoStd_52": """Test started: P-72 :
        Precondition: Reset Authenticator, create a Credential and perform one successful assertion.;
Send another valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that signCount increments.""",

    "fidoStd_53": """Test started: P-73 :
        Precondition: Reset Authenticator, create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and verify signature verifies using stored public key.""",

    "fidoStd_54": """Test started: P-74 :
        Precondition: Reset Authenticator, create multiple Credentials.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that numberOfCredentials field equals total matching credentials.""",

    "fidoStd_55": """Test started: P-75 :
        Precondition: Reset Authenticator, create multiple Credentials.;
Send authenticatorGetAssertion(0x02) followed by valid authenticatorGetNextAssertion(0x08), wait for the response, and check that numberOfCredentials field is omitted in next response.""",

    "fidoStd_56": """Test started: P-76 :
        Precondition: Reset Authenticator, create a Credential and perform assertions until signCount reaches maximum value.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check counter behavior at boundary.""",

    "fidoStd_57": """Test started: P-77 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with incorrect pinAuth, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_INVALID error code.""",

    "fidoStd_58": """Test started: P-78 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send multiple CTAP2 authenticatorGetAssertion(0x02) messages with incorrect pinAuth until retries exhausted, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_BLOCKED error code.""",

    "fidoStd_59": """Test started: P-79 :
        Precondition: Reset Authenticator, PIN not set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with pinAuth parameter, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_NOT_SET error code.""",

    "fidoStd_60": """Test started: P-80 :
        Precondition: Reset Authenticator, create maximum supported number of Discoverable Credentials for one RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and verify numberOfCredentials equals maximum supported.""",

    "fidoStd_61": """Test started: P-81 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with allowList present as an empty array, wait for the response, and check that empty allowList must be omitted and Authenticator returns CTAP1_ERR_SUCCESS error code.""",

    "fidoStd_62": """Test started: P-82 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList parameter, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_63": """Test started: P-83 :
        Precondition: Reset Authenticator and create multiple Credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList containing two credentials, wait for the response, and check that Authenticator returns assertions only from those two and numberOfCredentials equals 2.""",

    "fidoStd_64": """Test started: P-84 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message with allowList containing credential ID that does not exist, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "fidoStd_65": """Test started: P-85 :
        Precondition: Reset Authenticator and create multiple Credentials.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList containing one valid and one invalid credential ID, wait for the response, and check that Authenticator returns assertion only for the valid credential.""",

    "fidoStd_66": """Test started: P-86 :
        Precondition: Reset Authenticator and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList containing duplicate credential descriptors referencing same credential ID, wait for the response, and check that Authenticator returns only one assertion.""",

    "fidoStd_67": """Test started: P-87 :
        Precondition: Reset Authenticator and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message with allowList containing credential descriptor missing required fields, wait for the response, and check that Authenticator returns CTAP2_ERR_INVALID_CBOR error code.""",

    "fidoStd_68": """Test started: P-88 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.rk set to true, wait for the response, and check that Authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION error code.""",

    "fidoStd_69": """Test started: P-89 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.rk set to false, wait for the response, and check that Authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION error code.""",

    "fidoStd_70": """Test started: P-90 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options map containing both valid option (up) and invalid option (rk), wait for the response, and check that Authenticator rejects the request with CTAP2_ERR_INVALID_OPTION error code.""",

    "fidoStd_71": """Test started: P-91 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.rk and other invalid options simultaneously, wait for the response, and check that Authenticator rejects the request before performing any credential lookup.""",

    "fidoStd_72": """Test started: P-92 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthParam but omitting pinUvAuthProtocol, wait for the response, and check that Authenticator returns CTAP2_ERR_MISSING_PARAMETER error code.""",

    "fidoStd_73": """Test started: P-93 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthParam and including pinUvAuthProtocol with unsupported value, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_PARAMETER error code.""",

    "fidoStd_74": """Test started: P-94 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthProtocol but omitting pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error code.""",

    "fidoStd_75": """Test started: P-95 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthParam with incorrect length and including supported pinUvAuthProtocol, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_LENGTH error code.""",

    "fidoStd_76": """Test started: P-96 :
        Precondition: Reset Authenticator, PIN not set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthParam and including supported pinUvAuthProtocol, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_NOT_SET error code.""",

    "fidoStd_77": """Test started: P-97 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthParam, omitting pinUvAuthProtocol, and including incorrect pinUvAuthParam value, wait for the response, and check that Authenticator returns CTAP2_ERR_MISSING_PARAMETER error code before validating pinUvAuthParam value.""",

    "fidoStd_78": """Test started: P-98 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including pinUvAuthParam, including unsupported pinUvAuthProtocol, and including incorrect pinUvAuthParam value, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_PARAMETER error code before validating pinUvAuthParam value.""",

    "fidoStd_79": """Test started: P-99 :
        Precondition: Reset Authenticator, PIN not set and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without performing user verification, wait for the response, and check that UP bit is true and UV bit remains false.""",

    "fidoStd_80": """Test started: P-100 :
        Precondition: Reset Authenticator, create multiple Credentials.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList returning multiple credentials, then call authenticatorGetNextAssertion(0x08), wait for the response, and check that UP and UV bits are set only according to current operation and not copied blindly from previous response.""",

    "fidoStd_81": """Test started: P-101 :
        Precondition: Reset Authenticator and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message and inspect authenticatorData flags byte, wait for the response, and check that only allowed bits (UP, UV, BE, BS, AT, ED) are set and no unexpected bits are set.""",

    "fidoStd_82": """Test started: P-102 :
        Precondition: Reset Authenticator and create a Credential without extensions.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that ED bit remains false.""",

    "fidoStd_83": """Test started: P-103 :
        Precondition: Reset Authenticator and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including options map containing unknown key, wait for the response, and check that Authenticator treats the unknown key as absent and returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "fidoStd_84": """Test started: P-104 :
        Precondition: Reset Authenticator and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including options with both unknown key and valid "up" key, wait for the response, and check that Authenticator processes only recognized keys.""",

    "fidoStd_85": """Test started: P-105 :
        Precondition: Reset Authenticator, PIN not set and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without options.uv, wait for the response, and check that Authenticator treats uv as false and returns CTAP1_ERR_SUCCESS(0x00) error code with UV bit false.""",

    "fidoStd_86": """Test started: P-106 :
        Precondition: Reset Authenticator, PIN set and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without options.uv and without pinUvAuthParam, wait for the response, and check that Authenticator treats uv as false.""",

    "fidoStd_87": """Test started: P-107 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.rk set to true, wait for the response, and check that Authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION error code.""",

    "fidoStd_88": """Test started: P-108 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.rk set to false, wait for the response, and check that Authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION error code.""",

    "fidoStd_89": """Test started: P-109 :
        Precondition: Reset Authenticator and create a Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without options.up, wait for the response, and check that Authenticator treats up as true and UP bit is set.""",

    "fidoStd_90": """Test started: P-110 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.up set to false, wait for the response, and check that Authenticator suppresses user presence test if supported.""",

    "fidoStd_91": """Test started: P-111 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.up set to true, wait for the response, and check that Authenticator performs user presence verification.""",

    "fidoStd_92": """Test started: P-112 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including unknown option key and options.rk, wait for the response, and check that Authenticator rejects due to unsupported rk option.""",

    "fidoStd_93": """Test started: P-113 :
        Precondition: Reset Authenticator and create a Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message including options.rk with non-boolean value, wait for the response, and check that Authenticator returns CTAP2_ERR_INVALID_CBOR error code.""",

    "fidoStd_94": """Test started: P-114 :
        Precondition: Reset Authenticator, alwaysUv option enabled, authenticator not protected by user verification, clientPin supported and noMcGaPermissionsWithClientPin absent.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including options.up set to true, wait for the response, and check that Authenticator returns CTAP2_ERR_PUAT_REQUIRED error code.""",

    "fidoStd_95": """Test started: P-115 :
        Precondition: Reset Authenticator, alwaysUv option enabled, authenticator protected by user verification, clientPin supported and noMcGaPermissionsWithClientPin absent, and pinUvAuthParam not provided.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including options.up set to true, wait for the response, and check that Authenticator returns CTAP2_ERR_PUAT_REQUIRED error code.""",

    "fidoStd_96": """Test started: P-116 :
        Precondition: Reset Authenticator, alwaysUv option enabled, authenticator protected by user verification, valid pinUvAuthToken with ga permission exists.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including options.up set to true and valid pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and UV bit is set to true.""",

    "self_1": """Test started: P-117 :
        Precondition: Reset Authenticator, PIN set, pinUvAuthToken without ga permission.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including valid pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error code.""",

    "self_2": """Test started: P-118 :
        Precondition: Reset Authenticator, PIN set, pinUvAuthToken associated with RP-A.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message for RP-B including valid pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error code.""",

    "self_3": """Test started: P-119 :
        Precondition: Reset Authenticator, PIN set, pinUvAuthToken without permissions RP ID associated.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including valid pinUvAuthParam, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and associates the request rpId with the pinUvAuthToken.""",

    "self_4": """Test started: P-120 :
        Precondition: Reset Authenticator and create both Discoverable and Non-Discoverable Credentials for one RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that Authenticator returns only Discoverable credentials and excludes Non-Discoverable credentials.""",

    "self_5": """Test started: P-121 :
        Precondition: Reset Authenticator, PIN set, valid pinUvAuthToken created, pinUvAuthParam present, and internal getUserPresentFlagValue() returns true.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS(0x00)
UP bit is set to true
No additional user interaction is required""",

    "self_6": """Test started: P-122 :
        Precondition: Reset Authenticator, request includes "up": false, no pinUvAuthParam.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS(0x00)
UP bit remains false""",

    "self_7": """Test started: P-123 :
        Precondition: Reset Authenticator, request includes "up": false, pinUvAuthParam present and valid.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS(0x00)
UP bit remains false""",

    "self_8": """Test started: P-124 :
        Precondition: Reset Authenticator and create one credential for an RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including allowList containing that credential ID, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
Response does NOT contain numberOfCredentials member
Returned credential ID matches allowList entry
Signature verifies successfully using the credential public key
Signature is computed over authenticatorData || clientDataHash as defined in WebAuthn""",

    "self_9": """Test started: P-125 :
        Precondition: Reset Authenticator and create three credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including allowList containing all three credential IDs, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
Response does NOT contain numberOfCredentials
Returned credential ID is one of the allowList entries
Signature verifies successfully""",

    "self_10": """Test started: P-126 :
        Precondition:
Reset Authenticator and create:
Credential-A for RP-A
Credential-B for RP-B;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message for RP-A including allowList containing Credential-B ID, wait for the response, and check that:
Authenticator returns CTAP2_ERR_NO_CREDENTIALS""",

    "self_11": """Test started: P-127 :
        Precondition: Reset Authenticator and create one credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including allowList with that credential ID, wait for the response, and verify that:
Signature input equals authenticatorData || clientDataHash
Signature verification using stored public key succeeds
Signature algorithm matches credential’s COSE algorithm
Signature format and verification rules must follow WebAuthn.""",

    "self_12": """Test started: P-128 :
        Precondition: Reset Authenticator and create multiple credentials.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message including allowList with multiple credential IDs, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
numberOfCredentials member is NOT present in the response map
Only a single assertion is returned""",

    "self_13": """Test started: P-129 :
        Precondition: Reset Authenticator and create exactly one discoverable credential for an RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
numberOfCredentials is either absent or equals 1 (implementation dependent)
Returned credential ID matches the only stored credential
Signature verifies successfully per WebAuthn""",

    "self_14": """Test started: P-130 :
        Precondition: Reset Authenticator and create three discoverable credentials sequentially:
Credential-A (oldest)
Credential-B
Credential-C (most recent);
Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
numberOfCredentials equals 3
First returned credential is Credential-C (most recently created)""",

    "self_15": """Test started: P-131 :
        Precondition: Reset Authenticator and create three discoverable credentials sequentially:
Credential-A (oldest)
Credential-B
Credential-C (most recent);

Send a valid CTAP2 authenticatorGetAssertion(0x02) message without allowList, wait for the response, and check that:;
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
numberOfCredentials equals 3
First returned credential is Credential-C (most recently created);;

Send CTAP2 authenticatorGetNextAssertion(0x08) once, wait for the response, and check that:;
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
Returned credential is Credential-B;;

Send authenticatorGetNextAssertion(0x08) again and check that:;
Returned credential is Credential-A""",

    "self_16": """Test started: P-132 :
        Precondition: Reset Authenticator and create discoverable credential with full user entity info (id, name, displayName, icon).;
Send a valid authenticatorGetAssertion(0x02) without options.uv, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS (0x00)
user.id is present
user.name, user.displayName, and user.icon are NOT present
user entity matches stored credential""",

    "self_17": """Test started: P-133 :
        Precondition: Reset Authenticator and create multiple discoverable credentials.;
Send authenticatorGetAssertion(0x02) without UV and without allowList, wait for response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
numberOfCredentials > 1
Returned user entity includes only user.id
name/displayName/icon are omitted.""",

    "self_18": """Test started: P-134 :
        Precondition: Reset Authenticator without sending authenticatorGetAssertion.;
Send authenticatorGetNextAssertion(0x08), wait for the response, and check that Authenticator returns CTAP2_ERR_NOT_ALLOWED error code.""",

    "self_19": """Test started: P-135 :
        Precondition: Reset Authenticator and create one Discoverable Credential.;
Send authenticatorGetAssertion(0x02) and then send authenticatorGetNextAssertion(0x08), wait for the response, and check that Authenticator returns CTAP2_ERR_NOT_ALLOWED error code.""",

    "self_20": """Test started: P-136 :
        Precondition: Reset Authenticator and create multiple Discoverable Credentials for same RP.;
Send authenticatorGetAssertion(0x02) without allowList, then call authenticatorGetNextAssertion(0x08) until credentialCounter equals numberOfCredentials-1, then send one more authenticatorGetNextAssertion(0x08), wait for the response, and check that Authenticator returns CTAP2_ERR_NOT_ALLOWED error code.""",

    "self_21": """Test started: P-137 :
        Precondition: Reset Authenticator and create multiple Discoverable Credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, power cycle the Authenticator, then send authenticatorGetNextAssertion(0x08), wait for the response, and check that Authenticator returns CTAP2_ERR_NOT_ALLOWED error code.""",

    "self_22": """Test started: P-138 :
        Precondition: Reset Authenticator and create two Discoverable Credentials for same RP.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, delete one credential internally, then send authenticatorGetNextAssertion(0x08), wait for the response, and check that Authenticator returns CTAP2_ERR_NOT_ALLOWED error code.""",

    "self_23": """Test started: P-139 :
        Precondition: Reset Authenticator and create a Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message repeatedly 100 times, wait for each response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code each time.""",

    "self_24": """Test started: P-140 :
        Precondition: Reset Authenticator and create Discoverable Credential.;
Send authenticatorGetAssertion(0x02) with additional unexpected CBOR parameters, wait for the response, and check that Authenticator processes request returns  CTAP1_ERR_SUCCESS(0x00) error code.""",

    "self_25": """Test started: P-141 :
        Precondition: Reset Authenticator and create multiple Discoverable Credentials.;
Send authenticatorGetAssertion(0x02) and verify numberOfCredentials returned equals total matching credentials and Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "self_26": """Test started: P-142 :
        Precondition: Reset Authenticator and create a Non-Discoverable Credential.;
Send authenticatorGetAssertion(0x02) with allowList containing multiple entries including the correct credentialId, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "self_27": """Test started: P-143 :
        Precondition: Reset Authenticator and create a Credential using authenticatorMakeCredential where user.id length is at maximum supported size.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code and user.id matches stored value.""",

    "self_28": """Test started: P-144 :
        Precondition: Reset Authenticator, PIN not set and create a Discoverable Credential.;
Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

    "self_29": """Test started: P-145 :
        Precondition: Reset Authenticator without creating any Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",

    "self_30": """Test started: P-146 :
        Precondition: Reset Authenticator , Set PIN and create discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check aaguid from response and aaguid from get Info, both must match.""",

    "self_31": """Test started: P-147 :
        Precondition: Reset Authenticator , Set PIN and create discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check credentialIdLength is equals to the returned credentialID length.""",

    "self_32": """Test started: P-148 :
        Precondition: Reset Authenticator , No PIN Set and create discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check aaguid from response and aaguid from get Info, both must match.""",

    "self_33": """Test started: P-149 :
        Precondition: Reset Authenticator ,No PIN Set and create discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check credentialIdLength is equals to the returned credentialID length.""",

    "self_34": """Test started: P-150 :
        Precondition: Reset Authenticator , Set PIN and create Non discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check aaguid from response and aaguid from get Info, both must match.""",

    "self_35": """Test started: P-151 :
        Precondition: Reset Authenticator , Set PIN and create Non discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check credentialIdLength is equals to the returned credentialID length.""",

    "self_36": """Test started: P-152 :
        Precondition: Reset Authenticator , No PIN Set and create Non discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check aaguid from response and aaguid from get Info, both must match.""",

    "self_37": """Test started: P-153 :
        Precondition: Reset Authenticator ,No PIN Set and create Non discoverable Credential.;
Send a CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP2_OK error code. Check credentialIdLength is equals to the returned credentialID length.""",

    "self_38": """Test started: P-154 :
        Precondition: Authenticator Reset, No PIN Set , Create Credential and Authenticate it successfully.;
Parse GetAssertion response, and check that: (a) response includes "signature" field, and it's of type BYTE STRING (b) response includes "authData" field, and it's of type BYTE STRING (c) response MUST not include 'numberOfCredentials'""",


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

    global maxCredentialCountInList
    global maxCredentialIdLength
    
    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    util.ResetCardPower()
    util.ConnectJavaCard()
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])

    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    pin = "11223344"
    
    if reset_required == "yes":
        resetPowerCycle(True)
        util.APDUhex("00A4040008A0000006472F000100", "Select applet")
        response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        if status == "00":
            util.printcolor(util.CYAN,f"PRECONDITION : FIDO RESET DONE >> {retrieveStatusName(status)}")
        else:
            util.printcolor(util.RED,f"PRECONDITION: FIDO RESET FAILED >> {retrieveStatusName(status)}")
            # exit(0)

    if set_pin_required == "yes":
        if protocol == "PROTOCOL_ONE":
            response, status =  setpinProtocol1(pin)  #Set new pin 12121212
            if status == "00":
                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> SET PIN DONE >> {retrieveStatusName(status)}")
            else:
                util.printcolor(util.RED,f"PRECONDITION: {protocol} >> SET PIN FAILED >> {retrieveStatusName(status)}")
                exit(0)
        elif protocol == "PROTOCOL_TWO":
            response, status = setpinProtocol2(pin)  #Set new pin 12121212
            if status == "00":
                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> SET PIN DONE >> {retrieveStatusName(status)}")
            else:
                util.printcolor(util.RED,f"PRECONDITION: {protocol} >> SET PIN FAILED >> {retrieveStatusName(status)}")
                exit(0)
    
    if make_cred_required == "yes":
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if set_pin_required == "yes":
                if protocol == "PROTOCOL_ONE":
                    if mode == "fidoStd_2":
                        for i in range(maxCredCount):
                            user = "Piyush."+randomUser(4)+"@"+str(i)
                            response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> {i+1} TIME AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >>{i+1} TIME AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                            GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_3":
                        for i in range(2):
                            rpId = "entra"+str(i+1)+".com"
                            response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> {i+1} TIME AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >>{i+1} TIME AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                            GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_23":
                        for i in range(5):
                            rpId = "entra"+str(i+1)+".com"
                            response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> {i+1} TIME AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >>{i+1} TIME AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                            GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_13" or mode == "fidoStd_14":
                        rpId = "entra1.com"
                        response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            util.printcolor(util.CYAN,f"Discoverable Credential Created")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)

                        resetPowerCycle(True)
                        rpId = "entra.com"
                        response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, "sub_fidoStd_13")
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            util.printcolor(util.CYAN,f"Non Discoverable Credential Created")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)
                        GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_15":
                        isRpIDSame = True
                        credCount = 5
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)
                    
                    elif mode == "fidoStd_36" or mode == "fidoStd_37":
                        isRpIDSame = True
                        credCount = 5
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_17":
                        isRpIDSame = True
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_18":
                        isRpIDSame = False
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_43":
                        isRpIDSame = True
                        credCount = maxCredCount
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "self_14" or mode == "self_15" or mode == "self_17" or mode == "self_20" or mode == "self_21":
                        isRpIDSame = True
                        credCount = 3
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "self_22":
                        isRpIDSame = True
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_80":
                        isRpIDSame = True
                        credCount = 3
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_46":
                        isRpIDSame = False
                        credCount = 5
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)
                    
                    elif mode == "fidoStd_55":
                        isRpIDSame = True
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol1(pin, credCount, rpId, isRpIDSame)

                    else:
                        if mode == "fidoStd_4":
                            rpId = maxLengthRPID

                        if mode == "self_27":
                            user = randomUser(64)
                        

                        if mode == "fidoStd_24" or mode == "fidoStd_25" or mode == "fidoStd_95" or mode == "fidoStd_96":
                            response, status = toggleAlwaysUvProtocol1(pin, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR CONFIG(ENABLE ALWAYS UV) DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR CONFIG(ENABLE ALWAYS UV) FAILED >> {retrieveStatusName(status)}")
                                exit(0)

                        if mode == "fidoStd_41":
                            response, status = authenticatorConfigEnableEnterpriseAttestationProtocol1(pin, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR CONFIG(ENABLE EP) DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR CONFIG(ENABLE EP) FAILED >> {retrieveStatusName(status)}")
                                exit(0)

                        response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)
                        GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                elif protocol == "PROTOCOL_TWO":
                    if mode == "fidoStd_2":
                        
                        for i in range(maxCredCount):
                            # resetPowerCycle(True) # Uncomment this line for YubiKey operation
                            user = "Piyush."+randomUser(4)+"@"+str(i)
                            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> {i+1} TIME AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >>{i+1} TIME AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                            GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_15":
                        isRpIDSame = True
                        credCount = 5
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_36" or mode == "fidoStd_37":
                        isRpIDSame = True
                        credCount = 5
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)
                    
                    elif mode == "fidoStd_17":
                        isRpIDSame = True
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_18":
                        isRpIDSame = False
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_43":
                        isRpIDSame = True
                        credCount = maxCredCount
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "self_14" or mode == "self_15" or mode == "self_17" or mode == "self_20" or mode == "self_21":
                        isRpIDSame = True
                        credCount = 3
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "self_22":
                        isRpIDSame = True
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)
                    
                    elif mode == "fidoStd_80":
                        isRpIDSame = True
                        credCount = 3
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_46":
                        isRpIDSame = False
                        credCount = 5
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_55":
                        isRpIDSame = True
                        credCount = 2
                        makeCredentialNumberOfTimesProtocol2(pin, credCount, rpId, isRpIDSame)

                    elif mode == "fidoStd_3":
                        for i in range(2):
                            resetPowerCycle(True) # Uncomment this line for YubiKey operation
                            rpId = "entra"+str(i+1)+".com"
                            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> {i+1} TIME AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >>{i+1} TIME AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                            GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_23":
                        for i in range(5):
                            rpId = "entra"+str(i+1)+".com"
                            response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> {i+1} TIME AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >>{i+1} TIME AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                            GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                    elif mode == "fidoStd_13" or mode == "fidoStd_14":
                        rpId = "entra1.com"
                        response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            util.printcolor(util.CYAN,f"Discoverable Credential Created")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)

                        
                        rpId = "entra.com"
                        response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, "sub_fidoStd_13")
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            util.printcolor(util.CYAN,f"Non Discoverable Credential Created")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)
                        GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)

                        rpId = "entra.com"
                        response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, "sub_fidoStd_13")
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                            util.printcolor(util.CYAN,f"Non Discoverable Credential Created")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)
                        GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)
                    else:
                        if mode == "fidoStd_4":
                            rpId = maxLengthRPID

                        if mode == "self_27":
                            user = randomUser(64)
                       

                        if mode == "fidoStd_24" or mode == "fidoStd_25" or mode == "fidoStd_95" or mode == "fidoStd_96":
                            response, status = toggleAlwaysUvProtocol2(pin, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR CONFIG(ENABLE ALWAYS UV) DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR CONFIG(ENABLE ALWAYS UV) FAILED >> {retrieveStatusName(status)}")
                                exit(0)

                        if mode == "fidoStd_41":
                            response, status = authenticatorConfigEnableEnterpriseAttestationProtocol2(pin, mode)
                            if status == "00":
                                util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR CONFIG(ENABLE EP) DONE >> {retrieveStatusName(status)}")
                            else:
                                util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR CONFIG(ENABLE EP) FAILED >> {retrieveStatusName(status)}")
                                exit(0)
                        
                        # resetPowerCycle(True)
                        response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                        if status == "00":
                            util.printcolor(util.CYAN,f"PRECONDITION : {protocol} >> AUTHENTICATOR MAKE CREDENTIAL DONE >> {retrieveStatusName(status)}")
                        else:
                            util.printcolor(util.RED,f"PRECONDITION: {protocol} >> AUTHENTICATOR MAKE CREDENTIAL FAILED >> {retrieveStatusName(status)}")
                            exit(0)
                        GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)
                else:
                    util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                    exit(0)
            else:
                rk = True
                if mode == "fidoStd_10" or mode == "fidoStd_11":
                    rk = False

                response, status = makeCredWithoutPINSet(clientDataHash, rpId, user, rk, mode)
                if status == "00":
                    util.printcolor(util.CYAN,f"PRECONDITION : AUTHENTICATOR MAKE CREDENTIAL WITHOUT PIN DONE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"PRECONDITION: AUTHENTICATOR MAKE CREDENTIAL WITHOUT PIN FAILED >> {retrieveStatusName(status)}")
                    exit(0)

                GLOBAL_PUBLIC_KEY = getCredentialPublicKeyFromResponse(response)
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
    util.APDUhex("80100000010400", "GetInfo")

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

    ######################################
    #### EXTRA FOR POS CASE REFERENCE ####
    ######################################
    if mode == "PositiveCase Using Extraction of Response and Validating(Including ep)":
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            response, status = authenticatorGetInfo()
            key = "ep"
            value = extractResponseCBOR(response, key)
            util.printcolor(util.CYAN,f"{key} >> '{value}'")
            if protocol == "PROTOCOL_ONE":
                response, status = authenticatorConfigEnableEnterpriseAttestationProtocol1(pin, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR CONFIG -- ENABLE ENTERPRISE ATTESTATION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    response, status = authenticatorGetInfo()
                    value = extractResponseCBOR(response, key)
                    if value != True:
                        util.printcolor(util.RED,f"{key} >> '{value}'")
                        exit(0)
                    else:
                        util.printcolor(util.GREEN,f"{key} >> '{value}'")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR CONFIG -- ENABLE ENTERPRISE ATTESTATION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
                response, status = makeCredProtocol1(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR MAKE CREDENTIAL RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR MAKE CREDENTIAL RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
                key = "2"
                value = extractResponseCBOR(response, key)
                exit(0)
                   
            elif protocol == "PROTOCOL_TWO":
                response, status = authenticatorConfigEnableEnterpriseAttestationProtocol2(pin, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR CONFIG -- ENABLE ENTERPRISE ATTESTATION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    response, status = authenticatorGetInfo()
                    value = extractResponseCBOR(response, key)
                    if value != True:
                        util.printcolor(util.RED,f"{key} >> '{value}'")
                        exit(0)
                    else:
                        util.printcolor(util.GREEN,f"{key} >> '{value}'")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR CONFIG -- ENABLE ENTERPRISE ATTESTATION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
                response, status = makeCredProtocol2(pin, clientDataHash, rpId, user, MC_PERMISSION_BYTE, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR MAKE CREDENTIAL RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR MAKE CREDENTIAL RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
                key = "2"
                value = extractResponseCBOR(response, key)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)


    ######################################
    ###############   END   ##############
    ######################################

    if mode == "fidoTool_1":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_2":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_3":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com".encode("utf-8")
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_4":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_5":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_6":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_7":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_8":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_9":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == True:
                    util.printcolor(util.GREEN,f"EXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UNEXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == True:
                    util.printcolor(util.GREEN,f"EXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UNEXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                    exit(0)
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_10":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                # flag = "UV"
                # flagValue = get_flag_from_getAssertion_response(response, flag)
                # if flagValue == True:
                #     util.printcolor(util.GREEN,f"EXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                # else:
                #     util.printcolor(util.RED,f"UNEXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                #     exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                # flag = "UV"
                # flagValue = get_flag_from_getAssertion_response(response, flag)
                # if flagValue == True:
                #     util.printcolor(util.GREEN,f"EXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                # else:
                #     util.printcolor(util.RED,f"UNEXPECTED: authenticatorData.flags have {flag} flag set to '{flagValue}'")
                #     exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_11":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_12":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_13":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_14":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_15":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_16":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_17":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_18":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "signature"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData != None:
                    util.printcolor(util.YELLOW,f"{field} >> {fieldData}")
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

                field = "userId"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData != None:
                    userID = hex_to_ascii(fieldData)
                    if user == userID:
                        util.printcolor(util.YELLOW,f"{field} >> {userID}")
                    else:
                        util.printcolor(util.RED,f"Response Returned: {field} >> {userID} & Request Given: {field} >> {user} NOT Matched")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

                field = "credentialId"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData != None:
                    util.printcolor(util.YELLOW,f"{field} >> {fieldData}")
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

                field = "numberOfCredentials"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData == None:
                    util.printcolor(util.YELLOW,f"{field} >> {fieldData}")
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)
                

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "signature"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData != None:
                    util.printcolor(util.YELLOW,f"{field} >> {fieldData}")
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

                field = "userId"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData != None:
                    userID = hex_to_ascii(fieldData)
                    if user == userID:
                        util.printcolor(util.YELLOW,f"{field} >> {userID}")
                    else:
                        util.printcolor(util.RED,f"Response Returned: {field} >> {userID} & Request Given: {field} >> {user} NOT Matched")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

                field = "credentialId"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData != None:
                    util.printcolor(util.YELLOW,f"{field} >> {fieldData}")
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

                field = "numberOfCredentials"
                fieldData = parse_get_assertion_field(response, field)
                if fieldData == None:
                    util.printcolor(util.YELLOW,f"{field} >> {fieldData}")
                else:
                    util.printcolor(util.RED,f"{field} >> {fieldData}")
                    exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_19":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                authData = extract_authdata_from_getAssertion_response(response)
                if len(authData)//2 >= 37:
                    util.printcolor(util.YELLOW,f"auth Data >> {authData}({len(authData)//2} bytes)")
                else:
                    util.printcolor(util.RED,f"auth Data is not at least 37 bytes >> {authData}({len(authData)//2} bytes)")
                    exit(0)


                hashField = "rpIdHash"
                rpIdHashRes = parse_get_assertion_field(response, hashField).upper()
                rpIdHashGen = generateRpIDHash(rpId).upper()
                util.printcolor(util.CYAN,f"authData.rpIdHash : {rpIdHashRes}")
                util.printcolor(util.CYAN,f"GetAssertion_Request.rpId : {rpIdHashGen}")
                if rpIdHashRes == rpIdHashGen:
                    util.printcolor(util.YELLOW,f"authData.rpIdHash matches the hash of the GetAssertion_Request.rpId")
                else:
                    util.printcolor(util.RED,f"authData.rpIdHash NOT matches the hash of the GetAssertion_Request.rpId")
                    exit(0)

                flag = "AT"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == False or flagValue == None:
                    util.printcolor(util.YELLOW,f"AT flag in authData.flags bitmap is not set; {flag} = '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"AT flag in authData.flags bitmap is set; {flag} = '{flagValue}'")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                authData = extract_authdata_from_getAssertion_response(response)
                if len(authData)//2 >= 37:
                    util.printcolor(util.YELLOW,f"auth Data >> {authData}({len(authData)//2} bytes)")
                else:
                    util.printcolor(util.RED,f"auth Data is not at least 37 bytes >> {authData}({len(authData)//2} bytes)")
                    exit(0)


                hashField = "rpIdHash"
                rpIdHashRes = parse_get_assertion_field(response, hashField).upper()
                rpIdHashGen = generateRpIDHash(rpId).upper()
                util.printcolor(util.CYAN,f"authData.rpIdHash : {rpIdHashRes}")
                util.printcolor(util.CYAN,f"GetAssertion_Request.rpId : {rpIdHashGen}")
                if rpIdHashRes == rpIdHashGen:
                    util.printcolor(util.YELLOW,f"authData.rpIdHash matches the hash of the GetAssertion_Request.rpId")
                else:
                    util.printcolor(util.RED,f"authData.rpIdHash NOT matches the hash of the GetAssertion_Request.rpId")
                    exit(0)

                flag = "AT"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == False or flagValue == None:
                    util.printcolor(util.YELLOW,f"AT flag in authData.flags bitmap is not set; {flag} = '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"AT flag in authData.flags bitmap is set; {flag} = '{flagValue}'")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoTool_20":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "signCount"
                signCount1 = parse_get_assertion_field(response, field)

                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                signCount2 = parse_get_assertion_field(response, field)
                if signCount2 > signCount1:
                    util.printcolor(util.YELLOW,f"response2.counter({signCount2}) is bigger than response1.counter({signCount1})")
                else:
                    util.printcolor(util.RED,f"response2.counter({signCount2}) is not bigger than response1.counter({signCount1})")
                    exit(0)

                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                signCount3 = parse_get_assertion_field(response, field)
                if signCount3 > signCount2:
                    util.printcolor(util.YELLOW,f"response3.counter({signCount3}) is bigger than response2.counter({signCount2})")
                else:
                    util.printcolor(util.RED,f"response3.counter({signCount3}) is not bigger than response2.counter({signCount2})")
                    exit(0)

                authDataStr = extract_authdata_from_getAssertion_response(response)
                signatureField = "signature"
                signature = bytes.fromhex(parse_get_assertion_field(response, signatureField))
                publicKey = load_public_key_from_cose_hex(GLOBAL_PUBLIC_KEY)

                isSignatureValid = verify_assertion_signature(authDataStr, clientDataHash, signature, publicKey)
                if isSignatureValid == True:
                    util.printcolor(util.YELLOW,f"Signature : {signature.hex()}")
                    util.printcolor(util.YELLOW,f"✅ Signature VALID")
                else:
                    util.printcolor(util.RED,f"Signature : {signature.hex()}")
                    util.printcolor(util.RED,f"❌ Signature INVALID")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "signCount"
                signCount1 = parse_get_assertion_field(response, field)

                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                signCount2 = parse_get_assertion_field(response, field)
                if signCount2 > signCount1:
                    util.printcolor(util.YELLOW,f"response2.counter({signCount2}) is bigger than response1.counter({signCount1})")
                else:
                    util.printcolor(util.RED,f"response2.counter({signCount2}) is not bigger than response1.counter({signCount1})")
                    exit(0)

                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                signCount3 = parse_get_assertion_field(response, field)
                if signCount3 > signCount2:
                    util.printcolor(util.YELLOW,f"response3.counter({signCount3}) is bigger than response2.counter({signCount2})")
                else:
                    util.printcolor(util.RED,f"response3.counter({signCount3}) is not bigger than response2.counter({signCount2})")
                    exit(0)

                authDataStr = extract_authdata_from_getAssertion_response(response)
                signatureField = "signature"
                signature = bytes.fromhex(parse_get_assertion_field(response, signatureField))
                publicKey = load_public_key_from_cose_hex(GLOBAL_PUBLIC_KEY)

                isSignatureValid = verify_assertion_signature(authDataStr, clientDataHash, signature, publicKey)
                if isSignatureValid == True:
                    util.printcolor(util.YELLOW,f"Signature : {signature.hex()}")
                    util.printcolor(util.YELLOW,f"✅ Signature VALID")
                else:
                    util.printcolor(util.RED,f"Signature : {signature.hex()}")
                    util.printcolor(util.RED,f"❌ Signature INVALID")
                    exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    elif mode == "fidoStd_1":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra1.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_2":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
                
                fieldCredNum = "numberOfCredentials"
                credNum = parse_get_assertion_field(response, fieldCredNum)
                if credNum == maxCredCount:
                    util.printcolor(util.YELLOW,f"EXPECTED: numberOfCredentials = {credNum}")
                else:
                    util.printcolor(util.RED,f"UNEXPECTED: numberOfCredentials = {credNum}")
                    exit(0)

                for i in range(credNum):
                    response, status = authenticatorGetNextAssertion(mode)
                    if status == "00" or ( i== credNum - 1 and status == "30" ):
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)
                

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldCredNum = "numberOfCredentials"
                credNum = parse_get_assertion_field(response, fieldCredNum)
                if credNum == maxCredCount:
                    util.printcolor(util.YELLOW,f"EXPECTED: numberOfCredentials = {credNum}")
                else:
                    util.printcolor(util.RED,f"UNEXPECTED: numberOfCredentials = {credNum}")
                    exit(0)

                for i in range(credNum):
                    response, status = authenticatorGetNextAssertion(mode)
                    if status == "00" or ( i== credNum - 1 and status == "30" ):
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_3":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                rpId = "entra1.com"
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                rpId = "entra2.com"
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                rpId = "entra1.com"
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                rpId = "entra2.com"
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_4":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = maxLengthRPID
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_5":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_6":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = ""
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_7":
            scenarioCount += 1
            clientDataHash = os.urandom(31)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_8":
            scenarioCount += 1
            clientDataHash = os.urandom(33)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_9":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_10":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_11":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_12":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_13":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_14":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_15":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                for i in range(5):
                    credID_Key = "CREDENTIAL_ID_"+str(i+1)
                    credID = getCredentialID(credID_Key)
                    util.printcolor(util.YELLOW,f"Authenticating CredentialID >> {credID}")

                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credID, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

            elif protocol == "PROTOCOL_TWO":
                for i in range(5):
                    credID_Key = "CREDENTIAL_ID_"+str(i+1)
                    credID = getCredentialID(credID_Key)
                    util.printcolor(util.YELLOW,f"Authenticating CredentialID >> {credID}")

                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credID, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_16":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                credId = randomHexStr(2)+globalCredentialID_Protocol1
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                credId = randomHexStr(2)+globalCredentialID_Protocol2
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_17":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_18":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                rpId = getRpID("RP_1")
                credId = getCredentialID("CREDENTIAL_ID_2")
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                rpId = getRpID("RP_1")
                credId = getCredentialID("CREDENTIAL_ID_2")
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credId, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_19":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_20":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "15":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "15":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_21":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, "", mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, "", mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_22":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1+globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2+globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_23":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, randomHexStr(maxCredentialIdLength), mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, randomHexStr(maxCredentialIdLength), mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_24":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_25":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_26":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_27":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_28":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_29":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_30":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_31":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount = parse_get_assertion_field(response, fieldSignCount)
                if signCount > 0:
                    util.printcolor(util.CYAN,f"signCount is greater than zero after first successful authentication i.e. signCount = {signCount}")
                else:
                    util.printcolor(util.RED,f"signCount is not greater than zero after first successful authentication i.e. signCount = {signCount}")
                    exit(0)

                clientDataHash = os.urandom(32)
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount1 = parse_get_assertion_field(response, fieldSignCount)
                if signCount1 > signCount:
                    util.printcolor(util.CYAN,f"signCount value incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                else:
                    util.printcolor(util.RED,f"signCount value NOT incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                    exit(0)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount = parse_get_assertion_field(response, fieldSignCount)
                if signCount > 0:
                    util.printcolor(util.CYAN,f"signCount is greater than zero after first successful authentication i.e. signCount = {signCount}")
                else:
                    util.printcolor(util.RED,f"signCount is not greater than zero after first successful authentication i.e. signCount = {signCount}")
                    exit(0)

                clientDataHash = os.urandom(32)
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount1 = parse_get_assertion_field(response, fieldSignCount)
                if signCount1 > signCount:
                    util.printcolor(util.CYAN,f"signCount value incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                else:
                    util.printcolor(util.RED,f"signCount value NOT incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_32":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldCredNum = "numberOfCredentials"
                numberOfCredentials = parse_get_assertion_field(response, fieldCredNum)
                if numberOfCredentials == None:
                    util.printcolor(util.CYAN,f"numberOfCredentials is Omitted")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials is Not Omitted")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldCredNum = "numberOfCredentials"
                numberOfCredentials = parse_get_assertion_field(response, fieldCredNum)
                if numberOfCredentials == None:
                    util.printcolor(util.CYAN,f"numberOfCredentials is Omitted")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials is Not Omitted")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_33":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount = parse_get_assertion_field(response, fieldSignCount)
                if signCount > 0:
                    util.printcolor(util.CYAN,f"signCount is greater than zero after first successful authentication i.e. signCount = {signCount}")
                else:
                    util.printcolor(util.RED,f"signCount is not greater than zero after first successful authentication i.e. signCount = {signCount}")
                    exit(0)
                resetPowerCycle(True)

                clientDataHash = os.urandom(32)
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount1 = parse_get_assertion_field(response, fieldSignCount)
                if signCount1 > signCount:
                    util.printcolor(util.CYAN,f"signCount value incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                else:
                    util.printcolor(util.RED,f"signCount value NOT incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                    exit(0)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount = parse_get_assertion_field(response, fieldSignCount)
                if signCount > 0:
                    util.printcolor(util.CYAN,f"signCount is greater than zero after first successful authentication i.e. signCount = {signCount}")
                else:
                    util.printcolor(util.RED,f"signCount is not greater than zero after first successful authentication i.e. signCount = {signCount}")
                    exit(0)

                resetPowerCycle(True)

                clientDataHash = os.urandom(32)
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                fieldSignCount = "signCount"
                signCount1 = parse_get_assertion_field(response, fieldSignCount)
                if signCount1 > signCount:
                    util.printcolor(util.CYAN,f"signCount value incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                else:
                    util.printcolor(util.RED,f"signCount value NOT incremeted after second authentication i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_34":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                authDataStr = extract_authdata_from_getAssertion_response(response)
                signatureField = "signature"
                signature = bytes.fromhex(parse_get_assertion_field(response, signatureField))
                publicKey = load_public_key_from_cose_hex(GLOBAL_PUBLIC_KEY)
                clientDataHash = os.urandom(32)
                isSignatureValid = verify_assertion_signature(authDataStr, clientDataHash, signature, publicKey)
                if isSignatureValid == False:
                    util.printcolor(util.YELLOW,f"Signature : {signature.hex()}")
                    util.printcolor(util.YELLOW,f"❌ Signature INVALID")
                else:
                    util.printcolor(util.RED,f"Signature : {signature.hex()}")
                    util.printcolor(util.RED,f"✅ Signature VALID even after using different clientDataHash")
                    exit(0)
                

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                authDataStr = extract_authdata_from_getAssertion_response(response)
                signatureField = "signature"
                signature = bytes.fromhex(parse_get_assertion_field(response, signatureField))
                publicKey = load_public_key_from_cose_hex(GLOBAL_PUBLIC_KEY)
                clientDataHash = os.urandom(32)
                isSignatureValid = verify_assertion_signature(authDataStr, clientDataHash, signature, publicKey)
                if isSignatureValid == False:
                    util.printcolor(util.YELLOW,f"Signature : {signature.hex()}")
                    util.printcolor(util.YELLOW,f"❌ Signature INVALID")
                else:
                    util.printcolor(util.RED,f"Signature : {signature.hex()}")
                    util.printcolor(util.RED,f"✅ Signature VALID even after using different clientDataHash")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_35":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                authDataStr = extract_authdata_from_getAssertion_response(response)
                authDataArr = bytes.fromhex(authDataStr)
                dataLen = len(authDataArr)
                if dataLen >= 37:
                    util.printcolor(util.YELLOW,f"returned authData length matches specification i.e. authData Length = {dataLen}")
                else:
                    util.printcolor(util.RED,f"returned authData length not matches specification i.e. authData Length = {dataLen}")
                    exit(0)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                authDataStr = extract_authdata_from_getAssertion_response(response)
                authDataArr = bytes.fromhex(authDataStr)
                dataLen = len(authDataArr)
                if dataLen >= 37:
                    util.printcolor(util.YELLOW,f"returned authData length matches specification i.e. authData Length = {dataLen}")
                else:
                    util.printcolor(util.RED,f"returned authData length not matches specification i.e. authData Length = {dataLen}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_36":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_37":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_38":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_39":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                userField = "userId"
                userValue = parse_get_assertion_field(response, userField)
                if user == hex_to_ascii(userValue):
                    util.printcolor(util.YELLOW,f"User.id matched")
                else:
                    util.printcolor(util.RED,f"User.id not matched")
                    exit(0)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                userField = "userId"
                userValue = parse_get_assertion_field(response, userField)
                if user == hex_to_ascii(userValue):
                    util.printcolor(util.YELLOW,f"User.id matched")
                else:
                    util.printcolor(util.RED,f"User.id not matched")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_40":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                userField = "userId"
                userValue = parse_get_assertion_field(response, userField)
                if user == hex_to_ascii(userValue):
                    util.printcolor(util.YELLOW,f"User.id matched")
                else:
                    util.printcolor(util.RED,f"User.id not matched")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                userField = "userId"
                userValue = parse_get_assertion_field(response, userField)
                if user == hex_to_ascii(userValue):
                    util.printcolor(util.YELLOW,f"User.id matched")
                else:
                    util.printcolor(util.RED,f"User.id not matched")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_41":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                validate_enterprise_attestation_in_assertion(response)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                validate_enterprise_attestation_in_assertion(response)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_42":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_43":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                for i  in range(maxCredCount):
                    credIDKey = "CREDENTIAL_ID_"+str(i+1)
                    credID = getCredentialID(credIDKey)
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, credID, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

            elif protocol == "PROTOCOL_TWO":
                for i  in range(maxCredCount):
                    credIDKey = "CREDENTIAL_ID_"+str(i+1)
                    credID = getCredentialID(credIDKey)
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, credID, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_44":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_45":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status =  setpinProtocol1(pin)  #Set new pin 12121212
                if status == "00":
                    util.printcolor(util.CYAN,f"{protocol} >> SET PIN DONE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> SET PIN FAILED >> {retrieveStatusName(status)}")
                    exit(0)
                
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status =  setpinProtocol2(pin)  #Set new pin 12121212
                if status == "00":
                    util.printcolor(util.CYAN,f"{protocol} >> SET PIN DONE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> SET PIN FAILED >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_46":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = getRpID("RP_5")
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_47":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_48":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == True:
                    util.printcolor(util.GREEN,f"UP set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UP set to '{flagValue}'")
                    exit(0)


                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, "sub_fidoStd_48")
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == False:
                    util.printcolor(util.GREEN,f"UP set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UP set to '{flagValue}'")
                    exit(0)



            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == True:
                    util.printcolor(util.GREEN,f"UP set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UP set to '{flagValue}'")
                    exit(0)


                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, "sub_fidoStd_48")
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == False:
                    util.printcolor(util.GREEN,f"UP set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UP set to '{flagValue}'")
                    exit(0)


            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_49":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UV"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == True:
                    util.printcolor(util.GREEN,f"UV set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UV set to '{flagValue}'")
                    exit(0)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
                
                flag = "UV"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == True:
                    util.printcolor(util.GREEN,f"UV set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UV set to '{flagValue}'")
                    exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_50":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UV"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == False:
                    util.printcolor(util.GREEN,f"UV set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UV set to '{flagValue}'")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UV"
                flagValue = get_flag_from_getAssertion_response(response, flag)
                if flagValue == False:
                    util.printcolor(util.GREEN,f"UV set to '{flagValue}'")
                else:
                    util.printcolor(util.RED,f"UV set to '{flagValue}'")
                    exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_51":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_52":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_53":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_54":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_55":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentialsKey = "numberOfCredentials"
                numberOfCredentials = parse_get_assertion_field(response, numberOfCredentialsKey)
                if numberOfCredentials == None:
                    util.printcolor(util.GREEN,f"numberOfCredentials is Absent")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials is Present")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentialsKey = "numberOfCredentials"
                numberOfCredentials = parse_get_assertion_field(response, numberOfCredentialsKey)
                if numberOfCredentials == None:
                    util.printcolor(util.GREEN,f"numberOfCredentials is Absent")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials is Present")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_56":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_57":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "31":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "31":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_58":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_59":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "35":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "35":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_60":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_61":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_62":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_63":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_64":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_65":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_66":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_67":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_68":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2B":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2B":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_69":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2B":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2B":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_70":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_71":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2B":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2B":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_72":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "14":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_73":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "02":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "02":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_74":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_75":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "03":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_76":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_77":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_78":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_79":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == True:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)

                flag = "UV"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == True:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)

                flag = "UV"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_80":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == 3:
                    util.printcolor(util.GREEN,f"numberOfCredentials = {numberOfCredentials}")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials = {numberOfCredentials}")
                    exit(0)

                for i in range(numberOfCredentials-1):
                    response, status = authenticatorGetNextAssertion(mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

                    flag = "UP"
                    value = get_flag_from_getAssertion_response(response, flag)
                    if value == True:
                        util.printcolor(util.GREEN,f"{flag} is {value}")
                    else:
                        util.printcolor(util.RED,f"{flag} is {value}")
                        exit(0)

                    flag = "UV"
                    value = get_flag_from_getAssertion_response(response, flag)
                    if value == True:
                        util.printcolor(util.GREEN,f"{flag} is {value}")
                    else:
                        util.printcolor(util.RED,f"{flag} is {value}")
                        exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == 3:
                    util.printcolor(util.GREEN,f"numberOfCredentials = {numberOfCredentials}")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials = {numberOfCredentials}")
                    exit(0)

                for i in range(numberOfCredentials-1):
                    response, status = authenticatorGetNextAssertion(mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{i+1} TIME AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

                    flag = "UP"
                    value = get_flag_from_getAssertion_response(response, flag)
                    if value == True:
                        util.printcolor(util.GREEN,f"{flag} is {value}")
                    else:
                        util.printcolor(util.RED,f"{flag} is {value}")
                        exit(0)

                    flag = "UV"
                    value = get_flag_from_getAssertion_response(response, flag)
                    if value == True:
                        util.printcolor(util.GREEN,f"{flag} is {value}")
                    else:
                        util.printcolor(util.RED,f"{flag} is {value}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_81":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)


            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_82":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "ED"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "ED"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_83":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_84":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_85":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_86":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_87":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_88":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_89":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_90":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_91":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_92":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_93":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "11":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_94":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
            if protocol == "PROTOCOL_ONE":

                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_95":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "36":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "fidoStd_96":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_1":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_2":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_3":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_4":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_5":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_6":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)



                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_7":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                flag = "UP"
                value = get_flag_from_getAssertion_response(response, flag)
                if value == False:
                    util.printcolor(util.GREEN,f"{flag} is {value}")
                else:
                    util.printcolor(util.RED,f"{flag} is {value}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_8":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_9":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_10":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_11":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_12":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_13":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_14":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == 3:
                    util.printcolor(util.GREEN,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                else:
                    util.printcolor(util.RED,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_3")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"First returned credential is Credential-C (most recently created)")
                else:
                    util.printcolor(util.RED,f"First returned credential is Not Credential-C (Not most recently created)")
                    exit(0)




            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == 3:
                    util.printcolor(util.GREEN,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                else:
                    util.printcolor(util.RED,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_3")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"First returned credential is Credential-C (most recently created)")
                else:
                    util.printcolor(util.RED,f"First returned credential is Not Credential-C (Not most recently created)")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_15":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == 3:
                    util.printcolor(util.GREEN,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                else:
                    util.printcolor(util.RED,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_3")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"First returned credential is Credential-C (most recently created)")
                else:
                    util.printcolor(util.RED,f"First returned credential is Not Credential-C (Not most recently created)")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_2")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"Returned credential is Credential-B")
                else:
                    util.printcolor(util.RED,f"Returned credential is NOT Credential-B")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_1")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"Returned credential is Credential-A")
                else:
                    util.printcolor(util.RED,f"Returned credential is NOT Credential-A")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == 3:
                    util.printcolor(util.GREEN,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                else:
                    util.printcolor(util.RED,f"Credential Created 3; numberOfCredentials = {numberOfCredentials} in response")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_3")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"First returned credential is Credential-C (most recently created)")
                else:
                    util.printcolor(util.RED,f"First returned credential is Not Credential-C (Not most recently created)")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_2")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"Returned credential is Credential-B")
                else:
                    util.printcolor(util.RED,f"Returned credential is NOT Credential-B")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                credentialId = parse_get_assertion_field(response, "credentialId")
                mc_CredID = getCredentialID("CREDENTIAL_ID_1")
                if credentialId == mc_CredID:
                    util.printcolor(util.GREEN,f"Returned credential is Credential-A")
                else:
                    util.printcolor(util.RED,f"Returned credential is NOT Credential-A")
                    exit(0)

                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_16":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "userId"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.GREEN,f"{field} is Present; {field} = {hex_to_ascii(value)}")
                else:
                    util.printcolor(util.RED,f"{field} is Not Present")
                    exit(0)

                field = "userName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")
                    

                field = "userDisplayName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "userId"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.GREEN,f"{field} is Present; {field} = {hex_to_ascii(value)}")
                else:
                    util.printcolor(util.RED,f"{field} is Not Present")
                    exit(0)

                field = "userName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")

                field = "userDisplayName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")
                
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_17":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 3:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                field = "userId"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.GREEN,f"{field} is Present; {field} = {hex_to_ascii(value)}")
                else:
                    util.printcolor(util.RED,f"{field} is Not Present")
                    exit(0)

                field = "userName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")

                field = "userDisplayName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 3:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                field = "userId"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.GREEN,f"{field} is Present; {field} = {hex_to_ascii(value)}")
                else:
                    util.printcolor(util.RED,f"{field} is Not Present")
                    exit(0)

                field = "userName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")

                field = "userDisplayName"
                value = parse_get_assertion_field(response, field)
                if value != None:
                    util.printcolor(util.RED,f"{field} is Present; {field} = {value}")
                    exit(0)
                else:
                    util.printcolor(util.CYAN,f"{field} is Not Present")

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_18":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_19":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_20":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 3:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                for i in range(3):
                    response, status = authenticatorGetNextAssertion(mode)
                    if (i != 2 and status == "00") or (i == 2 and status == "30"):
                        util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

                

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 3:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                for i in range(3):
                    response, status = authenticatorGetNextAssertion(mode)
                    if (i != 2 and status == "00") or (i == 2 and status == "30"):
                        util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_21":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 3:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                resetPowerCycle(True)

                util.APDUhex("00A4040008A0000006472F000100", "Select applet")
                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 3:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                resetPowerCycle(True)

                util.APDUhex("00A4040008A0000006472F000100", "Select applet")
                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_22":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 2:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                
                response, status = deleteCredentialsProtocol1(pin, CM_PERMISSION_BYTE, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> DELETE CREDENTIALS RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> DELETE CREDENTIALS RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, "sub_self_22")
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                field = "numberOfCredentials"
                value = parse_get_assertion_field(response, field)
                if value == 2:
                    util.printcolor(util.GREEN,f"{field} is {value}")
                else:
                    util.printcolor(util.RED,f"{field} is {value}")
                    exit(0)

                response, status = deleteCredentialsProtocol2(pin, CM_PERMISSION_BYTE, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> DELETE CREDENTIALS RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> DELETE CREDENTIALS RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, "sub_self_22")
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                response, status = authenticatorGetNextAssertion(mode)
                if status == "30":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET NEXT ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_23":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            signCount1 = 0
            if protocol == "PROTOCOL_ONE":
                for i in range(100):
                    signCount = signCount1
                    response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

                    signCount1 = parse_get_assertion_field(response, "signCount")
                    if signCount1 > signCount:
                        util.printcolor(util.CYAN,f"signCount incremented i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                    else:
                        util.printcolor(util.RED,f"signCount not incremented i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                        exit(0)

            elif protocol == "PROTOCOL_TWO":
                for i in range(100):
                    signCount = signCount1
                    response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                    if status == "00":
                        util.printcolor(util.GREEN,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    else:
                        util.printcolor(util.RED,f"{protocol} >> {i+1} TIME AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                        exit(0)

                    signCount1 = parse_get_assertion_field(response, "signCount")
                    if signCount1 > signCount:
                        util.printcolor(util.CYAN,f"signCount incremented i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                    else:
                        util.printcolor(util.RED,f"signCount not incremented i.e. Previous signCount = {signCount}; Current signCount = {signCount1}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_24":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_25":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_26":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_27":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                userId = parse_get_assertion_field(response, "userId")
                if user == hex_to_ascii(userId):
                    util.printcolor(util.CYAN,f"user.id matches stored value")
                else:
                    util.printcolor(util.RED,f"user.id NOT matches stored value")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                userId = parse_get_assertion_field(response, "userId")
                if user == hex_to_ascii(userId):
                    util.printcolor(util.CYAN,f"user.id matches stored value")
                else:
                    util.printcolor(util.RED,f"user.id NOT matches stored value")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_28":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_29":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "2E":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_30":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = authenticatorGetInfo()
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET INFO RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET INFO RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = authenticatorGetInfo()
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET INFO RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET INFO RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_31":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_32":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_33":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_34":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_35":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_36":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_37":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionProtocol1(pin, clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionProtocol2(pin, clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "self_38":
            scenarioCount += 1
            clientDataHash = os.urandom(32)
            rpId = "entra.com"
            user = "Piyush"
            if protocol == "PROTOCOL_ONE":
                response, status = getAssertionWithoutPINSetProtocol1(clientDataHash, rpId, globalCredentialID_Protocol1, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                signature = parse_get_assertion_field(response, "signature")
                if signature != None:
                    util.printcolor(util.CYAN,f"response includes 'signature' field, and it's of type BYTE STRING")
                else:
                    util.printcolor(util.RED,f"response not includes 'signature' field")
                    exit(0)

                authData = parse_get_assertion_field(response, "authData")
                if authData != None:
                    util.printcolor(util.CYAN,f"response includes 'authData' field, and it's of type BYTE STRING")
                else:
                    util.printcolor(util.RED,f"response not includes 'authData' field")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == None:
                    util.printcolor(util.CYAN,f"numberOfCredentials not present")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials present")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                response, status = getAssertionWithoutPINSetProtocol2(clientDataHash, rpId, globalCredentialID_Protocol2, mode)
                if status == "00":
                    util.printcolor(util.GREEN,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED EXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                else:
                    util.printcolor(util.RED,f"{protocol} >> AUTHENTICATOR GET ASSERTION RETURNED UNEXPECTED STATUS CODE >> {retrieveStatusName(status)}")
                    exit(0)

                signature = parse_get_assertion_field(response, "signature")
                if signature != None:
                    util.printcolor(util.CYAN,f"response includes 'signature' field, and it's of type BYTE STRING")
                else:
                    util.printcolor(util.RED,f"response not includes 'signature' field")
                    exit(0)

                authData = parse_get_assertion_field(response, "authData")
                if authData != None:
                    util.printcolor(util.CYAN,f"response includes 'authData' field, and it's of type BYTE STRING")
                else:
                    util.printcolor(util.RED,f"response not includes 'authData' field")
                    exit(0)

                numberOfCredentials = parse_get_assertion_field(response, "numberOfCredentials")
                if numberOfCredentials == None:
                    util.printcolor(util.CYAN,f"numberOfCredentials not present")
                else:
                    util.printcolor(util.RED,f"numberOfCredentials present")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

            
    else:
        util.printcolor(util.RED,f"'{mode}' MODE NOT FOUND FOR {protocol}")
        exit(0)



  


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
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


def validate_ep_batch_certificate_like(x5c_list):
    """
    Validates that x5c[0] looks like a valid Enterprise Batch Attestation certificate.
    Does NOT compare against a known EPBatchCertificate.
    """

    # 1. Basic checks
    if not isinstance(x5c_list, list) or len(x5c_list) == 0:
        return False, "x5c must be a non-empty list"

    if not isinstance(x5c_list[0], (bytes, bytearray)):
        return False, "x5c[0] must be a byte string"

    try:
        cert = x509.load_der_x509_certificate(
            bytes(x5c_list[0]),
            default_backend()
        )
    except Exception:
        return False, "x5c[0] is not valid DER X.509"

    # 2. Must be X.509 v3
    if cert.version != x509.Version.v3:
        return False, "Certificate is not X.509 v3"

    # 3. Must NOT be a CA
    try:
        bc = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if bc.ca:
            return False, "Certificate is a CA (invalid for EP batch)"
    except x509.ExtensionNotFound:
        pass  # Absence is acceptable per some implementations

    # 4. Must NOT be self-signed
    if cert.subject == cert.issuer:
        return False, "Certificate is self-signed (not a batch cert)"

    # 5. Must use EC P-256
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False, "Public key is not EC"

    if pub.curve.name != "secp256r1":
        return False, "EC curve is not P-256"
    
    return True, "Looks like a valid EP Batch Attestation certificate"


def authenticatorGetInfo():
    util.APDUhex("00a4040008a0000006472f000100", "Select applet")
    response, status = util.APDUhex("80100000010400", "Get Info")
    return response, status

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
    extractResponseCBOR
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


from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_serial_number_from_x5c(x5c_list):
    # Take first certificate (leaf)
    cert_bytes = x5c_list[0]

    # Load DER certificate
    cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

    # Get serial number (integer)
    serial_number = cert.serial_number

    # Convert to hex string (recommended for certificates)
    serial_hex = format(serial_number, 'X')

    return serial_hex


def extractResponseCBOR(hex_response: str, requestKey: str):
    """
    Input  : CTAP2 response as HEX string
    Output : Prints full CBOR tree and prints & returns requested key value
    """

    found_value = None

    def dump(value, indent=0):
        nonlocal found_value
        pad = "  " * indent

        if isinstance(value, dict):
            print(f"{pad}MAP ({len(value)})")
            for k, v in value.items():
                # if isinstance(k, int):
                #     key_str = format(k, 'X')
                # else:
                #     key_str = str(k)
                print(f"{pad}  KEY [{type(k).__name__}] = {k}")

                # ---- Match requested key ----
                if str(k) == requestKey:
                    found_value = v

                dump(v, indent + 2)

        elif isinstance(value, list):
            print(f"{pad}ARRAY ({len(value)})")
            for i, item in enumerate(value):
                print(f"{pad}  INDEX {i}")
                dump(item, indent + 2)

        elif isinstance(value, bytes):
            print(f"{pad}BYTES ({len(value)}): {value.hex()}")

        else:
            print(f"{pad}{type(value).__name__}: {value}")

    # ---- Decode CTAP2 response ----
    raw = binascii.unhexlify(hex_response)

    if not raw:
        raise ValueError("Empty response")

    status = raw[0]
    print(f"CTAP2 STATUS = 0x{status:02X}")

    if status != 0x00:
        print("CTAP2 error response — no CBOR payload")
        return None

    if len(raw) == 1:
        print("No CBOR payload present")
        return None

    decoded = cbor2.loads(raw[1:])

    print("\nCBOR DECODED STRUCTURE")
    print("---------------------")
    dump(decoded)

    # ---- Handle result inside function ----
    print("\nRESULT")
    print("------")
    if found_value is not None:
        print("Requested key value found:")
        if isinstance(found_value, bytes):
            print(found_value.hex())
        else:
            print(found_value)
    else:
        util.printcolor(util.RED,f"Requested key '{requestKey}' not found")

    return found_value



# def extractGetInfo(hex_response: str, requestKey):
#     reqKey = requestKey
#     """
#     Input  : CTAP2 response as HEX string
#     Output : Prints CTAP2 status + full CBOR tree
#     """

#     def dump(value, reqKey):
#         i = 0
#         indent=0
#         pad = "  " * indent
#         boolValue = ""

#         if isinstance(value, dict):
#             print(f"{pad}MAP ({len(value)})")
#             for k, v in value.items():
#                 print(f"{pad}  KEY [{type(k).__name__}] = {k}")
#                 dump(v, indent + 2)
               

#         elif isinstance(value, list):
#             print(f"{pad}ARRAY ({len(value)})")
#             for i, item in enumerate(value):
#                 print(f"{pad}  INDEX {i}")
#                 dump(item, indent + 2)

#         elif isinstance(value, bytes):
#             print(f"{pad}BYTES ({len(value)}): {value.hex()}")

#         else:
#             print(f"{pad}{type(value).__name__}: {value}")


#     # --- Decode ---
#     raw = binascii.unhexlify(hex_response)

#     if len(raw) == 0:
#         raise ValueError("Empty response")

#     status = raw[0]
#     print(f"CTAP2 STATUS = 0x{status:02X}")

#     if status != 0x00:
#         print("CTAP2 error response — no CBOR payload")
#         return

#     if len(raw) == 1:
#         print("No CBOR payload present")
#         return

#     # CBOR starts AFTER status byte
#     cbor_payload = raw[1:]

#     decoded = cbor2.loads(cbor_payload)

#     print("\nCBOR DECODED STRUCTURE")
#     print("---------------------")
#     dump(decoded, reqKey)




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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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


def makeCredentialNumberOfTimesProtocol2(pin, maxCredCount, rp, isRpIDSame):
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

        response, status = makeCredProtocol2(pin, clientDataHash, RP_domain, user, MC_PERMISSION_BYTE, MODE)  #Make cred by protocol 2
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

def makeCredentialNumberOfTimesProtocol1(pin, maxCredCount, rp, isRpIDSame):
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

        response, status = makeCredProtocol1(pin, clientDataHash, RP_domain, user, MC_PERMISSION_BYTE, MODE)  #Make cred by protocol 1
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    util.APDUhex("80100000010400", "get info")
    response, status = getPINTokenWithPermissionWithoutPINSetProtocol1(pin, permission, mode)
    return response, status

def getCredsMetadataWithoutPINSetProtocol2(pin, permission, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    util.APDUhex("80100000010400", "get info")
    response, status = getPINTokenWithPermissionWithoutPINSetProtocol2(pin, permission, mode)
    return response, status


def enumerateCredentialsBeginProtocol2(pin, permission, rp, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")

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
            util.APDUhex("00A4040008A0000006472F000100", "Select applet")
        apdu = deleteCredInfoProtocol1(pinToken,subCommand, credId, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status

def deleteCredentialsProtocol2(pin, permission, credId, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")

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
            util.APDUhex("00A4040008A0000006472F000100", "Select applet")
        apdu = deleteCredInfoProtocol2(pinToken,subCommand, credId, mode)


    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status


def deleteCredentialsWithoutPinProtocol2(permission, credId, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    subCommand = 0x06  #delecredential credential 
    apdu = deleteCredInfoWithoutPinProtocol2(subCommand, credId, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status

def deleteCredentialsWithoutPinProtocol1(permission, credId, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    subCommand = 0x06  #delecredential credential 
    apdu = deleteCredInfoWithoutPinProtocol1(subCommand, credId, mode)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    return response, status

def getAssertionProtocol1(curpin, clientDataHash, rp, credId, mode):
    resetPowerCycle(True)
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    
    if mode == "self_1":
        pinToken, pubkey = getPINTokenWithPermissionProtocol1(curpin, PCMR_PERMISSION_BYTE, mode)
    elif mode == "self_2":
        pinToken, pubkey = getPINTokenWithPermissionProtocol1(curpin, GA_PERMISSION_BYTE, mode)
    else:
        pinToken = getPINtokenPubkeyProtocol1(curpin)

    pinUvAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:16]
    if mode == "fidoStd_9":
        clientDataHash = os.urandom(32)
    
    if mode == "fidoStd_28":
        pinUvAuthParam = os.urandom(16)

    apdu = createCBORmakeAssertion_Protocol1(clientDataHash, rp, pinUvAuthParam, credId, mode)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status

def getAssertionWithoutPINSetProtocol1(clientDataHash, rp, credId, mode):
    resetPowerCycle(True)
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    apdu = createCBORmakeAssertionWithoutPINSet_Protocol1(clientDataHash, rp, credId, mode)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status

def getAssertionWithoutPINSetProtocol2(clientDataHash, rp, credId, mode):
    resetPowerCycle(True)
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    apdu = createCBORmakeAssertionWithoutPINSet_Protocol2(clientDataHash, rp, credId, mode)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status

def createCBORmakeAssertionWithoutPINSet_Protocol1(clientDataHash, rp, credId, mode):
    pinUvAuthParam = os.urandom(16)
    allowList  = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    if mode == "fidoStd_12":
        allowList  = [{
        "id": bytes.fromhex(""),
        "type": "public-key"
    }]

    options  = {"uv": False, "up": True}
    if mode == "self_6":
        options  = {"up": False}

    if mode == "fidoStd_11":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                # 0x03: allowList,                                # allowList
                0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_59":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                0x05: options,                                  # options
                0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_79":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                # 0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "self_16":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                # 0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "self_17":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                # 0x03: allowList,                                # allowList
                # 0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 1,                                        # pinUvAuthProtocol 
        }
    else:
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 1,                                        # pinUvAuthProtocol 
        }

    getAssertionCBOR = cbor2.dumps(get_assertion_map).hex().upper()
    full_payload = "02" + getAssertionCBOR
    length = len(full_payload) // 2
    if length <= 255:
        apdu = "80100000" + f"{length:02X}" + full_payload
    else:
        apdu = "80100000" + "00" + f"{length:04X}" + full_payload    
    return apdu

def createCBORmakeAssertionWithoutPINSet_Protocol2(clientDataHash, rp, credId, mode):
    pinUvAuthParam = os.urandom(32)
    allowList  = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    if mode == "fidoStd_12":
        allowList  = [{
        "id": bytes.fromhex(""),
        "type": "public-key"
    }]

    options  = {"uv": False, "up": True}
    if mode == "self_6":
        options  = {"up": False}

    if mode == "fidoStd_11":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                # 0x03: allowList,                                # allowList
                0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_59":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                0x05: options,                                  # options
                0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_79":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                # 0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "self_16":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                # 0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "self_17":
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                # 0x03: allowList,                                # allowList
                # 0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 2,                                        # pinUvAuthProtocol 
        }
    else:
        get_assertion_map = {
                0x01: rp,                                       # rp 
                0x02: clientDataHash,                           # clientDataHash
                0x03: allowList,                                # allowList
                0x05: options,                                  # options
                # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
                0x07: 2,                                        # pinUvAuthProtocol 
        }

    getAssertionCBOR = cbor2.dumps(get_assertion_map).hex().upper()
    full_payload = "02" + getAssertionCBOR
    length = len(full_payload) // 2
    if length <= 255:
        apdu = "80100000" + f"{length:02X}" + full_payload
    else:
        apdu = "80100000" + "00" + f"{length:04X}" + full_payload    
    return apdu

def getAssertionProtocol2(curpin, clientDataHash, rp, credId, mode):
    resetPowerCycle(True)
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    if mode == "self_1":
        pinToken, pubkey = getPINTokenWithPermissionProtocol2(curpin, PCMR_PERMISSION_BYTE, mode)
    elif mode == "self_2":
        pinToken, pubkey = getPINTokenWithPermissionProtocol2(curpin, GA_PERMISSION_BYTE, mode)
    else:
        pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)

    pinUvAuthParam = util.hmac_sha256(pinToken, clientDataHash)

    if mode == "fidoStd_9":
        clientDataHash = os.urandom(32)

    if mode == "fidoStd_28":
        pinUvAuthParam = os.urandom(32)
    
    apdu = createCBORmakeAssertion_Protocol2(clientDataHash, rp, pinUvAuthParam, credId, mode)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status


def createCBORmakeAssertion_Protocol1(clientDataHash, rp, pinUvAuthParam, credId, mode):
    allowList  = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    if mode == "fidoStd_19":
        allowList  = [{
            "id": bytes.fromhex(credId),
            "type": "public-key"
        },
        {
            "id": bytes.fromhex(credId),
            "type": "public-key"
        }]

    if mode == "fidoStd_61":
        allowList  = []

    if mode == "fidoStd_36":
        allowList  = [{"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_1")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_2")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_3")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_5")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_4")), "type": "public-key"},
        ]

    if mode == "fidoStd_37":
        allowList  = [{"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_1")), "type": "public-key"},
                {"id": bytes.fromhex(randomHexStr(maxCredentialIdLength)), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_3")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_5")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_4")), "type": "public-key"},
        ]

    if mode == "self_26":
        allowList  = [{"id": bytes.fromhex(credId), "type": "public-key"},
                {"id": bytes.fromhex(randomHexStr(128)), "type": "public-key"},
        ]

    if mode == "fidoStd_20":
        doInsertCredId = True
        CredentialCountInList = maxCredentialCountInList + 1
        allowList  = generate_allow_list_entries(CredentialCountInList, maxCredentialIdLength, credId, doInsertCredId)

    if mode == "fidoStd_22":
        doInsertCredId = False
        allowList  = generate_credential_list_with_custom_id(maxCredentialCountInList, maxCredentialIdLength, randomHexStr(maxCredentialIdLength+1), maxCredentialCountInList)

    if mode == "fidoStd_17":
        allowList  = [{
            "id": bytes.fromhex(credId+randomHexStr(4)),
            "type": "public-key"
        },
        {
            "id": bytes.fromhex(credId),
            "type": "public-key"
        }]

    if mode == "fidoTool_16":
        allowList  = [{
        "id": credId,
        "type": "public-key"
    }]

    if mode == "fidoTool_15":
        allowList  = [{
        "type": "public-key"
    }]
        
    if mode == "fidoTool_14":
        allowList  = [{
        "id": bytes.fromhex(credId),
        "type": 1234
    }]
        
    if mode == "fidoTool_13":
        allowList  = [{
        "id": bytes.fromhex(credId)
    }]
        
    if mode == "fidoTool_12":
        allowList  = [{
        bytes.fromhex(credId),
        "public-key"
    }]
        
    if mode == "fidoTool_11":
        allowList  = [{
        "id": bytes.fromhex(credId),
        "type": "private-key"
    }]

    if mode == "fidoTool_6":
        allowList  = {
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }
        
    if mode == "fidoTool_7":
        allowList  = [
        bytes.fromhex(credId),
        "public-key"
        ]

    options  = {"uv": False, "up": True}
    if mode == "self_7":
        options  = {"up": False}

    if mode == "sub_fidoStd_48":
        options  = {"uv": False, "up": False}

    if mode == "fidoStd_24":
        options  = {"up": True}

    if mode == "fidoStd_83":
        options  = {"pu": True}

    if mode == "fidoStd_93":
        options  = {"rk": 1}

    if mode == "fidoStd_68":
        options  = {"up": True, "rk": True}

    if mode == "fidoStd_69":
        options  = {"up": True, "rk": False}

    if mode == "fidoStd_71":
        options  = {"kr": True, "rk": True}

    if mode == "fidoTool_8":
        options  = {"kv": False, "up": True}

    if mode == "fidoTool_10":
        options  = {"uv": True, "up": True}

    if mode == "fidoTool_2":
        get_assertion_map = {
            # 0x01: rp,                                     # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoTool_4":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            # 0x02: clientDataHash,                         # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoTool_5":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash.hex(),                     # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoTool_17" or mode == "fidoStd_2" or mode == "fidoStd_26" or mode == "fidoStd_27" or mode == "fidoStd_55" or mode == "self_20" or mode == "self_21" or mode == "self_22" or mode == "self_29":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            # 0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_13" or mode == "self_14" or mode == "self_15":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            # 0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_80":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            # 0x03: allowList,                                # allowList
            # 0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_24" or mode == "fidoStd_95":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_29":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_72":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            # 0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_73":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 3,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_75":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam[3:],                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "self_24":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
            0x08: pinUvAuthParam,                           # pinUvAuthParam 

        }
    else:
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }

    getAssertionCBOR = cbor2.dumps(get_assertion_map).hex().upper()
    full_payload = "02" + getAssertionCBOR
    length = len(full_payload) // 2
    if length <= 255:
        apdu = "80100000" + f"{length:02X}" + full_payload
    else:
        apdu = "80100000" + "00" + f"{length:04X}" + full_payload    
    return apdu 

def createCBORmakeAssertion_Protocol2(clientDataHash, rp, pinUvAuthParam, credId, mode):
    allowList  = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    if mode == "fidoStd_19":
        allowList  = [{
            "id": bytes.fromhex(credId),
            "type": "public-key"
        },
        {
            "id": bytes.fromhex(credId),
            "type": "public-key"
        }]

    if mode == "fidoStd_61":
        allowList  = []

    if mode == "fidoStd_36":
        allowList  = [{"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_1")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_2")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_3")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_5")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_4")), "type": "public-key"},
        ]

    if mode == "self_26":
        allowList  = [{"id": bytes.fromhex(credId), "type": "public-key"},
                {"id": bytes.fromhex(randomHexStr(128)), "type": "public-key"},
        ]

    if mode == "fidoStd_37":
        allowList  = [{"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_1")), "type": "public-key"},
                {"id": bytes.fromhex(randomHexStr(maxCredentialIdLength)), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_3")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_5")), "type": "public-key"},
                {"id": bytes.fromhex(getCredentialID("CREDENTIAL_ID_4")), "type": "public-key"},
        ]

    if mode == "fidoStd_20":
        doInsertCredId = True
        CredentialCountInList = maxCredentialCountInList + 1
        allowList  = generate_allow_list_entries(CredentialCountInList, maxCredentialIdLength, credId, doInsertCredId)

    if mode == "fidoStd_22":
        doInsertCredId = False
        allowList  = generate_credential_list_with_custom_id(maxCredentialCountInList, maxCredentialIdLength, randomHexStr(maxCredentialIdLength+1), maxCredentialCountInList)


    if mode == "fidoStd_17":
        allowList  = [{
            "id": bytes.fromhex(credId+randomHexStr(4)),
            "type": "public-key"
        },
        {
            "id": bytes.fromhex(credId),
            "type": "public-key"
        }]

    if mode == "fidoTool_16":
        allowList  = [{
        "id": credId,
        "type": "public-key"
    }]

    if mode == "fidoTool_15":
        allowList  = [{
        "type": "public-key"
    }]

    if mode == "fidoTool_14":
        allowList  = [{
        "id": bytes.fromhex(credId),
        "type": 1234
    }]

    if mode == "fidoTool_13":
        allowList  = [{
        "id": bytes.fromhex(credId)
    }]

    if mode == "fidoTool_12":
        allowList  = [{
        bytes.fromhex(credId),
        "public-key"
    }]

    if mode == "fidoTool_11":
        allowList  = [{
        "id": bytes.fromhex(credId),
        "type": "private-key"
    }]

    if mode == "fidoTool_6":
        allowList  = {
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }

    if mode == "fidoTool_7":
        allowList  = [
        bytes.fromhex(credId),
        "public-key"
        ]



    options  = {"uv": False, "up": True}

    if mode == "self_7":
        options  = {"up": False}

    if mode == "sub_fidoStd_48":
        options  = {"uv": False, "up": False}

    if mode == "fidoStd_24":
        options  = {"up": True}

    if mode == "fidoStd_83":
        options  = {"pu": True}

    if mode == "fidoStd_93":
        options  = {"rk": 1}

    if mode == "fidoStd_68":
        options  = {"up": True, "rk": True}

    if mode == "fidoStd_69":
        options  = {"up": True, "rk": False}

    if mode == "fidoStd_71":
        options  = {"kr": True, "rk": True}


    if mode == "fidoTool_8":
        options  = {"kv": False, "up": True}

    if mode == "fidoTool_10":
        options  = {"uv": True, "up": True}


    if mode == "fidoTool_2":
        get_assertion_map = {
        # 0x01: rp,                                     # rp 
        0x02: clientDataHash,                           # clientDataHash
        0x03: allowList,                                # allowList
        0x05: options,                                  # options
        0x06: pinUvAuthParam,                           # pinUvAuthParam 
        0x07: 2,                                        # pinUvAuthProtocol 
    }
    elif mode == "fidoTool_4":
        get_assertion_map = {
        0x01: rp,                                       # rp 
        # 0x02: clientDataHash,                         # clientDataHash
        0x03: allowList,                                # allowList
        0x05: options,                                  # options
        0x06: pinUvAuthParam,                           # pinUvAuthParam 
        0x07: 2,                                        # pinUvAuthProtocol 
    }
    elif mode == "fidoTool_5":
        get_assertion_map = {
        0x01: rp,                                       # rp 
        0x02: clientDataHash.hex(),                     # clientDataHash
        0x03: allowList,                                # allowList
        0x05: options,                                  # options
        0x06: pinUvAuthParam,                           # pinUvAuthParam 
        0x07: 2,                                        # pinUvAuthProtocol 
    }
    elif mode == "fidoTool_17" or mode == "fidoStd_2" or mode == "fidoStd_26" or mode == "fidoStd_27" or mode == "fidoStd_55" or mode == "self_20" or mode == "self_21" or mode == "self_22" or mode == "self_29":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            # 0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_13" or mode == "self_14" or mode == "self_15":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            # 0x03: allowList,                              # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_80":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            # 0x03: allowList,                              # allowList
            # 0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_24" or mode == "fidoStd_95":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            # 0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_29":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_72":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            # 0x07: 1,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_73":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 3,                                        # pinUvAuthProtocol 
        }
    elif mode == "fidoStd_75":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam[3:],                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }
    elif mode == "self_24":
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
            0x08: pinUvAuthParam,                           # pinUvAuthParam 

        }
    else:
        get_assertion_map = {
            0x01: rp,                                       # rp 
            0x02: clientDataHash,                           # clientDataHash
            0x03: allowList,                                # allowList
            0x05: options,                                  # options
            0x06: pinUvAuthParam,                           # pinUvAuthParam 
            0x07: 2,                                        # pinUvAuthProtocol 
        }


    getAssertionCBOR = cbor2.dumps(get_assertion_map).hex().upper()

    full_payload = "02" + getAssertionCBOR
    length = len(full_payload) // 2
    if length <= 255:
        apdu = "80100000" + f"{length:02X}" + full_payload
    else:
        apdu = "80100000" + "00" + f"{length:04X}" + full_payload + "0000"
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
                "id": "Piyush".encode(),
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

def authenticatorGetNextAssertion(mode):
    response, status = util.APDUhex("80100000010800", "authenticatorGetNextAssertion")
    return response, status

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
                "id": "Piyush".encode(),
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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



def createCBORmakeCredWithoutPINSet(clientDataHash, rp, user, credParam, rk, mode):

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

    
    options = {"rk": rk}

    make_cred_map = {
        0x01: clientDataHash,                           # clientDataHash 
        0x02: PublicKeyCredentialRpEntity,              # rp
        0x03: PublicKeyCredentialUserEntity,            # user
        0x04: pubKeyCredParams,                         # pubKeyCredParams 
        0x07: options,                                  # options 
        # 0x09: 2,                                        # pinUvAuthProtocol 
        # # 0x0A: enterpriseAttestation,                  # enterpriseAttestation
        # # 0x0B: attestationFormatsPreference            # attestationFormatsPreference
    }

    makeCredCBOR = cbor2.dumps(make_cred_map).hex().upper()

    # CTAP2 MakeCredential command (0x01)
    full_data = "01" + makeCredCBOR
    total_len = len(full_data) // 2  # bytes

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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
       
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

def makeCredProtocol2(curpin, clientDataHash, rp, user, permission, mode):
    global oldPinUvAuthToken
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100","Select applet")

    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)
    pinAuthParam = util.hmac_sha256(pinToken, clientDataHash)

    global pinUvAuthTokenAssociatedRPID 
    pinUvAuthTokenAssociatedRPID = pinToken

    oldPinUvAuthToken = pinToken

    global oldPinUvAuthParam_Protocol2
    oldPinUvAuthParam_Protocol2 = pinAuthParam 

    makeCredAPDU = createCBORmakeCredProtocol2(clientDataHash, rp, user, pinAuthParam, mode)
    result,status = util.APDUhex(makeCredAPDU,"Command authenticatorMakeCredential(0x01)", checkflag=True)

    if status == "00":
        global globalCredentialID_Protocol2
        globalCredentialID_Protocol2 = getCredentialIDFromResponse(result)

    return result, status

def makeCredProtocol2WithRPsParam(curpin, clientDataHash, rpID, rpName, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
       
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

def makeCredWithoutPINSet(clientDataHash, rp, user, rk, mode):
    # util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    makeCredAPDU = createCBORmakeCredWithoutPINSet(clientDataHash, rp, user, pubkey, rk, mode)
    result,status = util.APDUhex(makeCredAPDU,"Command authenticatorMakeCredential(0x01)", checkflag=True)
    if status == "00":
        global globalCredentialID_Protocol2
        globalCredentialID_Protocol2 = getCredentialIDFromResponse(result)

        global globalCredentialID_Protocol1
        globalCredentialID_Protocol1 = getCredentialIDFromResponse(result)

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

def extract_authdata_from_getAssertion_response(hex_response) -> str:
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

    return authdata.hex()

def getRpIDHashFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    data = auth_Data["rpIdHash"]
    return data

def getSignCountFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    data = auth_Data["signCount"]
    return data

def getAAGUIDFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    data = auth_Data["aaguid"]
    return data

def getCredentialIDLengthFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    data = auth_Data["credentialIdLength"]
    return data

def getCredentialPublicKeyFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    data = auth_Data["credentialPublicKey"]
    return data

def getCredentialIDFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    credentialId = auth_Data["credentialId"]
    return credentialId

def getFlagsFromResponse(response):
    print("Response ---> ",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    flags = auth_Data["flags"]
    return flags



def decode_authenticator_flags(flag_value, requested_flag=None):
    """
    Decode WebAuthn authenticator flags byte.

    :param flag_value: int (e.g., 0x45 or 69)
    :param requested_flag: str (e.g., "UP", "UV", "AT", "ED")
    :return: True/False for requested flag (if provided)
    """

    # Ensure integer input
    if isinstance(flag_value, str):
        flag_value = int(flag_value, 16)

    # Define bit positions
    flags = {
        "UP": 0,   # User Present
        "UV": 2,   # User Verified
        "AT": 6,   # Attested credential data included
        "ED": 7    # Extension data included
    }

    print(f"\nFlag Byte: 0x{flag_value:02X} ({flag_value:08b})\n")

    results = {}

    for name, bit in flags.items():
        value = bool(flag_value & (1 << bit))
        results[name] = value
        print(f"{name} (Bit {bit}): {value}")

    # Print reserved bits
    print("\nReserved Bits:")
    for bit in [1, 3, 4, 5]:
        print(f"RFU Bit {bit}: {bool(flag_value & (1 << bit))}")

    # Return requested flag if asked
    if requested_flag:
        requested_flag = requested_flag.upper()
        if requested_flag in results:
            return results[requested_flag]
        else:
            raise ValueError("Requested flag must be one of: UP, UV, AT, ED")


def getPublicKeyFromResponse(response):
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # print("authdata (hex):", authdata.hex())
    auth_Data = getAsseration.parse_authdata(authdata)
    credentialPublicKey = auth_Data["credentialPublicKey"]
    return credentialPublicKey

def makeAssertionProtocol2(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100", "Re-select Applet")
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


def makeCredProtocol1(curpin, clientDataHash, rp, user, permission, mode):
    global oldPinUvAuthToken
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00A4040008A0000006472F000100","Select applet")

    pinToken = getPINtokenPubkeyProtocol1(curpin)
    pinAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:16]

    global pinUvAuthTokenAssociatedRPID
    pinUvAuthTokenAssociatedRPID = pinToken

    oldPinUvAuthToken = pinToken

    global oldPinUvAuthParam_Protocol1
    oldPinUvAuthParam_Protocol1 = pinAuthParam
  
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCredProtocol1(clientDataHash, rp, user, pinAuthParam, mode)
    result,status = util.APDUhex(makeCredAPDU,"Command authenticatorMakeCredential(0x01)", checkflag=True);

    if status == "00":
        global globalCredentialID_Protocol1
        globalCredentialID_Protocol1 = getCredentialIDFromResponse(result)

    return result , status
   
def createCBORmakeCredProtocol1(clientDataHash, rp, user, pinUvAuthParam, mode):

    n = len(user)
    global globalUserName
    globalUserName = randomUser(64)
    global globalDisplayName
    globalDisplayName = randomUser(64)

    PublicKeyCredentialRpEntity = {
           "id": rp,  # id: unique identifier
         "name": randomRPId(8),  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": randomUser(n),  # name 
       "displayName": randomUser(n),  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    if mode == "self_16" or mode == "self_17":
        PublicKeyCredentialUserEntity = {
            "id": user.encode(), # id: byte sequence
            "name": randomUser(n),  # name 
            "displayName": randomUser(n),  # displayName
            "icon": "https://example.com/redpath.png"  # icon (optional)
      }

    if mode == "fidoStd_39":
        PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": globalUserName,  # name 
       "displayName": globalDisplayName,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }

    if mode == "fidoStd_40":
        PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": "",  # name 
       "displayName": "",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
       
    pubKeyCredParams  = [{
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }]

    options  = {"rk": True} 
    if mode == "sub_fidoStd_13" or mode == "fidoStd_23" or mode == "fidoStd_26" or mode == "fidoStd_36" or mode == "fidoStd_37" or mode == "self_26":
        options  = {"rk": False}

    excludeList = [{"id": bytes.fromhex(randomHexStr(maxCredentialIdLength)), "type": "public-key" }] # dummy credentialId
    enterpriseAttestation = 0x01
    attestationFormatsPreference = ["packed"]

    if mode == "fidoStd_41":
        make_cred_map = {
        0x01: clientDataHash,                           # clientDataHash 
        0x02: PublicKeyCredentialRpEntity,              # rp
        0x03: PublicKeyCredentialUserEntity,            # user
        0x04: pubKeyCredParams,                         # pubKeyCredParams 
        # 0x05: excludeList,                              # excludeList 
        0x07: options,                                  # options 
        0x08: pinUvAuthParam,                           # pinUvAuthParam 
        0x09: 1,                                        # pinUvAuthProtocol 
        0x0A: enterpriseAttestation,                    # enterpriseAttestation
        0x0B: attestationFormatsPreference              # attestationFormatsPreference
    }
    elif mode == "fidoStd_44":
        make_cred_map = {
        0x01: clientDataHash,                           # clientDataHash 
        0x02: PublicKeyCredentialRpEntity,              # rp
        0x03: PublicKeyCredentialUserEntity,            # user
        0x04: pubKeyCredParams,                         # pubKeyCredParams 
        0x05: excludeList,                              # excludeList 
        0x07: options,                                  # options 
        0x08: pinUvAuthParam,                           # pinUvAuthParam 
        0x09: 1,                                        # pinUvAuthProtocol 
        # 0x0A: enterpriseAttestation,                    # enterpriseAttestation
        # 0x0B: attestationFormatsPreference              # attestationFormatsPreference
    }
    else:
        make_cred_map = {
            0x01: clientDataHash,                           # clientDataHash 
            0x02: PublicKeyCredentialRpEntity,              # rp
            0x03: PublicKeyCredentialUserEntity,            # user
            0x04: pubKeyCredParams,                         # pubKeyCredParams 
            # 0x05: excludeList,                              # excludeList 
            0x07: options,                                  # options 
            0x08: pinUvAuthParam,                           # pinUvAuthParam 
            0x09: 1,                                        # pinUvAuthProtocol 
            # 0x0A: enterpriseAttestation,                    # enterpriseAttestation
            # 0x0B: attestationFormatsPreference              # attestationFormatsPreference
        }

    

    makeCredCBOR = cbor2.dumps(make_cred_map).hex().upper()

    # CTAP2 MakeCredential command (0x01)
    full_data = "01" + makeCredCBOR
    total_len = len(full_data) // 2  # bytes

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
    

def createCBORmakeCredProtocol2(clientDataHash, rp, user, pinUvAuthParam, mode):
    n = len(user)
    global globalUserName
    globalUserName = randomUser(64)
    global globalDisplayName
    globalDisplayName = randomUser(64)

    PublicKeyCredentialRpEntity = {
        "id": rp,  # id: unique identifier
        "name": randomRPId(8)  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    PublicKeyCredentialUserEntity = {
        "id": user.encode(), # id: byte sequence
        "name": randomUser(n),  # name 
        "displayName": randomUser(n),  # displayName
        #       "icon": "https://example.com/redpath.png"  # icon (optional)
    }

    if mode == "self_16" or mode == "self_17":
        PublicKeyCredentialUserEntity = {
            "id": user.encode(), # id: byte sequence
            "name": randomUser(n),  # name 
            "displayName": randomUser(n),  # displayName
            "icon": "https://example.com/redpath.png"  # icon (optional)
      }

    if mode == "fidoStd_39":
        PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": globalUserName,  # name 
       "displayName": globalDisplayName,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    if mode == "fidoStd_40":
        PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": "",  # name 
       "displayName": "",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    pubKeyCredParams  = [{
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }]
    
    options  = {"rk": True}
    if mode == "sub_fidoStd_13" or mode == "fidoStd_23" or mode == "fidoStd_26" or mode == "fidoStd_36" or mode == "fidoStd_37" or mode == "self_26":
        options  = {"rk": False}

    excludeList = [{"id": bytes.fromhex(randomHexStr(maxCredentialIdLength)), "type": "public-key" }] # dummy credentialId
    enterpriseAttestation = 0x01
    attestationFormatsPreference = ["packed"]

    if mode == "fidoStd_41":
        make_cred_map = {
        0x01: clientDataHash,                           # clientDataHash 
        0x02: PublicKeyCredentialRpEntity,              # rp
        0x03: PublicKeyCredentialUserEntity,            # user
        0x04: pubKeyCredParams,                         # pubKeyCredParams 
        # 0x05: excludeList,                              # excludeList 
        0x07: options,                                  # options 
        0x08: pinUvAuthParam,                           # pinUvAuthParam 
        0x09: 2,                                        # pinUvAuthProtocol 
        0x0A: enterpriseAttestation,                    # enterpriseAttestation
        0x0B: attestationFormatsPreference              # attestationFormatsPreference
        }
    elif mode == "fidoStd_44":
        make_cred_map = {
        0x01: clientDataHash,                           # clientDataHash 
        0x02: PublicKeyCredentialRpEntity,              # rp
        0x03: PublicKeyCredentialUserEntity,            # user
        0x04: pubKeyCredParams,                         # pubKeyCredParams 
        0x05: excludeList,                              # excludeList 
        0x07: options,                                  # options 
        0x08: pinUvAuthParam,                           # pinUvAuthParam 
        0x09: 2,                                        # pinUvAuthProtocol 
        # 0x0A: enterpriseAttestation,                    # enterpriseAttestation
        # 0x0B: attestationFormatsPreference              # attestationFormatsPreference
    }
    else:
        make_cred_map = {
            0x01: clientDataHash,                           # clientDataHash 
            0x02: PublicKeyCredentialRpEntity,              # rp
            0x03: PublicKeyCredentialUserEntity,            # user
            0x04: pubKeyCredParams,                         # pubKeyCredParams 
            # 0x05: excludeList,                            # excludeList 
            0x07: options,                                  # options 
            0x08: pinUvAuthParam,                           # pinUvAuthParam 
            0x09: 2,                                        # pinUvAuthProtocol 
            # 0x0A: enterpriseAttestation,                  # enterpriseAttestation
            # 0x0B: attestationFormatsPreference            # attestationFormatsPreference
        }


    makeCredCBOR = cbor2.dumps(make_cred_map).hex().upper()

    # CTAP2 MakeCredential command (0x01)
    full_data = "01" + makeCredCBOR
    total_len = len(full_data) // 2  # bytes

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

def enableEnterpriseAttestationCBORProtocol2(pinToken, subCommand):
    
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

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper() + "00"
    return apdu

def enableEnterpriseAttestationCBORProtocol1(pinToken, subCommand):
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, first 16 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # enableEnterpriseAttestation
        0x03: 1,               # pinUvAuthProtocol = 1
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper() + "00"
    return apdu

def authenticatorConfigEnableEnterpriseAttestationProtocol1(pin, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
    subCommand = 0x01
    apdu=enableEnterpriseAttestationCBORProtocol1(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
    return response, status

def authenticatorConfigEnableEnterpriseAttestationProtocol2(pin, mode):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
    subCommand = 0x01
    apdu=enableEnterpriseAttestationCBORProtocol2(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
    return response, status


def getPINtokenPubkeyProtocol1(pin):
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100", "Select applet")

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
    rp = "enterprisetest.certinfra.fidoalliance.org"
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    rpID             = cbor2.dumps(rp).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex

    if mode == "self_2":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ rpID



    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR + "00"
    return APDUcommand


def createGetPINtokenWithPermisionProtocol1(pinHashenc, key_agreement, permission, mode):
    rp = "enterprisetest.certinfra.fidoalliance.org"
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    rpID             = cbor2.dumps(rp).hex().upper() 

    # # Remove first byte if length > 2
    # if len(permission_hex) > 2:
    #     permission_hex = permission_hex[2:]
    
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "01" # Fido2 protocol 1
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex

    if mode == "self_2":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ "01" # Fido2 protocol 1
        dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ rpID


    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR + "00"
    return APDUcommand


def getPINTokenWithPermissionProtocol2(curpin, permission, mode):
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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
    util.APDUhex("00A4040008A0000006472F000100","Select applet")
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

def getCredsMetadata_APDU_Protocol2(subCommand, pinUvAuthParam, mode):

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

def getCredsMetadataProtocol2(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")

    pinToken, pubkey = getPINTokenWithPermissionProtocol2(pin, permission, mode)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    subCommand = 0x01  # getCredsMetadata
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


def getCredsMetadataProtocol1(pin, permission, mode):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")

    pinToken, pubKey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    subCommand = 0x01  # getCredsMetadata
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

def retrieveStatusName(status: str):
    code = ""
    if status == "00":
        code = "CTAP1_ERR_SUCCESS/CTAP2_OK"
    elif status == "01":
        code = "CTAP1_ERR_INVALID_COMMAND"
    elif status == "02":
        code = "CTAP1_ERR_INVALID_PARAMETER"
    elif status == "03":
        code = "CTAP1_ERR_INVALID_LENGTH"
    elif status == "04":
        code = "CTAP1_ERR_INVALID_SEQ"
    elif status == "05":
        code = "CTAP1_ERR_TIMEOUT"
    elif status == "06":
        code = "CTAP1_ERR_CHANNEL_BUSY"
    elif status == "0A":
        code = "CTAP1_ERR_LOCK_REQUIRED"
    elif status == "0B":
        code = "CTAP1_ERR_INVALID_CHANNEL"
    elif status == "11":
        code = "CTAP2_ERR_CBOR_UNEXPECTED_TYPE"
    elif status == "12":
        code = "CTAP2_ERR_INVALID_CBOR"
    elif status == "14":
        code = "CTAP2_ERR_MISSING_PARAMETER"
    elif status == "15":
        code = "CTAP2_ERR_LIMIT_EXCEEDED"
    elif status == "17":
        code = "CTAP2_ERR_FP_DATABASE_FULL"
    elif status == "18":
        code = "CTAP2_ERR_LARGE_BLOB_STORAGE_FULL"
    elif status == "19":
        code = "CTAP2_ERR_CREDENTIAL_EXCLUDED"
    elif status == "21":
        code = "CTAP2_ERR_PROCESSING"
    elif status == "22":
        code = "CTAP2_ERR_INVALID_CREDENTIAL"
    elif status == "23":
        code = "CTAP2_ERR_USER_ACTION_PENDING"
    elif status == "24":
        code = "CTAP2_ERR_OPERATION_PENDING"
    elif status == "25":
        code = "CTAP2_ERR_NO_OPERATIONS"
    elif status == "26":
        code = "CTAP2_ERR_UNSUPPORTED_ALGORITHM"
    elif status == "27":
        code = "CTAP2_ERR_OPERATION_DENIED"
    elif status == "28":
        code = "CTAP2_ERR_KEY_STORE_FULL"
    elif status == "2B":
        code = "CTAP2_ERR_UNSUPPORTED_OPTION"
    elif status == "2C":
        code = "CTAP2_ERR_INVALID_OPTION"
    elif status == "2D":
        code = "CTAP2_ERR_KEEPALIVE_CANCEL"
    elif status == "2E":
        code = "CTAP2_ERR_NO_CREDENTIALS"
    elif status == "2F":
        code = "CTAP2_ERR_USER_ACTION_TIMEOUT"
    elif status == "30":
        code = "CTAP2_ERR_NOT_ALLOWED"
    elif status == "31":
        code = "CTAP2_ERR_PIN_INVALID"
    elif status == "32":
        code = "CTAP2_ERR_PIN_BLOCKED"
    elif status == "33":
        code = "CTAP2_ERR_PIN_AUTH_INVALID"
    elif status == "34":
        code = "CTAP2_ERR_PIN_AUTH_BLOCKED"
    elif status == "35":
        code = "CTAP2_ERR_PIN_NOT_SET"
    elif status == "36":
        code = "CTAP2_ERR_PUAT_REQUIRED"
    elif status == "37":
        code = "CTAP2_ERR_PIN_POLICY_VIOLATION"
    elif status == "38":
        code = "RESERVED FOR FUTURE USE"
    elif status == "39":
        code = "CTAP2_ERR_REQUEST_TOO_LARGE"
    elif status == "3A":
        code = "CTAP2_ERR_ACTION_TIMEOUT"
    elif status == "3B":
        code = "CTAP2_ERR_UP_REQUIRED"
    elif status == "3C":
        code = "CTAP2_ERR_UV_BLOCKED"
    elif status == "3D":
        code = "CTAP2_ERR_INTEGRITY_FAILURE"
    elif status == "3E":
        code = "CTAP2_ERR_INVALID_SUBCOMMAND"
    elif status == "3F":
        code = "CTAP2_ERR_UV_INVALID"
    elif status == "40":
        code = "CTAP2_ERR_UNAUTHORIZED_PERMISSION"
    elif status == "7F":
        code = "CTAP1_ERR_OTHER"
    elif status == "DF":
        code = "CTAP2_ERR_SPEC_LAST"
    elif status == "E0":
        code = "CTAP2_ERR_EXTENSION_FIRST"
    elif status == "EF":
        code = "CTAP2_ERR_EXTENSION_LAST"
    elif status == "F0":
        code = "CTAP2_ERR_VENDOR_FIRST"
    elif status == "FF":
        code = "CTAP2_ERR_VENDOR_LAST"
    else:
        code = ""
    STATUS_CODE = code + "("+status+")"
    return STATUS_CODE

def toggleAlwaysUvProtocol1(pin, mode):
    subCommand = 0x02
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes

    permission = 0x20
    pinToken, pubKey = getPINTokenWithPermissionProtocol1(pin, permission, mode)
    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})") 
    cbor_map = {
                0x01: subCommand,         # toggleAlwaysUv
                0x03: 0x01,               # pinUvAuthProtocol = 1
                0x04: pinUvAuthParam      #pinUvAuthParam
                }
 
    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1
    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", checkflag=True)
    return response, status
 


def toggleAlwaysUvProtocol2(pin, mode):
    subCommand = 0x02
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes

    permission = 0x20
    pinToken, pubKey = getPINTokenWithPermissionProtocol2(pin, permission, mode)
    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:32]
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})") 
    cbor_map = {
                0x01: subCommand,         # toggleAlwaysUv
                0x03: 0x02,               # pinUvAuthProtocol = 2
                0x04: pinUvAuthParam      #pinUvAuthParam
                }
 
    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1
    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", checkflag=True)
    return response, status

def randomHexStr(byte_length: int) -> str:
    if byte_length <= 0:
        raise ValueError("Length must be greater than 0")

    return os.urandom(byte_length).hex().upper()


def parse_get_assertion_field(response_hex: str, field: str):
    """
    Parse CTAP2 getAssertion response.
    - Bytes fields are returned as HEX string (uppercase).
    - Integer fields are returned as int.
    """

    if len(response_hex) < 2:
        raise ValueError("Invalid response")

    # 1️⃣ Check CTAP status
    status = int(response_hex[:2], 16)
    if status != 0x00:
        raise ValueError(f"CTAP error: 0x{status:02X}")

    # 2️⃣ Decode CBOR body
    decoded = cbor2.loads(bytes.fromhex(response_hex[2:]))

    auth_data = decoded.get(2)  # key 0x02 = authData

    rpIdHash = flags = signCount = None

    if auth_data:
        rpIdHash = auth_data[0:32]
        flags = auth_data[32]
        signCount_bytes = auth_data[33:37]
        signCount = int.from_bytes(signCount_bytes, "big")

    # ------------------------
    # Return requested field
    # ------------------------

    if field == "status":
        return status

    elif field == "rpIdHash":
        return rpIdHash.hex().upper() if rpIdHash else None

    elif field == "flags":
        return flags

    elif field == "signCount":
        return signCount

    elif field == "authData":
        return auth_data.hex().upper() if auth_data else None

    elif field == "signature":
        sig = decoded.get(3)
        return sig.hex().upper() if sig else None

    elif field == "credentialId":
        cred = decoded.get(1)
        if cred and "id" in cred:
            return cred["id"].hex().upper()
        return None

    elif field == "userId":
        user = decoded.get(4)
        if user and "id" in user:
            return user["id"].hex().upper()
        return None

    elif field == "userName":
        user = decoded.get(4)
        if user and "name" in user:
            return user["name"]
        return None

    elif field == "userDisplayName":
        user = decoded.get(4)
        if user and "displayName" in user:
            return user["displayName"]
        return None

    elif field == "numberOfCredentials":
        return decoded.get(5)

    else:
        raise ValueError("Unsupported field requested")


def parse_makecred_field(response_hex: str, field: str):

    if len(response_hex) < 2:
        raise ValueError("Invalid response")

    status = int(response_hex[:2], 16)
    if status != 0x00:
        raise ValueError(f"CTAP error: 0x{status:02X}")

    decoded = cbor2.loads(bytes.fromhex(response_hex[2:]))

    fmt = decoded.get(1)
    auth_data = decoded.get(2)
    att_stmt = decoded.get(3)

    if not auth_data:
        return None

    index = 0

    rpIdHash = auth_data[index:index+32]
    index += 32

    flags = auth_data[index]
    index += 1

    signCount = int.from_bytes(auth_data[index:index+4], "big")
    index += 4

    AT_FLAG = 0x40
    ED_FLAG = 0x80

    aaguid = credentialId = credentialPublicKey = extensions = None

    if flags & AT_FLAG:
        aaguid = auth_data[index:index+16]
        index += 16

        cred_len = int.from_bytes(auth_data[index:index+2], "big")
        index += 2

        credentialId = auth_data[index:index+cred_len]
        index += cred_len

        credentialPublicKey, consumed = _decode_cbor_from_bytes(auth_data[index:])
        index += consumed

    if flags & ED_FLAG:
        extensions, consumed = _decode_cbor_from_bytes(auth_data[index:])

    # Return requested field

    if field == "status":
        return status
    elif field == "fmt":
        return fmt
    elif field == "attStmt":
        return att_stmt
    elif field == "rpIdHash":
        return rpIdHash.hex().upper()
    elif field == "flags":
        return flags
    elif field == "signCount":
        return signCount
    elif field == "aaguid":
        return aaguid.hex().upper() if aaguid else None
    elif field == "credentialId":
        return credentialId.hex().upper() if credentialId else None
    elif field == "credentialPublicKey":
        return credentialPublicKey
    elif field == "extensions":
        return extensions
    else:
        return None



def _decode_cbor_from_bytes(data: bytes):
    bio = io.BytesIO(data)
    obj = cbor2.load(bio)
    consumed = bio.tell()
    return obj, consumed


def extract_attStmt(makecred_response_hex: str):
    """
    Extract attStmt from CTAP2 authenticatorMakeCredential response.

    :param makecred_response_hex: Full CTAP2 response as hex string
    :return: attStmt dict (original CBOR type) or None
    """

    if not makecred_response_hex or len(makecred_response_hex) < 2:
        raise ValueError("Invalid response")

    # First byte = status
    status = int(makecred_response_hex[:2], 16)
    if status != 0x00:
        raise ValueError(f"CTAP error: 0x{status:02X}")

    # Decode CBOR part
    cbor_bytes = bytes.fromhex(makecred_response_hex[2:])
    decoded = cbor2.loads(cbor_bytes)

    # CTAP2 makeCredential response structure:
    # 1 -> fmt
    # 2 -> authData
    # 3 -> attStmt

    att_stmt = decoded.get(3)

    return att_stmt


def validate_attestation_statement(makecred_response_hex: str):

    if len(makecred_response_hex) < 2:
        util.printcolor(util.RED, "Invalid response length")
        return False

    status = int(makecred_response_hex[:2], 16)

    if status != 0x00:
        util.printcolor(util.RED, f"CTAP returned error: 0x{status:02X}")
        return False
    else:
        util.printcolor(util.GREEN, "CTAP status OK")

    decoded = cbor2.loads(bytes.fromhex(makecred_response_hex[2:]))

    fmt = decoded.get(1)
    att_stmt = decoded.get(3)

    if fmt is None or att_stmt is None:
        util.printcolor(util.RED, "Missing fmt or attStmt")
        return False

    util.printcolor(util.GREEN, f"Attestation format: {fmt}")

    if not isinstance(att_stmt, dict):
        util.printcolor(util.RED, "attStmt is not a CBOR map")
        return False

    # =========================
    # none
    # =========================
    if fmt == "none":
        if att_stmt == {}:
            util.printcolor(util.GREEN, "attStmt correctly empty for 'none'")
            return True
        else:
            util.printcolor(util.RED, "attStmt must be empty for 'none'")
            return False

    # =========================
    # packed
    # =========================
    elif fmt == "packed":

        if "alg" not in att_stmt:
            util.printcolor(util.RED, "packed attStmt missing 'alg'")
            return False

        if "sig" not in att_stmt:
            util.printcolor(util.RED, "packed attStmt missing 'sig'")
            return False

        if not isinstance(att_stmt["alg"], int):
            util.printcolor(util.RED, "'alg' must be integer")
            return False

        if not isinstance(att_stmt["sig"], bytes):
            util.printcolor(util.RED, "'sig' must be bytes")
            return False

        util.printcolor(util.GREEN, "Required fields 'alg' and 'sig' are valid")

        if "x5c" in att_stmt:
            if not isinstance(att_stmt["x5c"], list):
                util.printcolor(util.RED, "'x5c' must be a list")
                return False

            for cert in att_stmt["x5c"]:
                if not isinstance(cert, bytes):
                    util.printcolor(util.RED, "Each x5c entry must be bytes")
                    return False

            util.printcolor(util.GREEN, "x5c certificate chain structure valid")

        if "ecdaaKeyId" in att_stmt:
            if not isinstance(att_stmt["ecdaaKeyId"], bytes):
                util.printcolor(util.RED, "ecdaaKeyId must be bytes")
                return False

            util.printcolor(util.GREEN, "ecdaaKeyId structure valid")

        return True

    # =========================
    # fido-u2f
    # =========================
    elif fmt == "fido-u2f":

        if "sig" not in att_stmt or "x5c" not in att_stmt:
            util.printcolor(util.RED, "fido-u2f requires 'sig' and 'x5c'")
            return False

        if not isinstance(att_stmt["sig"], bytes):
            util.printcolor(util.RED, "'sig' must be bytes")
            return False

        if not isinstance(att_stmt["x5c"], list) or len(att_stmt["x5c"]) != 1:
            util.printcolor(util.RED, "'x5c' must contain exactly one certificate")
            return False

        if not isinstance(att_stmt["x5c"][0], bytes):
            util.printcolor(util.RED, "Certificate must be bytes")
            return False

        util.printcolor(util.GREEN, "fido-u2f attStmt structure valid")
        return True

    # =========================
    # android-key
    # =========================
    elif fmt == "android-key":

        required = ["alg", "sig", "x5c"]
        for key in required:
            if key not in att_stmt:
                util.printcolor(util.RED, f"android-key missing '{key}'")
                return False

        util.printcolor(util.GREEN, "android-key attStmt structure valid")
        return True

    # =========================
    # android-safetynet
    # =========================
    elif fmt == "android-safetynet":

        if "ver" not in att_stmt or "response" not in att_stmt:
            util.printcolor(util.RED, "android-safetynet missing 'ver' or 'response'")
            return False

        if not isinstance(att_stmt["ver"], str):
            util.printcolor(util.RED, "'ver' must be string")
            return False

        if not isinstance(att_stmt["response"], bytes):
            util.printcolor(util.RED, "'response' must be bytes")
            return False

        util.printcolor(util.GREEN, "android-safetynet attStmt structure valid")
        return True

    # =========================
    # tpm
    # =========================
    elif fmt == "tpm":

        required = ["alg", "sig", "ver", "certInfo", "pubArea"]
        for key in required:
            if key not in att_stmt:
                util.printcolor(util.RED, f"tpm missing '{key}'")
                return False

        util.printcolor(util.GREEN, "tpm attStmt structure valid")
        return True

    else:
        util.printcolor(util.RED, f"Unsupported attestation format: {fmt}")
        return False


def validate_epAtt(makecred_response_hex: str, enterprise_policy_enabled: bool):
    """
    Validate epAtt field in CTAP2 makeCredential response.

    :param makecred_response_hex: Full CTAP2 response (hex string)
    :param enterprise_policy_enabled: Expected enterprise attestation policy (True/False)
    :return: True/False
    """

    if len(makecred_response_hex) < 2:
        util.printcolor(util.RED, "Invalid response length")
        return False

    status = int(makecred_response_hex[:2], 16)

    if status != 0x00:
        util.printcolor(util.RED, f"CTAP returned error: 0x{status:02X}")
        return False

    decoded = cbor2.loads(bytes.fromhex(makecred_response_hex[2:]))

    # CTAP2 makeCredential response structure:
    # 1 -> fmt
    # 2 -> authData
    # 3 -> attStmt
    # 4 -> epAtt (optional)

    if 4 not in decoded:
        util.printcolor(util.GREEN, "epAtt field not present (optional field)")
        return True  # absence is allowed

    epAtt = decoded.get(4)

    util.printcolor(util.GREEN, "epAtt field is present")

    # Must be boolean
    if not isinstance(epAtt, bool):
        util.printcolor(util.RED, "epAtt must be boolean")
        return False

    util.printcolor(util.GREEN, f"epAtt value is boolean: {epAtt}")

    # Compare with enterprise policy configuration
    if epAtt == enterprise_policy_enabled:
        util.printcolor(util.GREEN, "epAtt value matches enterprise attestation policy")
        return True
    else:
        util.printcolor(util.RED, "epAtt value does NOT match enterprise attestation policy")
        return False



def generate_exclude_list_entries(maxCredentialCountInList: int, maxCredentialIdLength: int):
    """
    Generate list of credential descriptors.

    :param count: Number of entries to generate
    :param maxCredentialIdLength: Length of credential ID in bytes
    :return: List of dictionaries
    """

    if maxCredentialCountInList <= 0:
        return []

    result = []

    for _ in range(maxCredentialCountInList):
        random_bytes = secrets.token_bytes(maxCredentialIdLength)

        entry = {
            "id": random_bytes,
            "type": "public-key"
        }

        result.append(entry)

    return result

def generate_allow_list_entries(maxCredentialCountInList: int, maxCredentialIdLength: int, credId: str, doInsertCredId: bool):
    """
    Generate list of credential descriptors.

    :param count: Number of entries to generate
    :param maxCredentialIdLength: Length of credential ID in bytes
    :return: List of dictionaries
    """

    if maxCredentialCountInList <= 0:
        return []

    result = []

    for _ in range(maxCredentialCountInList):
        random_bytes = secrets.token_bytes(maxCredentialIdLength)
        if doInsertCredId == True:
            entry = {
                "id": bytes.fromhex(credId),
                "type": "public-key"
            }
        else:
          entry = {
                "id": random_bytes,
                "type": "public-key"
            }  

        result.append(entry)

    return result


def generate_credential_list_with_custom_id(
        count: int,
        maxCredentialIdLength: int,
        customCredentialId: str,
        position: int
):
    """
    Generate list of credential descriptors and insert user-provided credentialID
    at a specific position.

    :param count: Total number of entries
    :param maxCredentialIdLength: Length for random credential IDs (bytes)
    :param customCredentialId: Credential ID (bytes) to insert
    :param position: Index where customCredentialId should be placed
    :return: List of credential descriptor dictionaries
    """

    if count <= 0:
        return []

    if position-1 < 0 or position-1 >= count:
        raise ValueError("Position must be within range of count")

    result = []

    for i in range(count):
        if i == position-1:
            entry = {
                "id": bytes.fromhex(customCredentialId),
                "type": "public-key"
            }
        else:
            random_bytes = secrets.token_bytes(maxCredentialIdLength)
            entry = {
                "id": random_bytes,
                "type": "public-key"
            }

        result.append(entry)

    return result

# import cbor2

# def get_flag_from_getAssertion_response(response_hex: str, requested_flag: str) -> bool:
#     """
#     Extracts requested flag value from full authenticatorGetAssertion response (hex string).

#     :param response_hex: Full CBOR response in hex string format
#     :param requested_flag: Flag name (e.g., "up", "UV", "at")
#     :return: True/False
#     """

#     # Convert hex string to bytes
#     response_bytes = bytes.fromhex(response_hex)

#     # Decode CBOR response
#     decoded_response = cbor2.loads(response_bytes)

#     # authData is key 0x02
#     if 0x02 not in decoded_response:
#         raise ValueError("authData (0x02) not found in response")

#     auth_data = decoded_response[0x02]

#     if len(auth_data) < 37:
#         raise ValueError("Invalid authenticatorData length")

#     # Flags byte is at index 32
#     flags_byte = auth_data[32]

#     # Flag bit mapping
#     flag_bits = {
#         "UP": 0,
#         "UV": 2,
#         "BE": 3,
#         "BS": 4,
#         "AT": 5,
#         "ED": 6
#     }

#     requested_flag = requested_flag.upper()

#     if requested_flag not in flag_bits:
#         raise ValueError(f"Invalid flag requested: {requested_flag}")

#     # Extract all flags (for debugging)
#     print("All Flags:")
#     for flag, bit in flag_bits.items():
#         value = bool((flags_byte >> bit) & 1)
#         print(f"{flag}: {value}")

#     return bool((flags_byte >> flag_bits[requested_flag]) & 1)


def get_flag_from_getAssertion_response(response_hex: str, requested_flag: str) -> bool:
    """
    Extract requested flag value from full raw CTAP2 authenticatorGetAssertion response.
    Handles status byte automatically.
    """

    response_bytes = bytes.fromhex(response_hex)

    if len(response_bytes) < 2:
        raise ValueError("Invalid response")

    # First byte = status code
    status_code = response_bytes[0]

    if status_code != 0x00:
        raise ValueError(f"Authenticator returned error status: {hex(status_code)}")

    # Remaining bytes = CBOR map
    cbor_payload = response_bytes[1:]

    decoded = cbor2.loads(cbor_payload)

    if not isinstance(decoded, dict):
        raise ValueError("Decoded response is not a CBOR map")

    if 0x02 not in decoded:
        raise ValueError("authData (0x02) not found")

    auth_data = decoded[0x02]

    flags_byte = auth_data[32]

    flag_bits = {
        "UP": 0,
        "UV": 2,
        "AT": 6,
        "ED": 7
    }

    requested_flag = requested_flag.upper()

    if requested_flag not in flag_bits:
        raise ValueError("Valid flags: UP, UV, AT, ED")

    # Debug print
    print("Flags Byte:", hex(flags_byte))
    print("UP :", bool((flags_byte >> 0) & 1))
    print("UV :", bool((flags_byte >> 2) & 1))
    print("AT :", bool((flags_byte >> 6) & 1))
    print("ED :", bool((flags_byte >> 7) & 1))

    return bool((flags_byte >> flag_bits[requested_flag]) & 1)


def hex_to_ascii(hex_string: str) -> str:
    return bytes.fromhex(hex_string).decode("ascii")


from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def verify_assertion_signature(
        authData_hex: str,
        clientDataHash: bytes,
        signature: bytes,
        public_key):

    authData_bytes = bytes.fromhex(authData_hex)

    signed_data = authData_bytes + clientDataHash

    try:
        public_key.verify(
            signature,
            signed_data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
    

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def load_public_key_from_cose_hex(cose_hex: str):
    """
    Converts COSE key (hex string) to cryptography ES256 public key
    """

    cose_bytes = bytes.fromhex(cose_hex)

    cose_key = cbor2.loads(cose_bytes)

    # Verify it's ES256
    if cose_key.get(3) != -7:
        raise ValueError("Unsupported algorithm (expected ES256 / -7)")

    x = cose_key[-2]
    y = cose_key[-3]

    public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"),
        int.from_bytes(y, "big"),
        ec.SECP256R1()
    )

    return public_numbers.public_key(default_backend())

import cbor2

def validate_enterprise_attestation_in_assertion(response_hex):
    try:
        if len(response_hex) > 6:
            response_hex = response_hex[2:]
        else:
            util.printcolor(util.RED,f"Invalid Response")
            exit(0)

        # Convert HEX → bytes
        response_bytes = bytes.fromhex(response_hex)

        # Decode CBOR
        decoded = cbor2.loads(response_bytes)

        # Valid assertion keys (CTAP2 spec)
        valid_assertion_keys = {1, 2, 3, 4, 5, 6, 7}

        # Keys that must NEVER appear in assertion
        forbidden_keys = ["attStmt", "fmt", "x5c", "attestationObject"]

        # 1️⃣ Check numeric keys (unexpected structure)
        for key in decoded.keys():
            if key not in valid_assertion_keys:
                util.printcolor(util.RED,f"❌ EP VALIDATION FAILED: Unexpected key '{key}' found in assertion response.")
                exit(0)
            

        # 2️⃣ Check forbidden string keys
        for key in forbidden_keys:
            if key in decoded:
                 util.printcolor(util.RED,f"❌ EP VALIDATION FAILED: Enterprise attestation field '{key}' present in assertion.")
                 exit(0)

        # 3️⃣ Extra check: ensure no attestationObject inside nested maps
        def deep_search(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in forbidden_keys:
                        return True
                    if deep_search(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if deep_search(item):
                        return True
            return False

        if deep_search(decoded):
            util.printcolor(util.RED,f"❌ EP VALIDATION FAILED: Enterprise attestation data detected inside nested structure.")
            exit(0)

        util.printcolor(util.GREEN,f"✅ EP VALIDATION PASSED: No enterprise attestation data exposed during assertion.")

    except Exception as e:
         util.printcolor(util.RED,f"⚠️ EP VALIDATION ERROR: Unable to decode response - {str(e)}")
         exit(0)