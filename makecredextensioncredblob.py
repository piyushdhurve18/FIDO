import util
import cbor2
import binascii
import os
import struct
import getpintokenpermissionp2
import Setpinp1
import getpintokenCTAP2_2
from textwrap import wrap
import enableEnterpriseAttestationctap2
import toggleAlwaysUv
import hmac
import hashlib
from binascii import unhexlify
import pprint
import DocumentCreation

permissionRpId = ""
rp="localhost"
username="bobsmith"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - CRED BLOB)"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0


def getPinUvAuthTokenP2_2(mode,pinset,protocol,pin):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL

    if protocol == 1:
        PROTOCOL = 1
    else:
        PROTOCOL = 2
    util.ResetCardPower()
    util.ConnectJavaCard()       
            
    descriptions = {
            "credblob.T":"""Test started: P-1 :
Precondition: 
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.

P-1 Check that GetInfo contains maxCredBlobLength(0x0F) field, and it is at least 32. """,

"newtestcase":"""Test started: P-1 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:(Verify that the authenticator stores the credBlob value when creating a discoverable credential)
Steps1:
Send a TWO valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = true "extensions" with "credBlob" set to a valid byte string of length less than or equal to maxCredBlobLength.Verify the response
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:(Verify that the authenticator returns the stored credBlob during assertion)
Steps2:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId.Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step 3:
 Send a valid authenticatorGetNextAssertion (0x08).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.


""",



 "credblob.Discoverable":"""Test started: P-2 :
Precondition: 
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
P-2 Create a new discoverable credential, with "extensions" containg valid "credBlob" extension set to a random buffer, 
and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Send GetAssertion request with credBlob extension set to true, 
and check that result contains credBlob extension with expected bytes.""",


"credblobnotsetinmakecred":"""Test started: P-3 :
Precondition: 
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
P-3 Create a new discoverable credential and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. 
Send GetAssertion request with credBlob extension set to true, and check that result contains credBlob extension with empty BYTE STRING.""",

"verfycredblob":"""Test started: P-4 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.

Test Description:(Verify that the authenticator advertises support for the credBlob extension)
Steps:
Send a valid authenticatorGetInfo (0x04) request and verify the response.
Expected Result:
1.The response includes "credBlob" in the extensions list.
2.The response includes maxCredBlobLength (0x0F).
3.The value of maxCredBlobLength is at least 32.""",

"credblobwithu2f":"""Test started: P-5 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:(Verify that the authenticator stores the credBlob value when creating a discoverable credential)
Steps:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = true "extensions" with "credBlob" set to a valid byte string of length less than or equal to maxCredBlobLength.Verify the response
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:(Verify that the authenticator returns the stored credBlob during assertion)
Steps:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId.Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",

"withoutcredblobmakecred":"""Test started: P-6 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.The authenticator is configured with a PIN
5.A discoverable credential exists without a stored credBlob.

Test Description:(Verify that an empty byte string is returned when no credBlob is associated with the credential)
Steps:
Send a valid authenticatorGetAssertion (0x02) using previos credentialid request.Include "extensions" with "credBlob" = true.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.""",

"credbloblengthexceed":"""Test started: P-7 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo.maxCredBlobLength = 32.
5.The authenticator is configured with a PIN.

Test Description:(Verify that the authenticator does not store a credBlob value larger than the supported size.)
Step1:
Send a valid authenticatorMakeCredential (0x01) request.Include:options.rk = true extensions.credBlob credBlob Size Exceeds maxCredBlobLength.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an extensions field.
3.The extensions field includes:"credBlob" =false

Step 2:(Verify Oversized credBlob Is Not Returned)
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credential ID, with "extensions" set to "credBlob" = true. Verify the response.
Expected Results:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains authData.extensions.
3.The authData.extensions field includes:"credBlob" =false.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.""",
"credbloblengthzero":"""Test started: P-8 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.The authenticator is configured with a PIN.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with options.rk = true and include the extensions.credBlob field with a null value. Verify the response from the authenticator.
Expected Result:
The authenticator returns CTAP1_ERR_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId Include "extensions" with "credBlob" = true.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",


"credblobandcredprotect":"""Test started: P-9 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request that includes options.rk = true and an extensions object containing credBlob set to a valid byte string with a length less than maxCredBlobLength, and credProtect set to 1. Verify the authenticator’s response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field .
3.The "extensions" field includes "credBlob" = true and credProtect=1.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId with pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step3:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId without  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.

Step4:
Send a valid authenticatorGetAssertion (0x02)  request without  credentialId and without  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step5:
Send a valid authenticatorGetAssertion (0x02)  request without  credentialId and with  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.


Step 6:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 7:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",


"credblobandcredprotect02":"""Test started: P-10 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request that includes options.rk = true and an extensions object containing credBlob set to a valid byte string with a length less than maxCredBlobLength, and credProtect set to 1. Verify the authenticator’s response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field .
3.The "extensions" field includes "credBlob" = true and credProtect=2.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId with pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step3:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId without  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.

Step4:
Send a valid authenticatorGetAssertion (0x02)  request without  credentialId and without  pinauthparam .Include "extensions" with "credBlob" = true.
The authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step5:
Send a valid authenticatorGetAssertion (0x02)  request without  credentialId and with  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.

Step 6:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 7:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",


"credblobandcredprotect03":"""Test started: P-11 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request that includes options.rk = true and an extensions object containing credBlob set to a valid byte string with a length less than maxCredBlobLength, and credProtect set to 1. Verify the authenticator’s response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field .
3.The "extensions" field includes "credBlob" = true and credProtect=3.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId with pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step3:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId without  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
The authenticator returns CTAP2_ERR_NO_CREDENTIALS.

Step4:
Send a valid authenticatorGetAssertion (0x02)  request without  credentialId and without  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
The authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step5:
Send a valid authenticatorGetAssertion (0x02)  request without  credentialId and with  pinauthparam .Include "extensions" with "credBlob" = true.
Expected Result:
The authenticator returns CTAP2_ERR_NO_CREDENTIALS.

Step 6:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 7:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",


"getasseration.credblobfalse":"""Test started: P-12 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = true "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId.Include "extensions.credBlob" = false.The authenticator returns either an error code or CTAP1_ERR_SUCCESS (0x00).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",

"withoutincludingextension":"""Test started: P-13 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true).
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = True "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, without including extensions.credBlob. Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response does not contain the credBlob extension
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",

"extensionmappresent":"""Test started: P-14 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = True "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, with the extensions map present but without the credBlob key. The authenticator returns an error.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",


"nondiscoverable":"""Test started: P-15 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo.maxCredBlobLength is at least 32.
5.The authenticator is configured with a PIN.

Test Description:(Verify that the authenticator supports credBlob for non-discoverable credentials when rk = false.)
Step1:
Send a valid authenticatorMakeCredential (0x01) request.Include options.rk = false Include "extensions.credBlob" set to a valid byte string of length less than or eual to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.
Step 2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, including "extensions.credBlob" = true. Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The MakeCredential response includes "credBlob" field .
3.The GetAssertion response includes "credBlob" "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.""",


"credblobnotstoremakecred":"""Test started: P-16 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.The authenticator is configured with a PIN.
5.A non-discoverable credential exists without a stored credBlob (rk = false)


Step1:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId.Include "extensions" with "credBlob" = true.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The MakeCredential response includes "credBlob" field .
3.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",

"credbloblengthincress":"""Test started: P-17 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo.maxCredBlobLength = 32.
5.The authenticator is configured with a PIN.

Test Description:(Verify that the authenticator does not store a credBlob value larger than the supported size.)
Step1:
Send a valid authenticatorMakeCredential (0x01) request.Include:options.rk = False extensions.credBlob credBlob Size Exceeds maxCredBlobLength.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an extensions field.
3.The extensions field includes:"credBlob" =false

Step 2:(Verify Oversized credBlob Is Not Returned)
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credential ID, with "extensions" set to "credBlob" = true. Verify the response.
Expected Results:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The MakeCredential response includes "credBlob" field .
3.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",


"credblobnotpresent":"""Test started: P-18 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.The authenticator is configured with a PIN.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with options.rk = False, without including "extensions.credBlob".Verify the response.
Expected Result:
The authenticator returns CTAP1_ERR_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId Include "extensions" with "credBlob" = true.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.""",

"credblobfalseauthention":"""Test started: P-19 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId.Include "extensions.credBlob" = false.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2. No extension field.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",

"credblobnotauthention":"""Test started: P-20 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
end a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, without including extensions.credBlob. Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response does not contain the credBlob extension
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",
"credblobkeyauthention":"""Test started: P-21 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.
5.The authenticator is configured with a PIN

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = False.

Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, with the extensions map present but without the credBlob key. The authenticator returns an error.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains no  "extensions" field.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",
"credblobnotstore":"""Test started: P-22 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.A nondiscoverable credential exists without a stored credBlob.


Test Description:(Verify that an empty byte string is returned when no credBlob is associated with the credential)
Steps:
Send a valid authenticatorGetAssertion (0x02) using previos credentialid request.Include "extensions" with "credBlob" = true.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",




"credblobwithoutpin":"""Test started: P-23 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.


Test Description:(Verify that the authenticator stores the credBlob value when creating a discoverable credential)
Steps:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = true "extensions" with "credBlob" set to a valid byte string of length less than or equal to maxCredBlobLength.Verify the response
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:(Verify that the authenticator returns the stored credBlob during assertion)
Steps:
Send a valid authenticatorGetAssertion (0x02)  request using the previously recorded credentialId.Include "extensions" with "credBlob" = true.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" with the exact stored byte string.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",

"withoutpincredblobnotstore":"""Test started: P-24 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.A discoverable credential exists without a stored credBlob.


Test Description:(Verify that an empty byte string is returned when no credBlob is associated with the credential)
Steps:
Send a valid authenticatorGetAssertion (0x02) using previos credentialid request.Include "extensions" with "credBlob" = true.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send authenticatorGetNextAssertion (0x08) to retrieve the next assertion.
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",
"withoutpincredblobnotpresentmakecred":"""Test started: P-25 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with options.rk = true, without including "extensions.credBlob".Verify the response.
Expected Result:
The authenticator returns CTAP1_ERR_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId Include "extensions" with "credBlob" = true.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",
"withoutpincredbloblengthincess":"""Test started: P-26 :

Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo.maxCredBlobLength = 32.

Test Description:(Verify that the authenticator does not store a credBlob value larger than the supported size.)
Step1:
Send a valid authenticatorMakeCredential (0x01) request.Include:options.rk = true extensions.credBlob credBlob Size Exceeds maxCredBlobLength.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an extensions field.
3.The extensions field includes:"credBlob" =false

Step 2:(Verify Oversized credBlob Is Not Returned)
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credential ID, with "extensions" set to "credBlob" = true. Verify the response.
Expected Results:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains authData.extensions.
3.The authData.extensions field includes:"credBlob" =false.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",

"withoutpingetasserationfalse":"""Test started: P-27 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.


Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = true "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId.Include "extensions.credBlob" = false.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response does not contain the credBlob extension.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",

"withoutpingetasserationnot":"""Test started: P-28 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true).
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
end a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, without including extensions.credBlob feild . Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response does not contain the credBlob extension
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",
"withoutpinmappresent":"""Test started: P-29 :
Preconditions:
1.The authenticator supports discoverable credentials (rk = true)
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, with the extensions map present but without the credBlob key. The authenticator returns .
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response does not contain the credBlob extension
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",

"withoutpinnondiscoverable":"""Test started: P-30 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo.maxCredBlobLength is at least 32.


Test Description:(Verify that the authenticator supports credBlob for non-discoverable credentials when rk = false.)
Step1:
Send a valid authenticatorMakeCredential (0x01) request.Include options.rk = false Include "extensions.credBlob" set to a valid byte string of length less than or eual to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = False.
Step 2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, including "extensions.credBlob" = true. Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2..The response contains an "extensions" field..
3.The GetAssertion response includes "credBlob" with empty  byte string.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.""",

"withoutStrongextension":"""Test started: P-31 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.A non-discoverable credential exists without a stored credBlob (rk = false)


Test Description:
StepS:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId.Include "extensions" with "credBlob" = true.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",
"withoutpincredblobincress":"""Test started: P-32 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo.maxCredBlobLength = 32.


Test Description:(Verify that the authenticator does not store a credBlob value larger than the supported size.)
Step1:
Send a valid authenticatorMakeCredential (0x01) request.Include:options.rk = False extensions.credBlob credBlob Size Exceeds maxCredBlobLength.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an extensions field.
3.The extensions field includes:"credBlob" =false

Step 2:(Verify Oversized credBlob Is Not Returned)
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credential ID, with "extensions" set to "credBlob" = true. Verify the response.
Expected Results:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains authData.extensions.
3.The authData.extensions field includes:"credBlob" =false.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",
"withoutpincredblobextension":"""Test started: P-33 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with options.rk = False, without including "extensions.credBlob".Verify the response.
Expected Result:
The authenticator returns CTAP1_ERR_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId Include "extensions" with "credBlob" = true.Verify the response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" as an empty byte string.
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful  or not.
""",
"withoutpincredblobfalse":"""Test started: P-34 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = False.

Test Description:
Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId.Include "extensions.credBlob" = false.The authenticator returns  CTAP1_ERR_SUCCESS (0x00).
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains no "extensions" field.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful or not.
""",

"withoutpincredblobauthentication":"""Test started: P-35 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.


Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Test Description:
Step2:
end a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, without including extensions.credBlob. Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response does not contain the credBlob extension
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",
"withoutpincredblobnot":"""Test started: P-36 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset
3.authenticatorGetInfo response includes "credBlob" in the extensions list.
4.authenticatorGetInfo includes maxCredBlobLength at least 32 bytes to be stored.

Test Description:
Step1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include:options.rk = False "extensions" with "credBlob" set to a valid byte string of length less than equal to  maxCredBlobLength.Verify the response.
Expected Result
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response contains an "extensions" field.
3.The "extensions" field includes "credBlob" = true.

Step2:
Send a valid authenticatorGetAssertion (0x02) request using the previously recorded credentialId, with the extensions map present but without the credBlob key. The authenticator returns an error.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",


"u2fauthenticationwithpin":"""Test started: P-37 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator supports U2F (CTAP1) protocol
3.The authenticator is reset. (Dont have PIN set)
4.The authenticator have PIN set
5.authenticatorGetInfo response includes "credProtect" in the extensions list.


Test Description:
Step 1 (Registration): Create credential using valid U2F Registration request . 
Expected Result:
1. The authenticator successfully completes registration .
2.Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull


Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification .
Verify that the authenticator returns  CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS""",


"u2fregistationwitoutpin":"""Test started: P-38 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator supports U2F (CTAP1) protocol
3.The authenticator is reset. (Dont have PIN set)
4.authenticatorGetInfo response includes "credProtect" in the extensions list.


Test Description:
Step 1 (Registration): Create credential using valid U2F Registration request . 
Expected Result:
1. The authenticator successfully completes registration .
2.Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull

Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification .
Verify that the authenticator returns  CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_PIN_NOT_SET.
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_PIN_NOT_SET.""",



}
    if mode not in descriptions:
                    raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode]) 
    util.printcolor(util.YELLOW, descriptions[mode])
    util.printcolor(util.YELLOW, "****  Precondition authenticatorMakeCredential (0x01) Extension CredBlob CTAP2.2 ****")
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Authenticator","00")
    util.run_apdu("80100000010400", "GetInfo", "00")
    username="bobsmith"
    subcommand=0x03
    if protocol == 1:
        protocol = 0x01
        if mode in ["verfycredblob","withoutpincredblobnot", "credblobwithoutpin","withoutpincredblobnotstore","withoutpincredbloblengthincess","withoutpingetasserationfalse","withoutpingetasserationnot","withoutpinnondiscoverable","withoutStrongextension","withoutpincredblobincress","u2fregistationwitoutpin","withoutpincredblobextension","withoutpincredblobfalse","withoutpincredblobauthentication"]:
            print("Authenticator client PIN is not set")
        elif mode =="u2fauthentication":
             print("Perform U2F Registation")
        else:
            clentpinsetp1(pin, protocol, subcommand)
            pinset = "yes"
    else:
        if mode in ["verfycredblob","withoutpincredblobnot","credblobwithoutpin","withoutpincredblobnotstore","withoutpincredbloblengthincess","withoutpingetasserationfalse","withoutpingetasserationnot","withoutpinnondiscoverable","withoutStrongextension","withoutpincredblobincress","u2fregistationwitoutpin","withoutpincredblobextension","withoutpincredblobfalse","withoutpincredblobauthentication"]:
            print("Authenticator client PIN is not set")
        elif mode =="u2fauthentication":
             print("Perform U2F Registation")
        else:
            clentpinsetp2(pin, protocol, subcommand)
            pinset = "yes"



    try:
        scenarioCount += 1
        if str(pinset).lower() == "yes":
            if protocol==1:
                util.printcolor(util.YELLOW, "****  authenticatorMakeCredential (0x01) Extension Credblob CTAP2.2 For   Protocol {protocol}****")
                if mode == "credblob.T":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    decoded_info = getinforesponse(response)

                elif mode == "credblob.Discoverable":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(20)
                    
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode == "newtestcase":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(20)
                    Name="sasmita1"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, Name,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")


                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(20)
                    Name="sasmita2"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, Name,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")


                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extension=getextension(response)
                    response,status=util.run_apdu("80100000010800", "authenticatorGetNextAssertion (0x08)", "00")
                    extension=getextension(response)
                            


                elif mode == "credblobnotsetinmakecred":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(0)
                    mode ="credblobnotset"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                elif mode == "credblobwithu2f":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(20)
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "withoutcredblobmakecred":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension="00"
                    mode ="credblobnotset"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credbloblengthexceed":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(34)
                    
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credbloblengthzero":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(0)
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    print(response)
                    
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    # cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    # util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobandcredprotect":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    mode ="credblobcombine"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)credentialId  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    clientDataHash =os.urandom(32)
                    mode="withoutpintoken"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) credentialId idwithout pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    print(response)
                    extensioncheck(response)

                    util.ResetCardPower()
                    util.ConnectJavaCard()   
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutcred&withpinauth" 
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    print(response)
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobandcredprotect02":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    mode ="credblobcredprotect"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  credentialId with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    clientDataHash =os.urandom(32)
                    mode="withoutpintoken"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) credentialId without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    
                    util.ResetCardPower()
                    util.ConnectJavaCard()   
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutcred&withpinauth" 
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    print(response)
                    extensioncheck(response)
                    
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobandcredprotect03":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    mode ="credblobcredprotect03"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")

                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  credentialId with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    clientDataHash =os.urandom(32)
                    mode="withoutpintoken"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) credentialId without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    
                    util.ResetCardPower()
                    util.ConnectJavaCard()   
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutcred&withpinauth" 
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                
                
                elif mode == "getasseration.credblobfalse":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="credblobnotrequried"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "withoutincludingextension":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="credblobabsent"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)

                
                elif mode == "extensionmappresent":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutcredblob"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)

                    



                elif mode == "nondiscoverable":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(20)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                elif mode == "credblobnotstoremakecred":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(34)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credbloblengthincress":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(34)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobnotpresent":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(0)
                    mode="credblobnotsetwithrkfalse"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobfalseauthention":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="credblobnotrequried"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobnotauthention":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutextension"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobkeyauthention":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutcredblob"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode == "credblobnotstore":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #credblob
                    extension=os.urandom(34)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    
                    
                    mode="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    decode=parse_get_creds_metadata(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode=="u2fauthenticationwithpin":
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apdu(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                    credential_id, pubkey, kh_len = extract_credential_id(response)
                    print("KeyHandle length:", kh_len)
                    print("Credential ID (hex):", credential_id.hex())
                    # 3. Build AUTHENTICATE APDU
                    apdu = u2f_authenticate_apdu(mode,rpid, challenge, credential_id)
                    print("U2F AUTHENTICATE APDU:", apdu)
                    # 4. Send AUTHENTICATE APDU
                    response, status = util.run_apdu(
                        apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
                    pinAuthToken="00"
                    credId= credential_id.hex() 
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutpinauthparam"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
                    
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
                    mode="withoutcredwithpinauth"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                












                    
            elif protocol==2:
                    util.printcolor(util.YELLOW, "****  authenticatorMakeCredential (0x01) Extension CredBlob CTAP2.2 For   Protocol 2****")
                    if mode =="credblob.T":
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        decoded_info = getinforesponse(response)
                    elif mode == "credblob.Discoverable":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(20)
                        
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    elif mode == "credblobnotsetinmakecred":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(0)
                        mode ="credblobnotset"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    elif mode == "credblobwithu2f":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(20)
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "withoutcredblobmakecred":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(0)
                        mode ="credblobnotset"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        # cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        # util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credbloblengthexceed":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(34)
                    
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credbloblengthzero":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(0)
                        
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        print(response)
                        
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        # cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        # util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credblobandcredprotect":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode ="credblobcombine"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        print(response)
                        
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        clientDataHash =os.urandom(32)
                        mode="withoutpintoken"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)

                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)

                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="withoutcred&withpinauth" 
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credblobandcredprotect02":
                    
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode ="credblobcredprotect"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  credentialId with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        
                        clientDataHash =os.urandom(32)
                        mode="withoutpintoken"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) credentialId without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        

                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        
                        
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="withoutcred&withpinauth" 
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)
                        extensioncheck(response)
                        
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                    elif mode == "credblobandcredprotect03":
                    
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode ="credblobcredprotect03"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  credentialId with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        
                        clientDataHash =os.urandom(32)
                        mode="withoutpintoken"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) credentialId without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        
                        

                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        
                        
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")

                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="withoutcred&withpinauth" 
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        print(response)
                        extensioncheck(response)
                        
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                    
                    
                    elif mode == "getasseration.credblobfalse":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="credblobnotrequried" 
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "extensionmappresent":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="withoutcredblob" 
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "withoutincludingextension":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="credblobabsent"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    



                    elif mode == "nondiscoverable":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(20)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response,status=util.APDUhex(apdu,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credblobnotstoremakecred":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(34)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.APDUhex(apdu,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        extensioncheck(response)
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credbloblengthincress":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(34)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.APDUhex(apdu,"GetAssertion 0x02", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        extensioncheck(response)
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                    elif mode == "credblobnotpresent":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(0)
                        mode="credblobnotsetwithrkfalse"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.APDUhex(apdu,"GetAssertion 0x02", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        extensioncheck(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                    elif mode == "credblobfalseauthention":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="credblobnotrequried"  
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response,status=util.APDUhex(apdu,"GetAssertion 0x02", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        extensioncheck(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credblobnotauthention":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="withoutextension"  
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.APDUhex(apdu,"GetAssertion 0x02", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        extensioncheck(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                    elif mode == "credblobkeyauthention":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        mode="withoutcredblob"  
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.APDUhex(apdu,"GetAssertion 0x02", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        extensioncheck(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode == "credblobnotstore":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(32)
                        mode="nondiscoverable"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        util.ResetCardPower()
                        util.ConnectJavaCard()   
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        #response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.APDUhex(apdu,"GetAssertion 0x02", checkflag=True)
                        if response[:2] == "00":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                        extensioncheck(response)
                        
                        mode="cmpermission"
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        subCommand = 0x01  # getCredsMetadata
                        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                        apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        mode ="u2fauthentication"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId)
                    elif mode=="u2fauthenticationwithpin":
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        # 2. Build REGISTER APDU
                        rpid = "example.com"
                        challenge = os.urandom(32)
                        apdu = u2f_register_apdu(rpid, challenge)
                        print("U2F REGISTER APDU:", apdu)
                        # 3. SEND REGISTER APDU 
                        response, status = util.run_apdu(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                        credential_id, pubkey, kh_len = extract_credential_id(response)
                        print("KeyHandle length:", kh_len)
                        print("Credential ID (hex):", credential_id.hex())
                        # 3. Build AUTHENTICATE APDU
                        apdu = u2f_authenticate_apdu(mode,rpid, challenge, credential_id)
                        print("U2F AUTHENTICATE APDU:", apdu)
                        # 4. Send AUTHENTICATE APDU
                        response, status = util.run_apdu(
                            apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
                        pinAuthToken="00"
                        credId= credential_id.hex() 
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        mode="withoutpinauthparam"
                        apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        
                        pinAuthToken = util.hmac_sha256(pinToken, challenge)
                        
                        apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        
                        pinAuthToken = util.hmac_sha256(pinToken, challenge)
                        mode="withoutcredwithpinauth"
                        apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                    elif mode == "newtestcase":
                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(20)
                        username="sasmita1"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")


                        subcommand=0x05
                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        #credblob
                        extension=os.urandom(20)
                        username="sasmita2"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")


                        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                        clientDataHash =os.urandom(32)
                        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        response,status=util.run_apdu("80100000010800", "authenticatorGetNextAssertion (0x08)", "00")
                        extension=getextension(response)

                    
                    
                    







        
        if str(pinset).lower() == "no" and protocol in (1, 2):
                util.printcolor(util.YELLOW, "****  Without Authenticator clientpin****")
                if mode =="verfycredblob":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    decoded_info = getinforesponse(response)
                elif mode =="credblobwithoutpin":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(20)
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpincredblobnotstore":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(0)
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    util.printcolor(util.YELLOW, "No extension Extensions")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)            
                elif mode =="withoutpincredblobnotstore":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(0)
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpincredblobnotpresentmakecred":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(0)
                    mode="withoutextension"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpincredbloblengthincess":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(34)
                    
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpingetasserationfalse":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": False}
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpingetasserationnot":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": False}
                    mode="withoutextension"
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpinmappresent":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpinnondiscoverable":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutStrongextension":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                elif mode =="withoutpincredblobincress":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(34)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                elif mode =="withoutpincredblobextension":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(0)
                    mode="discoverablewithoutextension"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": True}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)            


                elif mode =="withoutpincredblobfalse":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": False}
                    
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)

                elif mode =="withoutpincredblobauthentication":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={"credBlob": False}
                    mode="withoutextension"
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                elif mode =="withoutpincredblobnot":
                    clientDataHash =os.urandom(32)
                    #credblob
                    extension=os.urandom(32)
                    mode="nondiscoverable"
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    clientDataHash =os.urandom(32)
                    credblob={}
                    mode="withoutextensionnotmap"
                    apdu=createCBORmakeAssertionwithoupinauth(mode,clientDataHash, rp,  credId,protocol,credblob)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    extensioncheck(response)
                    mode ="u2fauthentication"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                
                elif mode =="u2fregistationwitoutpin":
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                    credential_id, pubkey, kh_len = extract_credential_id(response)
                    print("KeyHandle length:", kh_len)
                    print("Credential ID (hex):", credential_id.hex())
                    # 3. Build AUTHENTICATE APDU
                    apdu = u2f_authenticate_apdu(mode,rpid, challenge, credential_id)
                    print("U2F AUTHENTICATE APDU:", apdu)
                    # 4. Send AUTHENTICATE APDU
                    response, status = util.run_apduu2f(
                        apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    credId= credential_id.hex()
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinAuthToken="00"
                    mode="withoutpinauthparam"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    response, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00") 
                    if protocol==1:
                        pinAuthToken=os.urandom(16)
                    else:
                        pinAuthToken=os.urandom(32)
                    mode="withpinauthparam"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status =util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredandpinauth"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
    finally:
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1       




def extract_credential_id(register_response_hex: str):
    data = bytes.fromhex(register_response_hex)

    offset = 0

    # Reserved byte
    if data[offset] != 0x05:
        raise ValueError("Invalid U2F register response")
    offset += 1

    # Public key (65 bytes)
    pubkey = data[offset:offset + 65]
    offset += 65

    # Key handle length
    key_handle_len = data[offset]
    offset += 1

    # Credential ID (keyHandle)
    credential_id = data[offset:offset + key_handle_len]
    offset += key_handle_len

    return credential_id, pubkey, key_handle_len


def u2f_authenticate_apdu(mode, rpid: str, challenge: bytes, credential_id: bytes | None):
    assert len(challenge) == 32

    # U2F Application parameter = SHA256(RP ID)
    app_param = hashlib.sha256(rpid.encode("utf-8")).digest()

    CLA = "00"
    INS = "02"
    P1  = "03"
    P2  = "00"

    if mode == "withoutcred":
        # Omit credential completely (will return 6700)
        data = challenge + app_param
    else:
        # Use a real or unknown credential_id
        if mode == "unknown":
            # Generate a key handle not present on device
            credential_id = os.urandom(32)
        # Normal validation
        assert credential_id is not None
        assert 0 < len(credential_id) <= 255
        key_handle_len = len(credential_id).to_bytes(1, "big")
        data = challenge + app_param + key_handle_len + credential_id

    lc = len(data).to_bytes(3, "big")  # extended length

    apdu = CLA + INS + P1 + P2 + lc.hex() + data.hex()
    return apdu










               

def getextension(response, expect_credblob=False):
    """
    expect_credblob:
        True  -> credBlob must be returned
        False -> credBlob must NOT be returned
    """

    authdata = parse_getassertion_response(response)
    parsed_authdata = parse_authdatagetassertion(authdata)

    extensions = parsed_authdata.get("extensions")

    # ------------------------------------------
    # Case 1: No extensions field
    # ------------------------------------------
    if extensions is None:
        util.printcolor(util.YELLOW, "No extensions field present")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but none returned!")

        return None

    # ------------------------------------------
    # Case 2: Extensions map empty
    # ------------------------------------------
    if isinstance(extensions, dict) and len(extensions) == 0:
        util.printcolor(util.YELLOW, "Extensions map present but empty")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but extensions empty!")

        return extensions

    # ------------------------------------------
    # Debug print
    # ------------------------------------------
    util.printcolor(util.CYAN, f"Returned extensions map: {extensions}")

    # ------------------------------------------
    # credBlob check
    # ------------------------------------------
    if "credBlob" in extensions:

        value = extensions["credBlob"]

        # if not expect_credblob:
        #     util.printcolor(util.RED, "credBlob returned but NOT expected!")

        if isinstance(value, bytes):

            if len(value) == 0:
                util.printcolor(util.YELLOW, "credBlob: <empty bytes>")
            else:
                util.printcolor(util.GREEN, f"credBlob ({len(value)} bytes): {value.hex()}")

            if len(value) > 32:
                util.printcolor(util.RED, "credBlob exceeds maximum allowed size (32 bytes)")

        else:
            util.printcolor(util.YELLOW, f"credBlob returned non-bytes value: {value}")

    else:

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but not returned!")
        else:
            util.printcolor(util.YELLOW, "credBlob: NOT PRESENT")

    return extensions


def getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: protocol,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    #util.printcolor(util.BLUE, cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)
    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex+"00"
    return apdu     
             

def clentpinsetp1(pin,protocol,subcommand):
    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
    newpinsetP1(pin,protocol,subcommand)
    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
def clentpinsetp2(pin,protocol,subcommand):
    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
    newpinsetP2(pin,protocol,subcommand)
    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")

def newpinsetP1(pin,protocol,subcommand):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    # Step 1: Get peer (authenticator) key agreement
    response, status = util.run_apdu("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", expected_prefix="00") 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocolP1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False)  # skips min length check
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
    # Compute HMAC using same 32 bytes
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    pinSetAPDU = create_cbor_setpin(new_pin_enc, pin_auth, key_agreement,protocol,subcommand)
    #response,status=util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    response, status = util.run_apdu(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", expected_prefix="00") 
    return response

def newpinsetP2(pin,protocol,subcommand):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    response, status=util.run_apdu("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", expected_prefix="00") 
    cbor_bytes   = binascii.unhexlify(response[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = create_cbor_setpin(newPinEnc, auth, key_agreement,protocol,subcommand)   
    response, status = util.run_apdu(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", expected_prefix="00") 
    #res,st=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response

def create_cbor_setpin(new_pin_enc, pin_auth, key_agreement,protocol,subcommand):
    cose_key = cbor2.dumps(key_agreement).hex().upper()
    cbor_newpin = cbor2.dumps(new_pin_enc).hex().upper()
    cbor_auth = cbor2.dumps(pin_auth).hex().upper()
    cbor_protocol = cbor2.dumps(protocol).hex().upper()
    cbor_subcommand = cbor2.dumps(subcommand).hex().upper()

    data_cbor = "A5"
    data_cbor += "01" + cbor_protocol            # pinProtocol = 1
    data_cbor += "02" + cbor_subcommand            # subCommand = 3 (SetPIN)
    data_cbor += "03" + cose_key              # keyAgreement
    data_cbor += "04" + cbor_auth             # pinAuth
    data_cbor += "05" + cbor_newpin           # newPinEnc

    length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
    return apdu


def getPINtokenp1(mode,pin,subcommand,protocol):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    #util.APDUhex("80100000010400", "GetInfo")
    util.printcolor(util.YELLOW,f"Providing Protocol1 sharesecret:")
    response, status = util.run_apdu("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00") 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    apdu=createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol)
    return apdu

def getPINtokenp2(mode,curpin,subcommand,protocol):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    response, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00")
    cbor_bytes    = binascii.unhexlify(response[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = response[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPinToken(mode,key_agreement,pinHashEnc,shareSecretKey,subcommand,protocol)
    # hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    # byte_array = bytes.fromhex(hexstring[2:])
    # cbor_data = cbor2.loads(byte_array)                                                                                                
    # first_key = sorted(cbor_data.keys())[0]
    # pinToken = cbor_data[first_key]
    # #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return pinSetAPDU

def createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol):
    if mode =="cmpermission":
        permission=4
        subcommand=9
         
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc,         # pinHashEnc
        9:permission}
    else:
         
        cbor_map = {
            1: protocol,                  # pinProtocol = 1
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc         # pinHashEnc
            # 9:permission,
            # 10:"localhost"

        }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.run_apdu(apdu,"Client PIN GetPINToken",expected_prefix="00")
    #response, status = util.APDUhex(apdu, "Client PIN  GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    if protocol ==1:
        enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
        if not enc_pin_token:
            raise ValueError("No pinToken returned from authenticator")

        pin_token = util.pintoken(shared_secret, enc_pin_token)
    else:
         byte_array = bytes.fromhex(response[2:])
         cbor_data = cbor2.loads(byte_array)                                                                                                
         first_key = sorted(cbor_data.keys())[0]
         pinToken = cbor_data[first_key]
        #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

         pin_token =  util.aes256_cbc_decrypt(shared_secret[32:],pinToken[:16],pinToken[-32:])
    
    util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token



def getinforesponse(response):
    """
    Parse CTAP2 GetInfo response and verify credBlob support
    """

    if isinstance(response, str):
        response = bytes.fromhex(response)

    # Strip CTAP success status byte
    if response and response[0] == 0x00:
        response = response[1:]

    print("First CBOR byte:", hex(response[0]))

    decoded = cbor2.loads(response)
    assert isinstance(decoded, dict), "GetInfo response is not a CBOR map"

    # ---- Validate extensions ----
    extensions = decoded.get(0x02)
    assert extensions and "credBlob" in extensions, "credBlob not supported"

    # ---- Extract maxCredBlobLength (CTAP2.1) ----
    max_credblob_len = decoded.get(0x0F)
    assert max_credblob_len is not None, "maxCredBlobLength missing"

    assert max_credblob_len == 32, (
        f"Expected maxCredBlobLength = 32, got {max_credblob_len}"
    )

    
    util.printcolor(util.GREEN, f"PASS: credBlob extension is supported")
    util.printcolor(util.GREEN, f"PASS: maxCredBlobLength = {max_credblob_len} bytes")

    # ---- Pretty-print full GetInfo map ----
    print("\nDecoded GetInfo response:")
    pprint.pprint(decoded, width=120)


    return decoded

def createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, user, protocol,credblob):
    
   

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
        }
    ]
    #for option
    if mode =="nondiscoverable":    
        option  = {"rk": False}#alwaysUv,makeCredUvNotRqd
    else:
         option  = {"rk": True}
    extension={"credBlob": credblob}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
   
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_option        = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()
    if mode =="withoutextension":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "09"+ cbor_protocol 
    if mode =="discoverablewithoutextension":
        option  = {"rk": False}
        cbor_option        = cbor2.dumps(option).hex().upper()
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "09"+ cbor_protocol 
    else:

        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "09"+ cbor_protocol 

    

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    
    # Final payload = 01 prefix + dataCBOR
    full_data = "01" + dataCBOR
    byte_len = len(full_data)//2
    

    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len <= 256:
        lc = format(byte_len, '02X')
        return "80100000" + lc + full_data +"00" # single string
        

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
            lc = format(len(chunk)//2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)
        return apdus  # list of chained APDUs

def createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol,credblob):
    
   

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
        }
    ]
    #for option
    if mode =="nondiscoverable":    
        option  = {"rk": False}#alwaysUv,makeCredUvNotRqd
    else:
         option  = {"rk": True}

    #for extension
    if mode =="credblobcombine":
         credprotect=1
         extension={"credBlob": credblob,
                    "credProtect": credprotect}
    elif mode =="credblobcredprotect":
        credprotect=2
        extension={"credBlob": credblob,
                    "credProtect": credprotect}
    elif mode =="credblobcredprotect03":
        credprotect=3
        extension={"credBlob": credblob,
                    "credProtect": credprotect}
    else:
        extension={"credBlob": credblob}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_option        = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()
    if mode =="credblobnotset":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol
    elif mode =="credblobnotsetwithrkfalse":
        option  = {"rk": False}
        cbor_option        = cbor2.dumps(option).hex().upper()
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol
    else: 
        dataCBOR = "A8"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol 

    

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    
    # Final payload = 01 prefix + dataCBOR
    full_data = "01" + dataCBOR
    byte_len = len(full_data)//2
    

    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len <= 256:
        lc = format(byte_len, '02X')
        return "80100000" + lc + full_data +"00" # single string
        

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
            lc = format(len(chunk)//2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)
        return apdus  # list of chained APDUs
    
def authParasing(response):
    print("response",response)
    authdata=extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info = parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    credentialPublicKey = credential_info["credentialPublicKey"]

    print("credid",credentialId)
    return credentialId,credentialPublicKey

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
def parse_authdata(authdata_bytes):
    offset = 0

    # rpIdHash (32 bytes)
    rp_id_hash = authdata_bytes[offset:offset + 32]
    offset += 32

    # flags (1 byte)
    flags = authdata_bytes[offset]
    offset += 1

    # signCount (4 bytes, big endian)
    sign_count_bytes = authdata_bytes[offset:offset + 4]
    sign_count = struct.unpack(">I", sign_count_bytes)[0]
    offset += 4

    # aaguid (16 bytes)
    aaguid = authdata_bytes[offset:offset + 16]
    offset += 16

    # credentialIdLength (2 bytes, big endian)
    cred_id_len = struct.unpack(">H", authdata_bytes[offset:offset + 2])[0]
    offset += 2

    # credentialId (cred_id_len bytes)
    credential_id = authdata_bytes[offset:offset + cred_id_len]
    offset += cred_id_len

    # credentialPublicKey (rest of the data)
    credential_pub_key = authdata_bytes[offset:]

    return {
        "rpIdHash": rp_id_hash.hex(),
        "flags": hex(flags),
        "signCount": sign_count,
        "aaguid": aaguid.hex(),
        "credentialIdLength": cred_id_len,
        "credentialId": credential_id.hex(),
        "credentialPublicKey": credential_pub_key.hex()
    }


import struct
import cbor2

def parse_authdatagetassertion(authdata_bytes):
    offset = 0

    # ---- rpIdHash (32 bytes) ----
    rp_id_hash = authdata_bytes[offset:offset + 32]
    offset += 32

    # ---- flags (1 byte) ----
    flags = authdata_bytes[offset]
    offset += 1

    # ---- signCount (4 bytes, big endian) ----
    sign_count = struct.unpack(">I", authdata_bytes[offset:offset + 4])[0]
    offset += 4

    parsed = {
        "rpIdHash": rp_id_hash.hex(),
        "flags": flags,
        "signCount": sign_count,
        "extensions": None
    }

    # ---- Extensions (only if flag 0x80 is set) ----
    EXTENSION_FLAG = 0x80
    if flags & EXTENSION_FLAG:
        extensions = cbor2.loads(authdata_bytes[offset:])
        parsed["extensions"] = extensions

    return parsed


def createCBORmakeAssertionwithoupinauth(mode,cryptohash, rp,  credId,protocol,credblob):
    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
        
    }]
    option= {"up":True}
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_credblob     = cbor2.dumps(credblob).hex().upper() 
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    pin_protocol       = cbor2.dumps(protocol).hex().upper()
    if mode =="withoutextension":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    elif mode =="withoutextensionnotmap":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_credblob
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    else:

        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_credblob

        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80100000" + format(length, '02X') + full_payload+"00"
    return apdu

    


def createCBORmakeAssertion(mode,cryptohash, rp,  credId,protocol,pinauthtoken):
    if mode =="credblobnotrequried":
        credblob={"credBlob": False}
    else:
        credblob={"credBlob": True}
    

    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
        
    }]
    if mode =="upturewith02":
         option= {"up":True}
    else:
         
        option= {"up":True}
   
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_credblob     = cbor2.dumps(credblob).hex().upper() 
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinauth       = cbor2.dumps(pinauthtoken).hex().upper()
    pin_protocol       = cbor2.dumps(protocol).hex().upper()                                      # 0x07: pinProtocol = 2

    if mode=="withoutcredId":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_credblob
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    elif mode =="withoutpintoken":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_credblob
        dataCBOR += "05" + cbor_option
    elif mode=="withoutcred&withpinauth":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_credblob

        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutcred&withpinauth":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_credblob

        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutcredblob":
        credblob={}
        cbor_credblob     = cbor2.dumps(credblob).hex().upper() 

        dataCBOR = "A7"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_credblob
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="credblobabsent":
        
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutextension":
        
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutpinauthparam":
        
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutcredwithpinauth":
        
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode =="newtestcase":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        #dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_credblob

        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol



    else:
              
    # 5-element map
        dataCBOR = "A7"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_credblob

        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    # util.printcolor(util.BLUE, dataCBOR)
    # util.hex_string_to_cbor_diagnostic(dataCBOR)

    # full_payload = "02" + dataCBOR
    # length = len(full_payload) // 2
    # print("datacborlength",length)
    # apdu = "80100000" + format(length, '02X') + full_payload+"00"
    # return apdu

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    
    # Final payload = 01 prefix + dataCBOR
    full_data = "02" + dataCBOR
    byte_len = len(full_data)//2
    
    print
    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len <= 256:
        lc = format(byte_len, '02X')
        return "80100000" + lc + full_data +"00" # single string
        

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
            lc = format(len(chunk)//2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)
        return apdus  # list of chained APDUs

import cbor2

import cbor2

def parse_get_creds_metadata(response_hex):
    """
    Parse CTAP2.1 CredentialMgmt getCredsMetadata response
    and print all relevant fields
    """

    # ---- Convert hex string to bytes ----
    response = bytes.fromhex(response_hex)

    # ---- Strip CTAP status byte (0x00) ----
    if response and response[0] == 0x00:
        response = response[1:]

    # ---- Strip ISO7816 status word (9000) ----
    if response[-2:] == b"\x90\x00":
        response = response[:-2]

    # ---- Decode CBOR ----
    decoded = cbor2.loads(response)

    if not isinstance(decoded, dict):
        raise ValueError("Invalid CBOR response")

    # ---- Extract fields ----
    count_present = decoded.get(0x01)
    resident_count = decoded.get(0x02)
    

    # ---- Print results ----
    print("Credential Metadata:")
    print(f"  - existingResidentCredentialsCount (0x01): {count_present}")
    print(f"  - maxPossibleRemainingResidentCredentialsCount  (0x02): {resident_count}")

    return decoded


def u2f_register_apdu(app_id: str, challenge: bytes):
    """
    Build U2F REGISTER APDU (CTAP1)
    """

    # Hashes required by U2F
    challenge_param = hashlib.sha256(challenge).digest()
    application_param = hashlib.sha256(app_id.encode()).digest()

    assert len(challenge_param) == 32
    assert len(application_param) == 32

    data = challenge_param + application_param

    apdu = (
        "00"      # CLA
        "01"      # INS = U2F_REGISTER
        "00"      # P1
        "00"      # P2
        "40"      # Lc = 64 bytes
        + data.hex().upper()
        + "00"    # Le
    )

    return apdu 
from io import BytesIO
def parse_credential_pubkey_and_extensions(hex_data):
    raw = bytes.fromhex(hex_data)
    bio = BytesIO(raw)
    decoder = cbor2.CBORDecoder(bio)

    cose_key = decoder.decode()       # First CBOR object
    extensions = decoder.decode()     # Second CBOR object

    return cose_key, extensions

import cbor2

def parse_getassertion_response(response):
    """
    Parse CTAP2 authenticatorGetAssertion (0x02) response
    and print credBlob extension if present
    """

    # ---- Convert hex to bytes if needed ----
    if isinstance(response, str):
        response = bytes.fromhex(response)

    # ---- Strip CTAP status byte (0x00) ----
    if response and response[0] == 0x00:
        response = response[1:]

    # ---- Decode CBOR ----
    decoded = cbor2.loads(response)

    if not isinstance(decoded, dict):
        raise ValueError("Invalid GetAssertion response")

    # ---- Extract fields ----
    credential = decoded.get(0x01)
    authData = decoded.get(0x02)
    signature = decoded.get(0x03)
    user = decoded.get(0x04)
    extensions = decoded.get(0x06)

    
    util.printcolor(util.YELLOW, f"  authData: {authData.hex() }")

    
    return authData

def print_extensions_hex(extensions):
    print("  Extensions:")
    for key, value in extensions.items():
        if isinstance(value, bytes):
            print(f"    {key}: {value.hex()}")
        else:
            print(f"    {key}: {value}")


def extensioncheck(response, expect_credblob=False):
    """
    expect_credblob:
        True  -> test expects credBlob to be returned
        False -> test expects credBlob NOT to be returned
    """

    authdata = parse_getassertion_response(response)
    parsed_authdata = parse_authdatagetassertion(authdata)

    extensions = parsed_authdata.get("extensions")

    # -------------------------------------------------
    # Case 1: No extensions field at all
    # -------------------------------------------------
    if extensions is None:
        util.printcolor(util.YELLOW, "No extensions field present")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but none returned!")
        return

    # -------------------------------------------------
    # Case 2: Extensions map exists but empty
    # -------------------------------------------------
    if isinstance(extensions, dict) and len(extensions) == 0:
        util.printcolor(util.YELLOW, "Extensions map present but empty")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but extensions empty!")
        return

    #util.printcolor(util.YELLOW, "Extensions:")

    # -------------------------------------------------
    # Case 3: credBlob handling
    # -------------------------------------------------
    if "credBlob" not in extensions:
        util.printcolor(util.YELLOW, "  credBlob: NOT PRESENT")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but not returned!")
        return

    value = extensions["credBlob"]

    if isinstance(value, bytes):
        if len(value) == 0:
            util.printcolor(util.YELLOW, "  credBlob: <empty bytes>")

            if not expect_credblob:
                util.printcolor(
                    util.GREEN,
                    "credBlob returned empty but present"
                )
        else:
            util.printcolor(
                util.YELLOW,
                f"  credBlob: {value.hex()}"
            )
    else:
        util.printcolor(
            util.YELLOW,
            f"  credBlob (non-bytes value): {value}"
        )


def u2fauthenticatenew(mode,rp, clientDataHash, credId):
    print("mode-->",mode)
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    #clientDataHash1=os.urandom(32)
    apdu = u2f_authenticate_apdunew(rp, clientDataHash, credId)
    print("U2F AUTHENTICATE APDU:", apdu)
                    # 4. Send AUTHENTICATE APDU
    if mode in ("u2fauthentication"):
       response, status = util.run_apdu(
                    apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
    else:
        response, status = util.run_apdu(apdu,"U2F AUTHENTICATE ",expected_error_name="6A80")

def u2f_authenticate_apdunew(rpid: str, challenge: bytes, credential_id):

    if isinstance(credential_id, str):
        credential_id = bytes.fromhex(credential_id)

    assert len(challenge) == 32

    app_param = hashlib.sha256(rpid.encode()).digest()

    CLA = b"\x00"
    INS = b"\x02"
    P1  = b"\x03"
    P2  = b"\x00"

    key_handle_len = len(credential_id).to_bytes(1, "big")

    data = challenge + app_param + key_handle_len + credential_id

    # ✅ MUST BE 1 BYTE
    lc = len(data).to_bytes(1, "big")

    apdu = CLA + INS + P1 + P2 + lc + data

    return apdu.hex()


            
