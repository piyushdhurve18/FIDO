import Setpinp1
import getpintokenCTAP2_2
from textwrap import wrap
import enableEnterpriseAttestationctap2
import toggleAlwaysUv
import hmac
import hashlib
from binascii import unhexlify
import pprint
import util
import cbor2
import binascii
import os
import struct
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import DocumentCreation

permissionRpId = ""
rp="localhost"
username="bobsmith"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - THIRD PARTY PAYMENT)"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0


def getPinUvAuthTokenP2_2(mode,pinsetrequried,protocol,pin):
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
     "tooltest1":"""Test started: P-1:
         Create a new discoverable credential, with "extensions" containing valid "thirdPartyPayment" extension set to true.
         Send GetAssertion request with thirdPartyPayment extension set to true, and check that result contains thirdPartyPayment extension with type boolean and set to true.""",

     "tooltest2":"""Test started: P-2:
         Create a new non-discoverable credential, with "extensions" containing valid "thirdPartyPayment" extension set to true.
         Send GetAssertion request with thirdPartyPayment extension set to true, and check that result contains thirdPartyPayment extension with type boolean and set to true.""",
     "tooltest3":"""Test started: F-1:
         Create a new non-discoverable credential, without any extensions.
         Send GetAssertion request with thirdPartyPayment extension set to true, and check that result contains thirdPartyPayment extension with type boolean and set to FALSE.""",
     
     
     "newtestcase":"""Test started: p-33 :           
            Preconditions:
            1.The authenticator supports CTAP2
            2.The authenticator is reset
            3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list.
            4.The authenticator is configured with a PIN
            5.The authenticator supports the thirdPartyPayment extension.
            6.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

            Test Description:
            Step 1:(Create Credential with thirdPartyPayment Enabled)
            Two  valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
            "thirdPartyPayment": true

            Expected Result:
            1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
            2.No "extensions" field in the authenticatorMakeCredential response

            Step 2: (Retrieve thirdPartyPayment)
            Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
            "thirdPartyPayment": true

            Expected output:
            1.The authenticator returns CTAP2_SUCCESS (0x00).
            2.The response contains an "extensions" field inside authenticatorData.
            3.The "extensions" field includes "thirdPartyPayment".
	            thirdPartyPayment": true
            Step 3:
            Send a valid authenticatorGetNextAssertion (0x08).Verify that the authenticator returns CTAP1_ERR_SUCCESS.
            """,



        "getinfo":"""Test started: P-3:
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.A PIN is configured on the authenticator.

Test Description:
Verify that the authenticator advertises support for the hmac-secret extension.
Steps:
Send a valid authenticatorGetInfo (0x04) request.The authenticator returns CTAP2_SUCCESS.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains thirdPartyPayment in the extensions list.
3.The response includes the thirdPartyPayment field, and its value matches the default .""",

"getinfowithoutpin":"""Test started: P-4:
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.

Test Description:
Verify that the authenticator advertises support for the hmac-secret extension.
Steps:
Send a valid authenticatorGetInfo (0x04) request.The authenticator returns CTAP2_SUCCESS.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains thirdPartyPayment in the extensions list.
3.The response includes the thirdPartyPayment field, and its value matches the default .""",


"thardpartytestcase3":"""Test started: P-5:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list.
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"thirdPartyPayment": true

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": true
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication error.
""",
"thardpartytestcase4":"""Test started: P-6:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
"thirdPartyPayment": true

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": true
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
""",

"thardpartytestcase5":"""Test started: P-7:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"thirdPartyPayment": true
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": True
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication error.""",

"thardpartytestcase6":"""Test started: P-8:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
"thirdPartyPayment": true
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": true
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.""",
"thardpartytestcase7":"""Test started: P-9:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
7.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
"thirdPartyPayment": False
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
""",
"thardpartytestcase8":"""Test started: P-10:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
7.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
"thirdPartyPayment": False
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase9":"""Test started: P-11:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
"thirdPartyPayment": False
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase10":"""Test started: P-12:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  nondiscoverable (rk=false) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field: 
"thirdPartyPayment": False
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successfull.
""",

"thardpartytestcase11":"""Test started: P-13:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
7.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.without Include the following in the extensions field: 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",

"thardpartytestcase12":"""Test started: P-14:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
7.The authenticator supports  nondiscoverable (rk=false) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.without Include the extensions field: 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS,.
""",
"thardpartytestcase13":"""Test started: P-15:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  nondiscoverable (rk=false) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.without Include the following in the extensions field: 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS,.
 """,

"thardpartytestcase14":"""Test started: P-16:
 Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.without Include  the extensions field: 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "thirdPartyPayment".
	thirdPartyPayment": false

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS,.
 """,

"thardpartytestcase15":"""Test started: P-17:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
7.The authenticator supports  nondiscoverable (rk=false) credentials with thirdPartyPayment.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field: 
"thirdPartyPayment": True
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.without Include "extensions" 
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains no  "extensions" field inside authenticatorData.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS,.
""",  
"thardpartytestcase16":"""Test started: P-18:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
7.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
"thirdPartyPayment": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2:
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.without Include "extensions" 

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains no  "extensions" field inside authenticatorData.

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase17":"""Test started: P-19:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
"thirdPartyPayment": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2:
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.without Include "extensions" 

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains no  "extensions" field inside authenticatorData.

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase18":"""Test started: P-20:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the extensions field: 
"thirdPartyPayment": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2:
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.without Include "extensions" 

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains no  "extensions" field inside authenticatorData.

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase19":"""Test started: P-21:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x01
3."credBlob" = 32-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': False, 'credProtect': 1, 'hmac-secret': True}
.3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": empty byte string
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
  """,


"thardpartytestcase20":"""Test started: P-22:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x02
3."credBlob" = 20-byte value
4."hmac-secret": false

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': False, 'credProtect': 2, 'hmac-secret': false}).
3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": empty byte string
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
  """,

"thardpartytestcase21":"""Test started: P-23:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x03
3."credBlob" = 10-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': False, 'credProtect': 3, 'hmac-secret': True}).
3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": empty byte string
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase22":"""Test started: P-24:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x01
3."credBlob" = 32-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': False, 'credProtect': 1, 'hmac-secret': True}
.3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": empty byte string
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
  """,


"thardpartytestcase23":"""Test started: P-25:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  nondiscoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x02
3."credBlob" = 20-byte value
4."hmac-secret": false

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': False, 'credProtect': 2, 'hmac-secret': false}).
3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": empty byte string
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
  """,

"thardpartytestcase24":"""Test started: P-26:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x01
3."credBlob" = 32-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': True, 'credProtect': 1, 'hmac-secret': True}
.3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": <32 byte>
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
  """,


"thardpartytestcase25":"""Test started: P-27:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x02
3."credBlob" = 20-byte value
4."hmac-secret": false

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': True, 'credProtect': 2, 'hmac-secret': false}).
3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": <20 byte>
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
  """,

"thardpartytestcase26":"""Test started: P-28:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x03
3."credBlob" = 10-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': True, 'credProtect': 3, 'hmac-secret': True}).
3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": <10byte>
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"thardpartytestcase27":"""Test started: P-29:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x01
3."credBlob" = 32-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob': True, 'credProtect': 1, 'hmac-secret': True}
.3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": <32byte>
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS.
  """,


"thardpartytestcase28":"""Test started: P-30:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x02
3."credBlob" = 20-byte value
4."hmac-secret": false

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field reflecting the processed extensions, for example:
    Extensions : {'credBlob':True, 'credProtect': 2, 'hmac-secret': false}).
3.The response does not include the "thirdPartyPayment" extension in the output.
Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.with the following in the extensions field:
1."thirdPartyPayment": true
2."credBlob": true
3."hmac-secret" with the following parameters:
    0x01: key_agreement,
    0x02:saltEnc(one salt(32byte)),
    0x03:saltAuth,
    0X04 :protocol

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes:
    1."thirdPartyPayment": true
    2."credBlob": <20byte>
    3."hmac-secret":
        .48 bytes when using protocol 2
        .32 bytes when using protocol 1

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
  """,
"thardpartytestcase29":"""Test started: P-31:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=False) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
"thirdPartyPayment": true
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Reset the Authenticator)
Send the FIDO reset command (0x07).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The thirdPartyPayment setting should be disabled after the reset.

Step 3: (Get Authenticator Information)
Send the authenticatorGetInfo command (0x04).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response should reflect that thirdPartyPayment is disabled.
""",
"thardpartytestcase30":"""Test started: P-32:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=False) credentials with thirdPartyPayment.
7.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
"thirdPartyPayment": true
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response
Step 2: (Reset the Authenticator)
Send the FIDO reset command (0x07).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The thirdPartyPayment setting should be disabled after the reset.

Step 3: (Get Authenticator Information)
Send the authenticatorGetInfo command (0x04).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response should reflect that thirdPartyPayment is disabled.
""",
"thardpartytestcase31":"""Test started: F-2:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"thirdPartyPayment": true,but CBOR payload with an incorrect length.
Expected Result:
1.The authenticator returns CTAP2_ERR_INVALID_CBOR(0x12).

""",
"thardpartytestcase32":"""Test started: F-3:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.In the extensions field, include "thirdPartyPayment": set to a random type.
Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE(0x11).
""",
"thardpartytestcase33":"""Test started: F-4:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
"thirdPartyPayment": true

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.n the extensions field, include "thirdPartyPayment": set to a random type.
Expected output:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE (0x11).
""",

"thardpartytestcase34":"""Test started: F-5:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field: 
"thirdPartyPayment": true

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.n the extensions field, include "thirdPartyPayment": true,but CBOR payload with an incorrect length.
Expected output:
The authenticator returns CTAP2_ERR_INVALID_CBOR(0x12).
""",


"thardpartytestcase35":"""Test started: F-6:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"thirdPartyPayment": true

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 2: (Reset the Authenticator)
Send the FIDO reset command (0x07).

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The thirdPartyPayment setting should be disabled after the reset.

Step 3: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true

Expected output:
1.The authenticator returns CTAP2_ERR_PIN_NOT_SET (0x35).""",

"thardpartytestcase36":"""Test started: F-7:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the thirdPartyPayment extension.
6.The authenticator supports  discoverable (rk=true) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"thirdPartyPayment": true

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.No "extensions" field in the authenticatorMakeCredential response

Step 3: (Retrieve thirdPartyPayment)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" 
"thirdPartyPayment": true,Provide an incorrect or invalid Credential ID (CredId) in the request.

Expected output:
The authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""",

"thardpartytestcase37":"""Test started: F-8:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " thirdPartyPayment" in the extensions list..
4.The authenticator supports the thirdPartyPayment extension.
5.The authenticator supports  discoverable (rk=True) credentials with thirdPartyPayment.

Test Description:
Step 1:(Create Credential with thirdPartyPayment Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."thirdPartyPayment": true
2."credProtect" = 0x03
3."credBlob" = 10-byte value
4."hmac-secret": True

Expected Result:
1.The authenticator returns CTAP2_ERR_PUAT_REQUIRED.""",
"thardpartytestcase38":"""Test started: F-9:
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

"thardpartytestcase39":"""Test started: F-10:
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
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.""",


    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode]) 
    util.printcolor(util.YELLOW, descriptions[mode])
    if mode in ("tooltest1","tooltest2","tooltest3"):
        util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Precondition : CTAP2.2 authenticatorMakeCredential (0x01) using thirdPartyPayment extension Protocol-{protocol}****")
    else:
        util.printcolor(util.YELLOW, f"**** Precondition based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with thirdPartyPayment extension Protocol-{protocol} ****")

    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN","00")
    response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
    getinforesponse(response)
    if str(pinsetrequried).lower() == "yes":

        subcommand=0x03
        if protocol == 1:
            clentpinsetp1(pin, protocol, subcommand)
            PinIsSet = "yes"
        elif protocol ==2:
            clentpinsetp2(pin, protocol, subcommand)
            PinIsSet = "yes"
              
        else:
            print("Perform U2F Registation")
    else:
        util.printcolor(util.YELLOW, "PIN  IS NOT SET")
        PinIsSet = "no"

    try:
        scenarioCount += 1
        if str(PinIsSet).lower() == "yes":
                if mode in ("tooltest1","tooltest2","tooltest3"):
                    util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Implementation: CTAP2.2 authenticatorMakeCredential (0x01) using thirdPartyPayment extension Protocol-{protocol} ****")
                else:
                    util.printcolor(util.YELLOW, f"**** Implementation based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with thirdPartyPayment extension For Protocol-{protocol} ****")
                if mode =="getinfo":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                else: 
                    if mode in("tooltest1","tooltest2","tooltest3","newtestcase","thardpartytestcase3","thardpartytestcase4","thardpartytestcase7","thardpartytestcase8","thardpartytestcase11","thardpartytestcase12","thardpartytestcase15","thardpartytestcase16","thardpartytestcase19","thardpartytestcase20","thardpartytestcase21","thardpartytestcase24","thardpartytestcase25","thardpartytestcase26","thardpartytestcase30","thardpartytestcase31","thardpartytestcase32","thardpartytestcase33","thardpartytestcase34","thardpartytestcase35","thardpartytestcase36","thardpartytestcase39"):
                        if mode =="thardpartytestcase39":
                            response=U2fprocess(mode,protocol,pin)
                            return response

                        #option
                        if mode in("tooltest2","tooltest3","thardpartytestcase4","thardpartytestcase7","thardpartytestcase12","thardpartytestcase15","thardpartytestcase19","thardpartytestcase20","thardpartytestcase21","thardpartytestcase30"):
                            option  = {"rk": False}
                        else:
                            option  = {"rk": True}

                        #extension
                        if mode in("thardpartytestcase7","thardpartytestcase8"):
                            extension={"thirdPartyPayment": False}
                        elif mode in("thardpartytestcase11","thardpartytestcase12","tooltest3"):
                            extension ="null"
                        elif mode in("thardpartytestcase19","thardpartytestcase24"):  
                            credblob=os.urandom(32)   
                            credprotect=0x01                   
                            extension={"thirdPartyPayment": True,
                                    "credBlob": credblob,
                                        "credProtect": credprotect,
                                        "hmac-secret": True,
                                        }
                        elif mode in("thardpartytestcase20","thardpartytestcase25"):  
                            credblob=os.urandom(20)   
                            credprotect=0x02                   
                            extension={"thirdPartyPayment": True,
                                    "credBlob": credblob,
                                        "credProtect": credprotect,
                                        "hmac-secret": False,
                                        }
                        elif mode in("thardpartytestcase21","thardpartytestcase26"):  
                            credblob=os.urandom(10)   
                            credprotect=0x03                  
                            extension={"thirdPartyPayment": True,
                                    "credBlob": credblob,
                                        "credProtect": credprotect,
                                        "hmac-secret": True,
                                        }
                        elif mode =="thardpartytestcase32":
                            extension={"thirdPartyPayment": os.urandom(32)}


                        else:
                            extension={"thirdPartyPayment": True}
                    
                        subcommand=0x05
                        clientDataHash=os.urandom(32)
                        if protocol ==1:
                            pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                        elif protocol ==2 :
                            pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

                        username="sasmita1"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                        if mode in ("thardpartytestcase31","thardpartytestcase32"):
                            if mode =="thardpartytestcase31":
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="12",expected_error_name="CTAP2_ERR_INVALID_CBOR")
                            else:
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                            
                            return response
                        else:
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                        print(response)
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions : {extensions}")
                        if mode =="newtestcase":
                            subcommand=0x05
                            clientDataHash=os.urandom(32)
                            if protocol ==1:
                                pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                            elif protocol ==2 :
                                pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

                            username="sasmita2"
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                            credId,credentialPublicKey=authParasing(response)
                            util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                            util.printcolor(util.YELLOW, f"credId2: {credId}")
                            cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                            util.printcolor(util.YELLOW, f"Extensions : {extensions}")


                        if mode =="thardpartytestcase30":
                            util.ResetCardPower()
                            util.ConnectJavaCard() 
                            util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                            util.run_apdu("80100000010700", "Reset Card PIN","00")
                            response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                            getinforesponse(response)
                            return response

                        clientDataHash, pinAuthToken=prepare_session(mode, pin, protocol)
                        if mode in ("thardpartytestcase19","thardpartytestcase20","thardpartytestcase21","thardpartytestcase24","thardpartytestcase25","thardpartytestcase26"):
                            hmac_secret_ext=hmacextension(protocol)
                            extension={"thirdPartyPayment": True,"credBlob": True,"hmac-secret": hmac_secret_ext}
                        elif mode =="thardpartytestcase33":
                            extension={"thirdPartyPayment": 0}#random value other than boolean


                        else:
                            extension={"thirdPartyPayment": True}
                        apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extension,pinAuthToken,protocol)
                        if mode in ("thardpartytestcase33","thardpartytestcase34","thardpartytestcase35","thardpartytestcase36"):
                            if mode =="thardpartytestcase33":
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02 With pinauthtoken",expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE" )
                            elif mode =="thardpartytestcase35":
                                util.ResetCardPower()
                                util.ConnectJavaCard() 
                                util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                                util.run_apdu("80100000010700", "Reset Card PIN","00")
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02 after Card Reset",expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET" )
                            elif mode =="thardpartytestcase36":
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02 after Card Reset",expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS" )
                    
                            else:
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02 With pinauthtoken",expected_prefix="12",expected_error_name="CTAP2_ERR_INVALID_CBOR" )
                            
                            return response
                        else:
                            response, status = util.run_apdu(apdu, "GetAssertion 0x02 With pinauthtoken",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                        
                        extension=getextension(response)
                        if mode =="newtestcase":
                            response,status=util.run_apdu("80100000010800", "authenticatorGetNextAssertion (0x08)", "00")
                            extension=getextension(response)
                            return extension


                        
                        if mode in("tooltest1","tooltest2","tooltest3"):
                            util.printcolor(util.YELLOW, f"Extension{extension}")
                        else:

                            apdu=credentialpresetornot(credId,rp, clientDataHash,protocol,pin)
                            response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                            decode=parse_get_creds_metadata(response)
                            u2fauthenticate(mode,rp, clientDataHash, credId)
        else:
                util.printcolor(util.YELLOW, f"**** Without clientpin  authenticatorMakeCredential (0x01) Extension thirdPartyPayment CTAP2.2 For Protocol-{protocol}")
                if mode =="getinfowithoutpin":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)   
                else: 
                    if mode in("thardpartytestcase5","thardpartytestcase6","thardpartytestcase9","thardpartytestcase10","thardpartytestcase13","thardpartytestcase14","thardpartytestcase17","thardpartytestcase18","thardpartytestcase22","thardpartytestcase23","thardpartytestcase27","thardpartytestcase28","thardpartytestcase29","thardpartytestcase37","thardpartytestcase38"):
                        if mode =="thardpartytestcase38":
                            response=U2fprocess(mode,protocol,pin)
                            return response
                        

                        #option
                        if mode in("thardpartytestcase6","thardpartytestcase10","thardpartytestcase13","thardpartytestcase18","thardpartytestcase22","thardpartytestcase23","thardpartytestcase29"):
                            option  = {"rk": False}
                        else:
                            option  = {"rk": True}
                        #extension
                        if mode in("thardpartytestcase9","thardpartytestcase10"):
                            extension={"thirdPartyPayment": False}
                        elif mode in("thardpartytestcase13","thardpartytestcase14"):
                            extension ="null"
                        elif mode in("thardpartytestcase22","thardpartytestcase27"):  
                            credblob=os.urandom(32)   
                            credprotect=0x01                   
                            extension={"thirdPartyPayment": True,
                                    "credBlob": credblob,
                                        "credProtect": credprotect,
                                        "hmac-secret": True,
                                        }
                        elif mode in("thardpartytestcase23","thardpartytestcase28"):  
                            credblob=os.urandom(20)   
                            credprotect=0x02                   
                            extension={"thirdPartyPayment": True,
                                    "credBlob": credblob,
                                        "credProtect": credprotect,
                                        "hmac-secret": False,
                                        }
                        elif mode =="thardpartytestcase37":
                            credblob=os.urandom(10)   
                            credprotect=0x03                   
                            extension={"thirdPartyPayment": True,
                                    "credBlob": credblob,
                                        "credProtect": credprotect,
                                        "hmac-secret": True,
                                        }

                        else:
                            extension={"thirdPartyPayment": True}
                        pinAuthToken="null"
                        clientDataHash=os.urandom(32)
                        username="bobsmith"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                        if mode =="thardpartytestcase37":
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                            return response
                        else:
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                    
                        
                        print(response)
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions : {extensions}")
                        if mode =="thardpartytestcase29":
                            util.ResetCardPower()
                            util.ConnectJavaCard() 
                            util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                            util.run_apdu("80100000010700", "Reset Card PIN","00")
                            response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                            getinforesponse(response)
                            return response
        

                        if mode in ("thardpartytestcase22","thardpartytestcase23","thardpartytestcase27","thardpartytestcase28"):
                            hmac_secret_ext=hmacextension(protocol)
                            extension={"thirdPartyPayment": True,"credBlob": True,"hmac-secret": hmac_secret_ext}
                        else:
                            extension={"thirdPartyPayment": True}
                        apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extension,pinAuthToken,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02 Without pinauthtoken",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                        extension=getextension(response)
                        u2fauthenticate(mode,rp, clientDataHash, credId)     
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


                

def U2fprocess(mode,protocol,pin):
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
    apdu = u2f_authenticate_apdu(rpid, challenge, credential_id)
    print("U2F AUTHENTICATE APDU:", apdu)
    # 4. Send AUTHENTICATE APDU
    response, status = util.run_apduu2f(apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    credId= credential_id.hex()
    util.printcolor(util.YELLOW, f"credId: {credId}")
    if mode =="thardpartytestcase39":
        response=authenticationwithpin(mode,challenge, rpid,  credId,protocol,pin)
    else:
        response=authentication(mode,challenge, rpid,  credId,protocol)
    return response

def authenticationwithpin(mode,challenge, rpid,  credId,protocol,pin):
    pinAuthToken="null"
    extension={"thirdPartyPayment": True}
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")            
    
    subcommand=0x05
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand,protocol)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:32]
    mode ="withpinauthparam"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")      
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredId"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    subcommand=0x05
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand,protocol)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:32]          
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredandpinauth"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    return response


def authentication(mode,challenge, rpid,  credId,protocol):
    pinAuthToken="null"
    extension={"thirdPartyPayment": True}
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")            
    
    util.printcolor(util.YELLOW, f"credId: {credId}")
    if protocol==1:
            pinAuthToken=os.urandom(16)
    else:
            pinAuthToken=os.urandom(32)
    mode ="withpinauthparam"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
           
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredId"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredandpinauth"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
    return response

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
def hmacextension(protocol):
    salt1 = os.urandom(32)
    subCommand=0x02
    if protocol==1:
        
        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
        saltEnc = aes256_cbc_encryptp11(shareSecretKey, salt1)
        saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
    else:
        key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
        saltEnc = aes256_cbc_encrypt(shareSecretKey , salt1)
        saltAuth =hmac_sha256(shareSecretKey, saltEnc)[:32]
    hmac_secret_ext = {
                        0x01: key_agreement,
                        0x02:saltEnc,
                        0x03:saltAuth,
                        0X04 :protocol}
    return hmac_secret_ext
    

def getKeyAgreement(protocol,subCommand):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cbor_map = {
        1: protocol,   # pinProtocol
        2: subCommand  # subCommand = getKeyAgreement
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    cardPublickey, status = util.run_apdu(apdu,"Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00")
                                        
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    util.printcolor(util.ORANGE,f"{pubkey}")
    

    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    return  key_agreement, shareSecretKey

def hmac_sha25611(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def aes256_cbc_encryptp11(shared_secret: bytes, data: bytes) -> bytes:
    """
    CTAP2 PIN/UV Protocol 1
    - Key = first 32 bytes of sharedSecret
    - IV  = 16 zero bytes
    - No padding (data must be multiple of 16)
    """

    assert len(data) % 16 == 0, "Data must be multiple of 16 bytes"

    aes_key = shared_secret[:32]  # ✅ FIX

    iv = b'\x00' * 16

    cipher = Cipher(
        algorithms.AES(aes_key),   # ✅ USE 32 BYTES ONLY
        modes.CBC(iv)
    )

    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes256_cbc_encrypt(shared_secret, data):
    assert len(data) % 16 == 0

    aes_key = shared_secret[32:]   # discard first 32 bytes
    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    ).encryptor()

    ct = cipher.update(data) + cipher.finalize()
    return iv + ct

def hmac_sha256(shared_secret, message):
    """
    Use the first 32 bytes of shared_secret as HMAC key.
    """
    hmac_key = shared_secret[:32]  # Only first 32 bytes
    hmac_obj = hmac.new(hmac_key, message, hashlib.sha256)
    return hmac_obj.digest()

def getKeyAgreementp1(protocol,subCommand):

    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cbor_map = {
        1: protocol,   # pinProtocol
        2: subCommand  # subCommand = getKeyAgreement
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.run_apdu(apdu,"Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00")

    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    keyAgreement, sharedSecret = encapsulate_protocol1(peer_key)                                    
    
    return  keyAgreement, sharedSecret

from cryptography.hazmat.primitives.asymmetric import ec
def encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,
        3: -25,
        -1: 1,
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key.get(-2))
    peer_y = bytes2int(peer_cose_key.get(-3))
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()
    return key_agreement, shared_secret


def int2bytes(val, length):
    return val.to_bytes(length, 'big')


def bytes2int(b):
    return int.from_bytes(b, 'big')
    

        



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
    return pinSetAPDU

def createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol):
    if mode =="cmpermission":
        permission=0x04
        cbor_map = {
            1: protocol,                  # pinProtocol = 1
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc ,        # pinHashEnc
            9:permission
            }
    else:

        cbor_map = {
                1: protocol,                  # pinProtocol = 1
                2: subcommand,                  # subCommand = 0x05 (getPINToken)
                3: key_agreement,      # keyAgreement (MAP)
                6: pinHashEnc         # pinHashEnc
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
    Parse CTAP2 GetInfo response and validate extensions.
    Reports:
        - All extensions
        - minPinLength, hmac-secret, credBlob, credProtect
        - forcePINChange
    """

    # Convert hex string to bytes if necessary
    if isinstance(response, str):
        response = bytes.fromhex(response)

    if not response:
        raise ValueError("Empty GetInfo response")

    # ---- Validate CTAP status ----
    status = response[0]
    if status != 0x00:
        raise ValueError(f"CTAP error: 0x{status:02X}")

    cbor_data = response[1:]
    if not cbor_data:
        raise ValueError("Missing CBOR payload")

    # ---- Decode CBOR ----
    decoded = cbor2.loads(cbor_data)
    if not isinstance(decoded, dict):
        raise ValueError("GetInfo response is not a CBOR map")

    # ---- Extensions (0x02) ----
    extensions = decoded.get(0x02, [])
    if extensions:
        util.printcolor(util.GREEN, f"Supported extensions: {extensions}")
    else:
        util.printcolor(util.YELLOW, "No extensions reported")

    # ---- Check each main extension ----
    for ext_name in ["minPinLength", "hmac-secret", "credBlob", "credProtect"]:
        if ext_name in extensions:
            util.printcolor(util.GREEN, f"{ext_name} extension is supported")
        else:
            util.printcolor(util.YELLOW, f"{ext_name} extension not supported")

    # ---- Validate minPINLength (0x0D) ----
    min_pin_length = decoded.get(0x0D)
    if min_pin_length is not None:
        util.printcolor(util.GREEN, f"minPINLength = {min_pin_length}")
    else:
        util.printcolor(util.YELLOW, "minPINLength (0x0D) not present")

    # ---- forcePINChange (0x0C) ----
    force_pin_change = decoded.get(0x0C, False)
    util.printcolor(util.GREEN, f"forcePINChange = {force_pin_change}")

    # ---- Pretty Print full response ----
    print("\nDecoded GetInfo response:")
    pprint.pprint(decoded, width=120)

    return decoded

def createCBORmakeCred(mode,clientDataHash, rp, user,pinAuthToken,protocol,extension,option):
    
   

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
    

   

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_option        = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()
    if mode in ("thardpartytestcase13","thardpartytestcase14"):
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "09"+ cbor_protocol 

    elif pinAuthToken=="null":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "09"+ cbor_protocol 
    elif extension =="null":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol
    elif mode =="thardpartytestcase31" :
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
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
    #if byte_len <=256:
    if byte_len < 256:
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
    
def createCBORmakeAssertion(mode,cryptohash, rp,  credId,extensions,pinAuthToken,protocol):
    if mode =="thardpartytestcase36":
        allow_list = [{
            "id": os.urandom(96),
            "type": "public-key"
        
        }]
    else:

        allow_list = [{
                "id": bytes.fromhex(credId),
                "type": "public-key"
            
            }]
    if mode =="hmac_secret_mccase36":
        option= {"up":False}
    else:

        option= {"up":True}


    
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_extensions     = cbor2.dumps(extensions).hex().upper()      # 0x04: extensions
    cbor_option       = cbor2.dumps(option).hex().upper() 
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    cbor_protocol       = cbor2.dumps(protocol).hex().upper()        # 0x07: pinProtocol = 2
    if mode in("thardpartytestcase15","thardpartytestcase16"):
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol
    elif mode in("thardpartytestcase17","thardpartytestcase18"):
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol
    elif mode =="withoutcredId":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_extensions
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol
    elif mode =="withoutcredandpinauth":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_extensions
        dataCBOR += "05" + cbor_option 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol


    elif pinAuthToken=="null":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol
    elif pinAuthToken =="Null":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol

    elif mode =="thardpartytestcase36":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol
    elif mode =="thardpartytestcase34":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol
    elif mode =="withpinauthparam":
        dataCBOR = "A7"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol
    elif mode =="newtestcase":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        #dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol



    else:
        dataCBOR = "A7"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol


    length = (len(dataCBOR) >> 1) +1    #have to add the 02 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Final payload = 01 prefix + dataCBOR
    full_data = "02" + dataCBOR
    byte_len = len(full_data) // 2
    

    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len < 256:
        lc = format(byte_len, '02X')
        return "80108000" + lc + full_data  # single string

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
            p1 = "80"
            p2 = "00"
            lc = format(len(chunk) // 2, '02X')
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
from io import BytesIO


def parse_credential_pubkey_and_extensions(hex_data):
    raw = bytes.fromhex(hex_data)
    bio = BytesIO(raw)
    decoder = cbor2.CBORDecoder(bio)

    # First CBOR object (always present)
    cose_key = decoder.decode()

    # Check if more CBOR data exists (extensions are optional)
    remaining = bio.read()

    if remaining:
        bio_ext = BytesIO(remaining)
        decoder_ext = cbor2.CBORDecoder(bio_ext)
        extensions = decoder_ext.decode()
    else:
        extensions = None

    return cose_key, extensions
def prepare_session(mode, pin, protocol):
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")

    subcommand = 0x05
    
    clientDataHash = os.urandom(32)
    if protocol == 1:
        pinToken = getPINtokenp1(mode, pin, subcommand, protocol)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]

    else:
        pinToken = getPINtokenp2(mode, pin, subcommand, protocol)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    return clientDataHash, pinAuthToken
def getextension(response, expect_credblob=False, expect_hmac=False, expect_thirdparty=False):
    """
    expect_credblob:
        True  -> credBlob must be returned
        False -> credBlob must NOT be returned

    expect_hmac:
        True  -> hmac-secret must be returned
        False -> hmac-secret must NOT be returned

    expect_thirdparty:
        True  -> thirdPartyPayment must be returned
        False -> thirdPartyPayment must NOT be returned
    """

    authdata = parse_getassertion_response(response)
    parsed_authdata = parse_authdatagetassertion(authdata)

    extensions = parsed_authdata.get("extensions")

    # -------------------------------------------------
    # Case 1: No extensions field
    # -------------------------------------------------
    if extensions is None:
        util.printcolor(util.YELLOW, "No extensions field present")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but none returned!")

        if expect_hmac:
            util.printcolor(util.RED, "Expected hmac-secret but none returned!")

        if expect_thirdparty:
            util.printcolor(util.RED, "Expected thirdPartyPayment but none returned!")

        return None

    # -------------------------------------------------
    # Case 2: Extensions map exists but empty
    # -------------------------------------------------
    if isinstance(extensions, dict) and len(extensions) == 0:
        util.printcolor(util.YELLOW, "Extensions map present but empty")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but extensions empty!")

        if expect_hmac:
            util.printcolor(util.RED, "Expected hmac-secret but extensions empty!")

        if expect_thirdparty:
            util.printcolor(util.RED, "Expected thirdPartyPayment but extensions empty!")

        return extensions

    # -------------------------------------------------
    # Print full extension map (DEBUG - very useful)
    # -------------------------------------------------
    util.printcolor(util.CYAN, f"Returned extensions map: {extensions}")

    # =================================================
    # credBlob handling
    # =================================================
    if "credBlob" in extensions:
        value = extensions["credBlob"]

        if isinstance(value, bytes):
            if len(value) == 0:
                util.printcolor(util.YELLOW, "credBlob: <empty bytes>")
            else:
                util.printcolor(util.GREEN, f"credBlob: {value.hex()}")
        else:
            util.printcolor(util.YELLOW, f"credBlob (non-bytes): {value}")
    else:
        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but not returned!")

    # =================================================
    # hmac-secret handling
    # =================================================
    if "hmac-secret" in extensions:
        hmac_value = extensions["hmac-secret"]

        if isinstance(hmac_value, bytes):
            util.printcolor(
                util.GREEN,
                f"hmac-secret output ({len(hmac_value)} bytes): {hmac_value.hex()}"
            )
        else:
            util.printcolor(
                util.RED,
                f"hmac-secret returned non-bytes value: {hmac_value}"
            )
    # else:
    #     if expect_hmac:
    #         util.printcolor(util.RED, "Expected hmac-secret but not returned!")
    #     else:
    #         util.printcolor(util.YELLOW, "hmac-secret: NOT PRESENT")

    # =================================================
    # thirdPartyPayment handling 
    # =================================================
    if "thirdPartyPayment" in extensions:
        tpp_value = extensions["thirdPartyPayment"]

        if isinstance(tpp_value, bool):
            util.printcolor(util.GREEN, f"thirdPartyPayment: {tpp_value}")
        else:
            util.printcolor(util.YELLOW, f"thirdPartyPayment (non-bool): {tpp_value}")
    else:
        if expect_thirdparty:
            util.printcolor(util.RED, "Expected thirdPartyPayment but not returned!")
        else:
            util.printcolor(util.YELLOW, "thirdPartyPayment: NOT PRESENT")

    return extensions
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
def credentialpresetornot(credId,rp, clientDataHash,protocol,pin):
    subcommand=0x09
    mode="cmpermission"
    subCommand = 0x01  # getCredsMetadata
    if protocol ==1:

        pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
    return apdu
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

def u2fauthenticate(mode,rp, clientDataHash, credId):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    #clientDataHash1=os.urandom(32)
    apdu = u2f_authenticate_apdu(rp, clientDataHash, credId)
    print("U2F AUTHENTICATE APDU:", apdu)
                    # 4. Send AUTHENTICATE APDU
    if mode in ("thardpartytestcase4","thardpartytestcase6","thardpartytestcase7","thardpartytestcase10","thardpartytestcase12","thardpartytestcase13","thardpartytestcase15","thardpartytestcase18","thardpartytestcase19","thardpartytestcase20","thardpartytestcase22","thardpartytestcase23"):
       response, status = util.run_apdu(
                    apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
    else:
        response, status = util.run_apdu(apdu,"U2F AUTHENTICATE ",expected_error_name="6A80")


def u2f_authenticate_apdu(rpid: str, challenge: bytes, credential_id):

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