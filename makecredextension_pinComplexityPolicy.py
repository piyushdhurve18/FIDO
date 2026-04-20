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
MODE = ""
BLOCKLIST_PIN = [
    "123456",
    "123123",
    "654321",
    "123321",
    "112233",
    "121212",
    "123456789",
    "password",
    "qwerty",
    "12345678",
    "1234567",
    "520520",
    "123654",
    "1234567890",
    "159753",
    "qwerty123",
    "abc123",
    "password1",
    "iloveyou",
    "1q2w3e4r",
]

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - CRED PROTECT)"
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
       
        "forcepintruet1":"""Test started: P-1:
P-1 Create a new credential with extensions containing pinComplexityPolicy set to True, and check that authenticator succeeds Check that MakeCredential response extensions contain pinComplexityPolicy extension, and check that it is of type boolean and set to true """,

"forcepintruet2":"""Test started: P-2:
P-2 Create a new credential with unauthorized RP with extensions containing pinComplexityPolicy set to True, Check that MakeCredential response ignores the extension and does not return any authenticator extension output""",



        "getinfo":"""Test started: P-3:
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.A PIN is configured on the authenticator.

Test Description:
Steps:
Send a valid authenticatorGetInfo (0x04) request.The authenticator returns CTAP2_SUCCESS.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains pinComplexityPolicy in the extensions list.
3.The response includes the pinComplexityPolicy field, and its value matches the default.""",

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
2.The response contains pinComplexityPolicy in the extensions list.
3.The response includes the pinComplexityPolicy field, and its value matches the default .""",

"pincomplexitytrue":"""Test started: P-5:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error .
""",

"pincomplexitytruerkfalse":"""Test started: P-6:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  nondiscoverable (rk=False) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = false.Include the following extension in the request:
"pinComplexityPolicy": true

The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP2_ERR_SUCCESS .
""",


"Authenticatorreset":"""Test started: P-7:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true
Step 3:( Reset the Authenticator)
Send the authenticatorReset (0x07) command to the authenticator.
Expected Result
The authenticator returns CTAP2_SUCCESS (0x00).
All credentials and PIN configurations are cleared.
Step 4:( Verify the PIN Complexity Policy After Rese)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
The response includes the extensions field (0x02).
The "pinComplexityPolicy" extension is present in the list of supported extensions.
The pinComplexityPolicy value is false, indicating that the policy has been reset to its default state.
Step 4:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is Failed.
""",

"UnauthorizedRpId":"""Test started: P-8:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator supports the pinComplexityPolicy extension.
5.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
6.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.

Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true

The rp.id must be part of the unauthorized RP ID list (unauthorized.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns no  "extensions" field .""",


"CheckPinComplexity":"""Test started: P-9:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:(set client pin):
Send a ClientPIN command to set a new complex PIN that satisfies the PIN complexity policy.
Example complex PIN:
Abc@1234
Expected Result:
1.The authenticator validates the PIN complexity requirements.
2.The authenticator successfully sets the new complex PIN.
3.The authenticator returns CTAP2_SUCCESS (0x00).
4.The authenticator allows User Verification using the configured PIN

Step 4: Retrieve PIN Token
Send the ClientPIN command with subCommand getPinUvAuthToken (0x05) using the same PIN configured in Step 3.
Expected Result:
1.The authenticator verifies the provided PIN.
2.The authenticator returns CTAP2_SUCCESS (0x00).
3.The authenticator returns a valid pinUvAuthToken in the response.
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is Failed,.
""",

"minimumpinlength":"""Test started: P-10:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
5.The authenticator supports the pinComplexityPolicy extension.
4.The authenticator is configured without PIN
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.

Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.

Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true

Step 3:(Set Minimum PIN Length)
If the authenticator supports setMinPINLength, send an authenticatorConfig (0x0D) command with setMinPINLength (0x03) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 4: (Verify the Minimum PIN Length)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
The minPINLength value reflects the updated PIN length.
The forcePINChange option is set to true.

Step 5: (Set PIN for Minimum pin length)
Send the setPin (0x03) command to the authenticator.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
""",

"minimumpinlengthwithpin":"""Test started: P-11:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
5.The authenticator supports the pinComplexityPolicy extension.
4.The authenticator is configured with a PIN
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.



Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.

Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true

Step 3:(Set Minimum PIN Length)
If the authenticator supports setMinPINLength, send an authenticatorConfig (0x0D) command with setMinPINLength (0x03) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
Step 4: (Verify the Minimum PIN Length)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
The minPINLength value reflects the updated PIN length.
The forcePINChange option is set to true.

Step 5: (Change PIN to Satisfy Updated Policy)
If forcePINChange = true, send a ClientPIN (0x06) command using the Change PIN subcommand (0x04).
Provide:
	.The current PIN
	.A new PIN that satisfies the updated minimum PIN length and complexity requirements.
Example complex PIN:Abc@12345
Expected Result:
1.The authenticator verifies the current PIN.
2.The authenticator validates that the new PIN satisfies the updated minimum length and complexity policy.
3.The PIN is successfully updated.
4.The authenticator returns CTAP2_SUCCESS (0x00).
Step 6:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is Failed.

""",
"extensionminimumpinlength":"""Test started: P-12:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.

Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true
Step 3:(Verify the Minimum PIN Length Extension)
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true  Use an authorized RP.
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_value>
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is failed.
""",
"normalpinset":"""Test started: P-13:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list.
4.The authenticator is configured with a PIN.
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:( Reset the Authenticator)
Send the authenticatorReset (0x07) command to the authenticator.
Expected Result
The authenticator returns CTAP2_SUCCESS (0x00).
All credentials and PIN configurations are cleared.
Step 4:( Verify the PIN Complexity Policy After Reset)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
The response includes the extensions field (0x02).
The "pinComplexityPolicy" extension is present in the list of supported extensions.
The pinComplexityPolicy value is false, indicating that the policy has been reset to its default state.
Step 5:(Set Client PIN (Normal PIN)):
Send a ClientPIN (0x06) command using the setPIN subCommand (0x03) to configure a new PIN.
Example complex PIN:
112233
Expected Result:
1.The authenticator validates the PIN complexity requirements.
2.The authenticator successfully sets the new complex PIN.
3.The authenticator returns CTAP2_SUCCESS (0x00).
4.The authenticator allows User Verification using the configured PIN
Step 6:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is failed.
""",
"unautherizedrplist":"""Test started: P-14:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.

Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true
Step 3:(Verify the Minimum PIN Length Extension)
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true  not in  authorized RP.
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is failed.
""",
"nondiscoverable":"""Test started: P-15:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  nondiscoverable (rk=false) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = false.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.

Step 2: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true
Step 3:(Verify the Minimum PIN Length Extension)
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true  not in  authorized RP.
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successfull.
""",


"normalpinsetafterpincomplexity":"""Test started: P-16:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:(Change PIN (Normal PIN)):
Send a ClientPIN (0x06) command using the setPIN subCommand (0x03) to configure a new PIN.
Example complex PIN:
112233
Expected Result:
1.The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
""",
"randompin":"""Test started: P-17:

Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:(Change PIN (Random PIN)):
Send a ClientPIN (0x06) command using the Changepin subCommand (0x04) to configure a new PIN.Provide a random normal PIN
Expected Result:
1.The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
""",
"serialpin":"""Test started: P-18:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:(Change PIN (Normal PIN)):
Send a ClientPIN (0x06) command using the Changepin subCommand (0x04) to configure a new PIN.Provide a serial/weak PIN, for example:111111
Expected Result:
1.The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
""",
"pinnotsetafterreset":"""Test started: P-19:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list.
4.Authenticator have a pin
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:( Reset the Authenticator)
Send the authenticatorReset (0x07) command to the authenticator.
Expected Result
The authenticator returns CTAP2_SUCCESS (0x00).
All credentials and PIN configurations are cleared.
Step 4:( Verify the PIN Complexity Policy After Rese)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
The authenticator returns .
The response includes the extensions field (0x02).
The "pinComplexityPolicy" extension is present in the list of supported extensions.
The pinComplexityPolicy value is false, indicating that the policy has been reset to its default state.
Step 5:(Change PIN After Reset):
Send ClientPIN (0x06) command using Change PIN subCommand (0x04)using Normal pin.
Example Normal PIN:
112233
Expected Result:
1.The authenticator return CTAP2_ERR_PIN_NOT_SET.
""",
"clientchangepin":"""Test started: P-20:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list.
4.Authenticator have a pin
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 2: Verify the PIN Complexity Policy
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
Step 3:(Change PIN (Weak / Serial PIN):
Send a ClientPIN (0x06) command using the Change PIN subCommand (0x04).
Provide the current PIN and attempt to change it to a serial/weak PIN, for example:111111
Expected Result:
1.The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
""",
"cborwrong":"""Test started: P-21:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with a PIN
5.The authenticator supports the pinComplexityPolicy extension.
6.The authenticator supports  discoverable (rk=true) credentials with pinComplexityPolicy.
7.The RP ID (example.com) is present in the minPinLengthRPIDs authorized list.


Step 1: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": random type

The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
""",
"u2fregistationwithoupin":"""Test started: P-22:
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


"u2fregistationwithpin":"""Test started: P-23:
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


"checkSetPINBlockListPINs":"""Test started: P-24:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured without PIN
5.The authenticator supports the pinComplexityPolicy extension.
6. Enable pinComplexityPolicy and verify pinComplexityPolicy is set to True.

Step 1: Set a BlockList PINs  using setPin(0x03) Command and Everytime authenticator must return 0x37(CTAP2_ERR_PIN_POLICY_VIOLATION).
""",

"checkChangePINBlockListPINs":"""Test started: P-25:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes " pinComplexityPolicy" in the extensions list..
4.The authenticator is configured with PIN
5.The authenticator supports the pinComplexityPolicy extension.
6. Enable pinComplexityPolicy and verify pinComplexityPolicy is set to True.

Step 1: Change the existing PIN with BlockList PINs  using changePin(0x04) Command and Everytime authenticator must return 0x37(CTAP2_ERR_PIN_POLICY_VIOLATION).
""",





    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])
    util.printcolor(util.YELLOW, "****  Precondition authenticatorMakeCredential (0x01) Extension pinComplexityPolicy CTAP2.2 ****")
    
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    #util.run_apdu("80100000010700", "Reset Card PIN","00")
    util.ResetCardPower()
    util.ConnectJavaCard()   
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN")
    
    global MODE
    MODE = mode

    try:
        scenarioCount += 1
        if str(pinsetrequried).lower() == "yes":
            if mode =="forcepintruet2":
                subCommandParams = {0x02: ["unautherized.com"]}
            else:
                subCommandParams = {0x02: ["example.com"], 0x04: True}

            subcommand=0x03
            subcommand_pintoken=0x09
            subCommand_setmin = 0x03
            permission = 0x20
            rpid=None
            
            if protocol == 1:
                clentpinsetp1(pin, protocol, subcommand)
                PinIsSet = "yes"
                pinToken=getPINtokenp1(mode,pin,subcommand_pintoken,protocol,permission,rpid)
                if mode != "getinfo":
                    apdu=minPinLengthRPIDs(pinToken, subCommand_setmin,protocol,subCommandParams)
                    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 

            
            elif protocol ==2:           
                clentpinsetp2(pin, protocol, subcommand)
                PinIsSet = "yes"           
                pinToken=getPINtokenp2(mode,pin,subcommand_pintoken,protocol,permission,rpid)
                if mode != "getinfo":
                    apdu=minPinLengthRPIDs(pinToken, subCommand_setmin,protocol,subCommandParams)
                    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
            
            else:
                print("Perform U2F Registation")

            
            
        else:
            util.printcolor(util.YELLOW, "PIN  IS NOT SET")
            PinIsSet = "no"

        if str(PinIsSet).lower() == "yes":
                    util.printcolor(util.YELLOW, f"****  authenticatorMakeCredential (0x01) Extension PIN Complexity CTAP2.2 For Protocol-{protocol}")
                    if mode =="getinfo":
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        getinforesponse(response)

                    elif mode == "checkChangePINBlockListPINs":
                        subcommand=0x04
                        pinRetryStatic = 0
                        pinRetryDynamic = 0
                        flag = True
                        for NEWPIN in BLOCKLIST_PIN:
                            newpin = NEWPIN
                            # newpin = "qwerty"
                            util.printcolor(util.YELLOW, f"Old PIN: {pin}; New PIN: {newpin}")
                            if protocol == 1:
                                    apdu=changepinp1(pin,newpin,protocol,subcommand)
                            elif protocol == 2:
                                    apdu=changepinp2(pin,newpin,protocol,subcommand)   
                                                            
                            response,status=util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION")
                            if protocol == 1:
                                pinRetryDynamic = getPinRetryProtocol1()
                            elif protocol == 2:
                                pinRetryDynamic = getPinRetryProtocol2()
                                
                            if flag == True:
                                pinRetryStatic = pinRetryDynamic
                                flag = False

                            if pinRetryStatic == pinRetryDynamic:
                                util.printcolor(util.GREEN, f"Current Pin Retry Count {pinRetryDynamic} is Same as Previous {pinRetryStatic}")
                            else:
                                util.printcolor(util.RED, f"Current Pin Retry Count {pinRetryDynamic} is Not same as Previous {pinRetryStatic}")
                                exit(0)
                            
                    else:
                        if mode in ("forcepintruet1","forcepintruet2","pincomplexitytrue","pincomplexitytruerkfalse","Authenticatorreset","UnauthorizedRpId","CheckPinComplexity","minimumpinlengthwithpin","extensionminimumpinlength","normalpinset","unautherizedrplist","nondiscoverable","normalpinsetafterpincomplexity","randompin","serialpin","pinnotsetafterreset","clientchangepin","cborwrong","u2fregistationwithpin"):
                            if mode =="u2fregistationwithpin":

                                response=U2fprocess(mode,protocol,pin)
                                return response
                            if mode in("pincomplexitytruerkfalse","nondiscoverable"):
                                option  = {"rk": False}
                            else:
                                option  = {"rk": True}
                            if mode =="cborwrong":
                                extension={"pinComplexityPolicy": os.urandom(10)}
                            else:
                                extension={"pinComplexityPolicy": True}
                            subcommand=0x09
                            permission=0x03
                            rpid="example.com"
                            clientDataHash=os.urandom(32)
                            if protocol ==1:
                                pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission,rpid)
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                            elif protocol ==2 :
                                pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission,rpid)
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rpid, username,  pinAuthToken,protocol,extension,option)
                            if mode =="cborwrong":
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                                return response
                            else:
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                            credId,credentialPublicKey=authParasing(response)
                            util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                            util.printcolor(util.YELLOW, f"credId: {credId}")
                            cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                            util.printcolor(util.YELLOW, f"Extensions : {extensions}")
                            if mode in ("forcepintruet1","forcepintruet2","UnauthorizedRpId"):
                                return extensions

                            response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                            pinpolicy=getinforesponse(response)
                            if mode =="pinnotsetafterreset":
                                util.ResetCardPower()
                                util.ConnectJavaCard()   
                                util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                                util.run_apdu("80100000010700", "Reset Card PIN","00")
                                response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                                pinpolicy=getinforesponse(response)
                                

                            if mode in ("normalpinsetafterpincomplexity","randompin","serialpin","pinnotsetafterreset","clientchangepin"):
                                if mode=="normalpinsetafterpincomplexity":
                                    newpin="123456"
                                elif mode =="randompin":
                                    newpin="123455"
                                elif mode =="serialpin":
                                    newpin="111111"
                                else:
                                    newpin="12345678"
                                subcommand=0x04
                                if protocol == 1:
                                    apdu=changepinp1(pin,newpin,protocol,subcommand)   
                                elif protocol ==2:
                                    apdu=changepinp2(pin,newpin,protocol,subcommand)

                                if mode =="pinnotsetafterreset":                                
                                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                                elif mode == "randompin":
                                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP2_SUCCESS")
                                else:
                                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION")
                                print("newpin",newpin)
                                return response
                                
                
                            if mode in ("CheckPinComplexity","minimumpinlengthwithpin"):
                                subcommand=0x04
                                newpin="Abc@12345"
                                if protocol == 1:
                                    apdu=changepinp1(pin,newpin,protocol,subcommand)   
                                elif protocol ==2:
                                    apdu=changepinp2(pin,newpin,protocol,subcommand)
                                util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                                pin = newpin
                            if mode =="minimumpinlengthwithpin": 
                                pin=minimumpinprocess(mode,pin,protocol) 
                            if mode in ("extensionminimumpinlength","unautherizedrplist","nondiscoverable") :
                                if mode in ("unautherizedrplist","nondiscoverable"):
                                    mode="unautherized"
                                else:
                                    print("autherizedrp")
                                
                                extensions=minimumextension(mode,pin,protocol)
                                util.printcolor(util.YELLOW, f"Extensions : {extensions}")
                                
                            if mode =="normalpinset":
                                pin="123456"
                                resetprocess(protocol,pin)
                            
    
                            apdu=credentialpresetornot(credId,rpid, clientDataHash,protocol,pin)
                            response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                            decode=parse_get_creds_metadata(response)
                            u2fauthenticate(mode,rpid, clientDataHash, credId)


        else:
            util.printcolor(util.YELLOW, f"**** Without clientpin  authenticatorMakeCredential (0x01) Extension pinComplexityPolicy CTAP2.2 For Protocol-{protocol}")
            if mode =="getinfowithoutpin":
                response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                getinforesponse(response) 
            else:
                if mode in("minimumpinlength","randompin","u2fregistationwithoupin","checkSetPINBlockListPINs"):
                    if mode =="u2fregistationwithoupin":
                        response=U2fprocess(mode,protocol,pin)
                        return response
                    
                    if mode == "minimumpinlength" or mode == "checkSetPINBlockListPINs":
                        subCommand = 0x03
                        subCommandParams = {0x02: ["example.com"], 0x04: True}
                        apdu = minPinLengthRPIDswithoutpin(subCommand,protocol,subCommandParams)
                        response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : subcommand minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        pinpolicy=getinforesponse(response)
                        if mode == "checkSetPINBlockListPINs":
                            subcommand = 0x03
                            for PIN in BLOCKLIST_PIN:
                                pin = PIN
                                if protocol == 1:
                                        response=clentpinsetp1(pin,protocol,subcommand)   
                                elif protocol ==2:
                                        response=clentpinsetp2(pin,protocol,subcommand)
                            return response
                    option  = {"rk": True}
                    extension={"pinComplexityPolicy": True}
                    subcommand=0x09
                    permission=0x03
                    rpid="example.com"
                    clientDataHash=os.urandom(32)
                    pinAuthToken ="null"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rpid, username,  pinAuthToken,protocol,extension,option)
                
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                    credId,credentialPublicKey=authParasing(response)
                    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions : {extensions}")
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinpolicy=getinforesponse(response)
                    subcommand=0x09
                    permission=0x20
                    rpid="example.com"
                    clientDataHash=os.urandom(32)
                    subCommand = 0x03
                    subCommandParams = {0x01 : 10} 
                    apdu = minPinLengthRPIDswithoutpin(subCommand,protocol,subCommandParams)
                    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : subcommand minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    pinpolicy=getinforesponse(response)
                    subcommand= 0x03
                    pin="8877665544"
                    if protocol==1:                    
                        clentpinsetp1(pin, protocol, subcommand)
                    else:
                        clentpinsetp2(pin, protocol, subcommand)
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
    if mode =="u2fregistationwithpin":
        response=authenticationwithpin(mode,challenge, rpid,  credId,protocol,pin)
    else:
        response=authentication(mode,challenge, rpid,  credId,protocol)
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
def authenticationwithpin(mode,challenge, rpid,  credId,protocol,pin):
    pinAuthToken="null"
    extension={"thirdPartyPayment": True}
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")            
    mode="withoutpermission"
    subcommand=0x03
    subcommand_pintoken=0x05
    subCommand_setmin = 0x03
    permission = 0x20
    rpid=None
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand_pintoken,protocol,permission,rpid)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand_pintoken,protocol,permission,rpid)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:32]
    
    mode ="withpinauthparam"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")      
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredId"
    
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    subcommand=0x05
    mode="withoutpermission"
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand_pintoken,protocol,permission,rpid)              
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand_pintoken,protocol,permission,rpid)               
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:32]          
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredandpinauth"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    return response

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
        rp="example.com"
        cbor_rp            = cbor2.dumps(rp).hex().upper()
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_extensions
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol
    elif mode =="withoutcredandpinauth":
        rp="example.com"
        cbor_rp            = cbor2.dumps(rp).hex().upper()
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
        rp="example.com"
        cbor_rp            = cbor2.dumps(rp).hex().upper()
        dataCBOR = "A7"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
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
                        
def resetprocess(protocol,pin):
    util.ResetCardPower()
    util.ConnectJavaCard()   
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN","00")
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    pinpolicy=getinforesponse(response)
    subcommand=0x03
    if protocol==1:
        clentpinsetp1(pin, protocol, subcommand)
    else:
        clentpinsetp2(pin, protocol, subcommand)
    
    
def minimumextension(mode,pin,protocol):
    if mode =="unautherized":
        rpid="unautherized.com"
    else:
        rpid="example.com"

    option  = {"rk": False}
    extension={"minPinLength": True}
    subcommand=0x09
    permission=0x03
    
    clientDataHash=os.urandom(32)
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission,rpid)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    elif protocol ==2 :
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission,rpid)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rpid, username,  pinAuthToken,protocol,extension,option)
    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
    credId,credentialPublicKey=authParasing(response)
    util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
    util.printcolor(util.YELLOW, f"credId: {credId}")
    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
    return extensions

def minimumpinprocess(mode,pin,protocol):
    subcommand_pintoken=0x09
    permission=0x20
    rpid="example.com"
    subCommand_setmin = 0x03
    subCommandParams = {0x01 : 10} 
    if protocol==1:
        pinToken=getPINtokenp1(mode,pin,subcommand_pintoken,protocol,permission,rpid)
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand_pintoken,protocol,permission,rpid)
    apdu=minPinLengthRPIDs(pinToken, subCommand_setmin,protocol,subCommandParams)
    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : subcommand minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    pin="Abc@12345"
    subcommand=0x04
    newpin="Abc@123487"
    if protocol == 1:
        apdu=changepinp1(pin,newpin,protocol,subcommand)   
    elif protocol ==2:
        apdu=changepinp2(pin,newpin,protocol,subcommand)
    util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
    pin = newpin
    return pin

def minPinLengthRPIDswithoutpin(subCommand,protocol,subCommandParams):

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: protocol               # pinUvAuthProtocol = 2
        
    }
    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu

def changepinp1(oldpin,newpin,protocol,subcommand):
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocol1(peer_key)
    current_pin_hash = util.hashlib.sha256(oldpin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, current_pin_hash)
    padded_new_pin = util.pad_pin(newpin)
    newPinEnc = util.aes256_cbc_encryptP1(shared_secret, padded_new_pin)
   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = util.hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]
    apdu = createCBORchangePIN(pinHashEnc, newPinEnc, pinAuth,key_agreement,protocol,subcommand)
    return apdu
           
def changepinp2(oldpin,newpin,protocol,subcommand):
    cardPublicKeyHex, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])
    oldPinHash = util.sha256(oldpin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)
    newPinPadded = util.pad_pin(newpin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)
    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]
    apdu = createCBORchangePIN(pinHashEnc, newPinEnc, pinAuth,key_agreement,protocol,subcommand)
    return apdu

def getPinRetryProtocol2():
        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        pinRetryCount = getRetryCountInInteger(response)
        util.printcolor(util.YELLOW, f"Current PIN Retry Count : {pinRetryCount}")
        return pinRetryCount


def getPinRetryProtocol1():
        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        pinRetryCount = getRetryCountInInteger(response)
        util.printcolor(util.YELLOW, f"Current PIN Retry Count : {pinRetryCount}")
        return pinRetryCount


def getRetryCountInInteger(response):
    last_byte = response[-2:] 
    value = int(last_byte, 16)
    return value

def createCBORchangePIN(pinHashEnc, newPINenc, pinAuth, keyAgreement,protocol,subcommand):
    """
    Constructs a CBOR-encoded APDU command for ClientPIN ChangePIN (subCommand = 0x04)
    """
    cbor_map = {
        1: protocol,               # pinProtocol 
        2: subcommand,               # subCommand = 0x04 (change PIN)
        3: keyAgreement,    # keyAgreement (MAP)
        4: pinAuth,         # pinAuth (first 16 bytes of HMAC for p1 32byte for p2)
        5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
        6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
    }

    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    return apdu
def minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams):
    print("subCommandParams",subCommandParams)
    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    if protocol ==1:
        # Message: 32x0xFF || 0x0D || subCommand
        message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
        print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

        # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
        pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
        print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
    else:
    
    # Message: 32x0xFF || 0x0D || subCommand
        message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
        print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

        # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
        pinUvAuthParam = util.hmac_sha256(pinToken, message)
        print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")


    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02: subCommandParams,
        0x03: protocol,               # pinUvAuthProtocol = 2,1
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
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
    if MODE == "checkSetPINBlockListPINs":
        response, status = util.run_apdu(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", expected_prefix="37", expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION") 
    else:
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
    if MODE == "checkSetPINBlockListPINs":
        response, status = util.run_apdu(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", expected_prefix="37", expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION") 
    else:
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
           

def getPINtokenp1(mode,pin,subcommand,protocol,permission,rpid):
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
    apdu=createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol,permission,rpid)
    return apdu

def getPINtokenp2(mode,curpin,subcommand,protocol,permission,rpid):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    response, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00")
    cbor_bytes    = binascii.unhexlify(response[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = response[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPinToken(mode,key_agreement,pinHashEnc,shareSecretKey,subcommand,protocol,permission,rpid)
    return pinSetAPDU

def createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol,permission,rpid):
    print("rpid--->",rpid)
    if rpid=="example.com":
        cbor_map = {
            1: protocol,                  # pinProtocol = 1,2
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc ,        # pinHashEnc
            9:permission,
            10:rpid
            }
    elif mode =="unautherized":
         cbor_map = {
            1: protocol,                  # pinProtocol = 1,2
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc ,        # pinHashEnc
            9:permission,
            10:rpid
            }
    elif mode =="withoutpermission":
        cbor_map = {
                1: protocol,                  # pinProtocol = 1,2
                2: subcommand,                  # subCommand = 0x05 (getPINToken)
                3: key_agreement,      # keyAgreement (MAP)
                6: pinHashEnc ,        # pinHashEnc
        }
        

    else:
    
        cbor_map = {
                1: protocol,                  # pinProtocol = 1,2
                2: subcommand,                  # subCommand = 0x05 (getPINToken)
                3: key_agreement,      # keyAgreement (MAP)
                6: pinHashEnc ,        # pinHashEnc
                9:permission
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



import cbor2
import pprint


import cbor2
import pprint
import util


def getinforesponse(response):
    """
    Parse CTAP2 GetInfo response and validate extensions.

    Reports:
        - Supported extensions
        - minPinLength, hmac-secret, credBlob, credProtect, pinComplexityPolicy
        - minPINLength value
        - forcePINChange
        - pinComplexityPolicy value
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

    # --------------------------------
    # Extensions (0x02)
    # --------------------------------
    extensions = decoded.get(0x02, [])

    if extensions:
        util.printcolor(util.GREEN, f"Supported extensions: {extensions}")
    else:
        util.printcolor(util.YELLOW, "No extensions reported")

    # --------------------------------
    # Check important extensions
    # --------------------------------
    important_ext = [
        "minPinLength",
        "hmac-secret",
        "credBlob",
        "credProtect",
        "pinComplexityPolicy"
    ]

    for ext in important_ext:
        if ext in extensions:
            util.printcolor(util.GREEN, f"{ext} extension is supported")
        else:
            util.printcolor(util.YELLOW, f"{ext} extension not supported")

    # --------------------------------
    # minPINLength (0x0D)
    # --------------------------------
    min_pin_length = decoded.get(0x0D)

    if min_pin_length is not None:
        util.printcolor(util.GREEN, f"minPINLength = {min_pin_length}")
    else:
        util.printcolor(util.YELLOW, "minPINLength not present")

    # --------------------------------
    # forcePINChange (0x0C)
    # --------------------------------
    force_pin_change = decoded.get(0x0C, False)

    util.printcolor(util.GREEN, f"forcePINChange = {force_pin_change}")

    # --------------------------------
    # pinComplexityPolicy (0x1B / 27)
    # --------------------------------
    pin_complexity_policy = decoded.get(27)

    if pin_complexity_policy is not None:
        util.printcolor(util.GREEN, f"pinComplexityPolicy = {pin_complexity_policy}")
    else:
        util.printcolor(util.YELLOW, "pinComplexityPolicy field not present")

    # --------------------------------
    # Pretty Print Full Response
    # --------------------------------
    util.printcolor(util.BLUE, "\nDecoded GetInfo response:")
    pprint.pprint(decoded, width=120)

    return pin_complexity_policy




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
    if  pinAuthToken=="null":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
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
def credentialpresetornot(credId,rp, clientDataHash,protocol,pin):
    subcommand=0x09
    mode="Withcmpermission"
    subCommand = 0x01  # getCredsMetadata
    permission=0x04
    rpid=None
    if protocol ==1:

        pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission,rpid)
        pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission,rpid)
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
    if mode in ("pincomplexitytruerkfalse","nondiscoverable"):
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
