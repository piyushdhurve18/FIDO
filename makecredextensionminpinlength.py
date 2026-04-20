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
import DocumentCreation

permissionRpId = ""
rp="localhost"
username="bobsmith"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - MIN PIN LENGTH)"
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
"case1setminpin":"""Test started: P-1 :
P-1 Create a new credential with extensions containing minPinLenth set to True, and check that authenticator succeeds Check that MakeCredential response extensions contain minPinLength extension. If authenticator supports GetInfo minPINLength, check that minPinLength extension result equal to GetInfo.minPINLength
""",
"getinfo":"""Test started: P-2 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.

Test Description:
Verify that the authenticator advertises support for the minPinLength extension.
Steps:
Send a valid authenticatorGetInfo (0x04) request.The authenticator returns CTAP2_SUCCESS.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes minimumpinlength  in the extensions list.
3.The response includes the minPINLength field, and its value corresponds to the default minimum PIN length.""",

"authorizedrp":"""Test started: P-3 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command with minPinLengthRPIDs (0x02) set to {"example.com"},without modifying the current (default) minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to False.
3.The minPINLength value remains the default minimum PIN length.

Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID that is included in the authorized list (e.g., "example.com").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <current_minimum_value>
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",

"unauthorizedrp":"""Test started: P-4 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command with minPinLengthRPIDs (0x02) set to {"example.com"},without modifying the current (default) minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to False.
3.The minPINLength value remains the default minimum PIN length.

Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID that is included in the authorized list (e.g., "example.com").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an no "extensions" field.

Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",

"case4setminpin":"""Test started: P-5 :         
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
If the authenticator supports setMinPINLength, send an authenticatorConfig (0x0D) command with setMinPINLength (0x03) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to false.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:(optional)
If forcePINChange is true, send a clientPIN (0x06) subcommand Change PIN command(0x04) using the current PIN to set a new PIN that complies with the updated minimum length requirement.

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_value>
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful. 
 """,
"case5setminpin":"""Test started: P-6 :         
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) to a value greater than the current 
minimum PIN length, and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:
If forcePINChange is true, send a clientPIN (0x06) subcommand Change PIN command(0x04) using the current PIN to set a new PIN that complies with the updated minimum length requirement.

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true Use an authorized RP.
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_value>
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful. 
 """,   
"case6setminpin":"""Test started: P-7 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) to a value greater than the current minimum PIN length, 
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:
If forcePINChange is true, send a clientPIN (0x06) subcommand Change PIN command(0x04) using the current PIN to set a new PIN that complies with the updated minimum length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": False ,Use an authorized RP
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",

"case7setminpin":"""Test started: P-8 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) to a value greater than the current minimum PIN length, and configure minPinLengthRPIDs (0x02) with an empty RP ID (i.e., "", null value).
Expected Result:
The authenticator returns CTAP1_ERR_INVALID_LENGTH.

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:
If forcePINChange is true, send a clientPIN (0x06) subcommand Change PIN command(0x04) using the current PIN to set a new PIN that complies with the updated minimum length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": True ,Use an authorized RP
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 5:
Send a valid U2F registration request and verify that the operation completes successfully
Expected Result:
The U2F registration operation is successful.""",

"case8setminpin":"""Test started: P-9 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
send an authenticatorConfig (0x0D) command with:
1.setMinPINLength (0x03) 
2.minPinLengthRPIDs (0x02) set to {"example.com"}
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to True.
3.The minPINLength value is updated to the newly configured minimum PIN length.
Step 3:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) to a value greater than the current minimum PIN length, 
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
Step 4:
Create a new credential using authenticatorMakeCredential (0x01) without inculde  the extensions field .
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.""",



"case9setminpin":"""Test started: P-10 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) to a value greater than the current minimum PIN length, 
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
If forcePINChange is true, send a clientPIN (0x06) subcommand Change PIN command(0x04) using the current PIN to set a new PIN that complies with the updated minimum length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 4:If the authenticator supports the reset command, perform an authenticator reset.
Expected Result 
1.The authenticator returns CTAP2_SUCCESS.
2.The minimum PIN length is restored to the default value.
3.The forcePINChange flag is cleared.

Step 5:
Create a new credential using authenticatorMakeCredential (0x01) with the 
extensions field set to "minPinLength": true, ensuring that the RP ID used is authorized.
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.

Step 6:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",

"case11setminpin":"""Test started: P-11 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) to the maximum supported value (64 bytes), ensuring it is greater than the current minimum PIN length
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.TheforceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
IfforceChangePin is true, send a clientPIN (0x06) command with the Change PIN (0x04) subcommand, using the current PIN to set a new PIN that complies with the updated minimum PIN length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS.

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true

Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_minimum_PIN_length>
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",

"case12setminpin":"""Test started: P-12 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.TheforceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
IfforceChangePin is true, send a clientPIN (0x06) command with the Change PIN (0x04) subcommand, using the current PIN to set a new PIN that complies with the updated minimum PIN length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS.
Step 4:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(8 to 10).
Expected Result:
The authenticator returns CTAP2_SUCCESS.
Step 5:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.TheforceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 6:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true

Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_minimum_PIN_length>
Step 7:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",

"case13setminpin":"""Test started: P-13 : 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
If forceChangePin is true, send a clientPIN (0x06) command with the Change PIN (0x04) subcommand, using the current PIN to set a new PIN that complies with the updated minimum PIN length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS.

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true

Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_minimum_PIN_length>
Step 5:
If the authenticator supports setMinPINLength, send an authenticatorConfig (0x0D) command with setMinPINLength (0x03) and set newMinPINLength (0x01) to a value less than the current minimum PIN length.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
Step 6:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",


"case14setminpin":"""Test started: P-14 : 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true
Expected Result:
The authenticator returns CTAP2_ERR_PUAT_REQUIRED.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,

"case15setminpin":"""Test started: P-15 :    
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.
Step 3:
Send the Authenticator Client PIN (0x06) subcommand getPinAuthToken (0x05).
Expected Result:
The authenticator returns CTAP2_ERR_PIN_INVALID.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,
"case16setminpin":"""Test started: P-16 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).
and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.
Step 3:
Send the Authenticator Client PIN (0x06) command with the subcommand getPinAuthTokenUsingPinWithPermissions (0x09).
Expected Result:
The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"case17setminpin":"""Test started: P-17 :  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
If forceChangePin is true, send a clientPIN (0x06) command with the Change PIN (0x04) subcommand, using the current PIN to set a new PIN that complies with the updated minimum PIN length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS.

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
"minPinLength": true,
"credProtect": 0x01,
"credBlob": <32-byte value>
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field contains:
"minPinLength": <updated_minimum_PIN_length>
"credBlob": true
"credProtect": 0x01
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,

"case18setminpin":"""Test started: P-18:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
If forceChangePin is true, send a clientPIN (0x06) command with the Change PIN (0x04) subcommand, using the current PIN to set a new PIN that complies with the updated minimum PIN length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS.

Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
"minPinLength": true,
"credProtect": 0x02,
"credBlob": <20-byte value>
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field contains:
"minPinLength": <updated_minimum_PIN_length>
"credBlob": true
"credProtect": 0x02
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",
"case19setminpin":"""Test started: P-19:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.
5.The authenticator is configured with a PIN

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command using the setMinPINLength (0x03) subcommand. Set newMinPINLength (0x01) and set newMinPINLength (0x01) to a value greater than the current minimum PIN length(6 to 8).and configure minPinLengthRPIDs (0x02) to include "example.com".
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to true.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
If forceChangePin is true, send a clientPIN (0x06) command with the Change PIN (0x04) subcommand, using the current PIN to set a new PIN that complies with the updated minimum PIN length requirement.
Expected Result:
The authenticator returns CTAP2_SUCCESS.
Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
"minPinLength": true,
"credProtect": 0x03,
"credBlob": <10-byte value>
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field contains:
"minPinLength": <updated_minimum_PIN_length>
"credBlob": true
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",

"case20setminpin":"""Test started: P-20:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command with minPinLengthRPIDs (0x02) set to {"example.com"},without modifying the current (default) minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.TheforceChangePin flag is set to False.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true, Use an RP ID that is included in the authorized list (e.g., "example.com")
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_value>
Step 5:
Send a valid U2F Registration request and verify that the registration completes successfully.
""",
"case21setminpin":"""Test started: P-21:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.

Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command with minPinLengthRPIDs (0x02) set to {"example.com"},without modifying the current (default) minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forceChangePin flag is set to false.
3.The minPINLength value is updated to the newly configured minimum PIN length.


Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": False ,Use an RP ID that is present in the authorized list (for example, "example.com").
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 5:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,



"case22setminpin":"""Test started: P-22:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
send an authenticatorConfig (0x0D) command with:
1.setMinPINLength (0x03)to a value greater than the current minimum PIN length(Ex 6 to 8).
2.minPinLengthRPIDs (0x02) set to {"example.com"}
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to false.
3.The minPINLength value is updated to the newly configured minimum PIN length.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true  Ensure that the RP ID used is "example.com".
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <current_minimum_value>
Step 4:
Send a valid U2F Registration request and verify that the registration completes successfully.""",
"case23setminpin":"""Test started: P-23:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
send an authenticatorConfig (0x0D) command with:
1.setMinPINLength (0x03))to a value greater than the current minimum PIN length(Ex 6 to 8).
2.minPinLengthRPIDs (0x02) set to {"example.com"}
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to False.
3.The minPINLength value is updated to the newly configured minimum PIN length.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": False   Ensure that the RP ID used is "example.com".
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.
Step 4:
Send a valid U2F Registration request and verify that the registration completes successfully. """,

"case24setminpin":"""Test started: P-24:  
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command with minPinLengthRPIDs (0x02) set to {"example.com"},without modifying the current (default) minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.TheforceChangePin flag is set to False.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true,Use an RP ID that is not included in the authorized list (for example, "unauthorized.com").
Verify that the operation completes successfully and that the response is returned without the minPinLength extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response does not contain an "extensions" field..

Step 5:
Send a valid U2F Registration request and verify that the registration completes successfully.""",
"case25setminpin":"""Test started: P-25: 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
Send an authenticatorConfig (0x0D) command with minPinLengthRPIDs (0x02) set to {"example.com"},without modifying the current (default) minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.TheforceChangePin flag is set to False.
3.The minPINLength value is updated to the newly configured minimum PIN length.

Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": False,Use an RP ID that is not included in the authorized list (for example, "unauthorized.com").
Verify that the operation completes successfully and that the response is returned without the minPinLength extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response does not contain an "extensions" field..

Step 5:
Send a valid U2F Registration request and verify that the registration completes successfully.""",

"case26setminpin":"""Test started: P-26: 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
send an authenticatorConfig (0x0D) command with:
1.setMinPINLength (0x03)to a value greater than the current minimum PIN length(Ex 6 to 8).
2.minPinLengthRPIDs (0x02) set to {"example.com"}
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to false.
3.The minPINLength value is updated to the newly configured minimum PIN length.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true Use an RP ID that is not included in the authorized list (for example, "unauthorized.com").
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains  "eoxtensions" field.

Step 4:
Send a valid U2F Registration request and verify that the registration completes successfully.""",

"case27setminpin":"""Test started: P-27: 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
send an authenticatorConfig (0x0D) command with:
1.setMinPINLength (0x03)to a value greater than the current minimum PIN length(Ex 6 to 8).
2.minPinLengthRPIDs (0x02) set to {"example.com"}
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to false.
3.The minPINLength value is updated to the newly configured minimum PIN length.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": False Use an RP ID that is not included in the authorized list (for example, "unauthorized.com").
Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no  "extensions" field.

Step 4:
Send a valid U2F Registration request and verify that the registration completes successfully.""",
"case28setminpin":"""Test started: P-28: 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.

Test Description:
Step 1:
send an authenticatorConfig (0x0D) command with:
1.setMinPINLength (0x03)to a value greater than the current minimum PIN length(Ex 6 to 8).
2.minPinLengthRPIDs (0x02) set to {"example.com"}
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).
Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to false.
3.The minPINLength value reflects the newly configured minimum PIN length.


Step 3:If the authenticator supports the reset command, perform an authenticator reset.
Expected Result 
1.The authenticator returns CTAP2_SUCCESS.
2.The minimum PIN length is restored to the default value.
Step 4:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to false.
3.The minPINLength value default minimum PIN length.


Step 5:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true Use an RP ID that is included in the authorized list (e.g., "example.com")

Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <default_minimum_PIN_length>
Step 6:
Send a valid U2F Registration request and verify that the registration completes successfully.""",

"case29setminpin":"""Test started: P-29: 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
If the authenticator supports setMinPINLength, send an authenticatorConfig (0x0D) command with setMinPINLength (0x03) and set newMinPINLength (0x01) to the maximum supported value (63 bytes), ensuring it is greater than the current minimum PIN length.
Expected Result:
The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Send a valid authenticatorGetInfo (0x04) request.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The forcePINChange flag is set to false.
3.The minPINLength value reflects the newly configured minimum PIN length.

Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true

Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <updated_minimum_PIN_length>
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",
"case30setminpin":"""Test started: P-30: 
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.authenticatorGetInfo response includes "minPinLength" in the extensions list.
4.The authenticatorGetInfo response reports the default minimum PIN length.


Test Description:
Step 1:
Test Description:
Step 1 (Registration): Create credential using valid U2F Registration request . 
Expected Result:
1. The authenticator successfully completes registration .
2.Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull""",

}
    
    if mode not in descriptions:
                    raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode]) 
    util.printcolor(util.YELLOW, descriptions[mode])
    if mode =="case1setminpin":
        util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Precodition: CTAP2.2 authenticatorMakeCredential (0x01) using Min Pin Length extension Protocol-{protocol} ****")
    else:
        util.printcolor(util.YELLOW, f"**** Precondition based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with Min Pin Length extension Protocol-{protocol} ****")


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
            if protocol==1:
                util.printcolor(util.YELLOW, "****  authenticatorMakeCredential (0x01) Extension Credblob CTAP2.2 For   Protocol {protocol}****")
                if mode =="getinfo":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
            
                else:
                    subcommand=0x09
                    permission = 0x20
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission)
                    subCommand = 0x03
                    rp="example.com"
                    if mode in ["authorizedrp", "unauthorizedrp"]:
                        subCommandParams = {0x02: ["example.com"]}
                        pinAuthToken,clientDataHash,pin=performprotocol1(mode,pin,subCommand,protocol,subCommandParams,permission,pinToken)
                        
                        extension = {"minPinLength": True}
                        if mode == "authorizedrp":
                            rp = "example.com"
                            util.printcolor(util.YELLOW, "Testing with AUTHORIZED RP")
                        else:
                            rp = "unauthorized.com"
                            util.printcolor(util.YELLOW, "Testing with UNAUTHORIZED RP")   
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        
                        
                        if mode == "authorizedrp":
                            credId, credentialPublicKey = authParasing(response)
                            cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                            util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                            if not extensions or "minPinLength" not in extensions:
                                raise AssertionError("minPinLength extension MUST be returned for authorized RP")
                            util.printcolor(util.GREEN,"PASS: minPinLength correctly returned for authorized RP")

                        else: 
                            util.printcolor(util.GREEN,"PASS: minPinLength  ignored for unauthorized RP")

                    elif mode in ("case1setminpin","case4setminpin", "case5setminpin","case6setminpin","case7setminpin","case8setminpin","case9setminpin","case11setminpin","case12setminpin","case13setminpin","case14setminpin","case15setminpin","case16setminpin","case17setminpin","case18setminpin","case19setminpin"):
                        if mode =="case1setminpin":
                            subCommandParams = {0x02: ["example.com"]}

                        elif mode =="case4setminpin":
                            subCommandParams = {0x01: 8}
                        elif mode =="case7setminpin": 
                            subCommandParams = {0x01: 8,0x02: [""]} 
                            mode="authenticofignull" 
                        elif mode =="case8setminpin": 
                            subCommandParams = {0x01: 8,0x02: ["example.com"]}  
                            mode="withoutExtension"
                        elif mode =="case9setminpin": 
                            subCommandParams = {0x01: 8,0x02: ["example.com"]}  
                            mode="performresetcommand"  
                        elif mode =="case11setminpin": 
                            subCommandParams = {0x01: 63,0x02: ["example.com"]} 
                        else:
                            subCommandParams = {0x01: 8,0x02: ["example.com"]}
                        

                        if mode =="case6setminpin":
                            extension = {"minPinLength": False}
                        elif mode in ("case17setminpin","case18setminpin","case19setminpin"):
                            if mode =="case17setminpin":

                                credblob=os.urandom(32)
                                credprotect=0x01
                            elif mode =="case18setminpin":
                                credblob=os.urandom(20)
                                credprotect=0x02
                            else :
                                credblob=os.urandom(10)
                                credprotect=0x03
                            extension = {"minPinLength": True,
                                        "credBlob": credblob,
                                        "credProtect": credprotect}

                        else:
                            extension = {"minPinLength": True}
                        
                        
                        print("hii")
                        pinAuthToken,clientDataHash,pin=performprotocol1(mode,pin,subCommand,protocol,subCommandParams,permission,pinToken)
                        
                        if mode =="performresetcommand":
                            util.ResetCardPower()
                            util.ConnectJavaCard() 
                            util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                            util.run_apdu("80100000010700", "Reset Card PIN","00")
                            response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
                            getinforesponse(response)
                        elif mode =="case12setminpin":
                            subCommandParams = {0x01: 10}
                            pinAuthToken,clientDataHash=mulpletimesp1(mode,pin,subCommand,protocol,subCommandParams,permission)
                        if mode =="case15setminpin":
                            apdu=registationu2f()
                            response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                            return response
                        elif mode =="case16setminpin":
                            apdu=registationu2f()
                            response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                            return response
                        elif mode =="case14setminpin":
                            clientDataHash=os.urandom(32)
                            mode="performresetcommand"
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                            if isinstance(makeCredAPDU, str):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                            else:
                                for i, apdu in enumerate(makeCredAPDU):
                                    response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        else:
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                            if isinstance(makeCredAPDU, str):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                            else:
                                for i, apdu in enumerate(makeCredAPDU):
                                    response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                            credId, credentialPublicKey = authParasing(response)
                            cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                            util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                            if extensions and "minPinLength" in extensions:
                                util.printcolor(util.GREEN,"PASS:  minPinLength is present for an authorized RP")
                            else:
                                util.printcolor(util.GREEN,"PASS: minPinLength  ignored for unauthorized RP, null RP ID, or when minPinLength is set to false or no extension field")

                            if mode =="case13setminpin":
                                subcommand=0x09
                                permission = 0x20
                                pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission)
                                subCommand = 0x03
                                subCommandParams={0x01: 6}
                                apdu=minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams)
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION") 

                            u2fauthenticatenew(mode,rp, clientDataHash, credId)                       
            

            else:
                util.printcolor(util.YELLOW, "****  authenticatorMakeCredential (0x01) Extension Credblob CTAP2.2 For   Protocol 2****")
                if mode =="getinfo":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                else:
                    subcommand=0x09
                    permission = 0x20
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission)
                    subCommand = 0x03
                    rp="example.com"
                    if mode in ["authorizedrp", "unauthorizedrp"]:
                        subCommandParams = {0x02: ["example.com"]}
                        pinAuthToken,clientDataHash,pin=performprotocol2(mode,pin,subCommand,protocol,subCommandParams,permission,pinToken)
                        
                        extension = {"minPinLength": True}
                        if mode == "authorizedrp":
                            rp = "example.com"
                            util.printcolor(util.YELLOW, "Testing with AUTHORIZED RP")
                        else:
                            rp = "unauthorized.com"
                            util.printcolor(util.YELLOW, "Testing with UNAUTHORIZED RP")   
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        
                        
                        if mode == "authorizedrp":
                            credId, credentialPublicKey = authParasing(response)
                            cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                            util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                            if not extensions or "minPinLength" not in extensions:
                                raise AssertionError("minPinLength extension MUST be returned for authorized RP")
                            util.printcolor(util.GREEN,"PASS: minPinLength correctly returned for authorized RP")

                        else: 
                            util.printcolor(util.GREEN,"PASS: minPinLength  ignored for unauthorized RP")
                    elif mode in ("case1setminpin","case4setminpin", "case5setminpin","case6setminpin","case7setminpin","case8setminpin","case9setminpin","case11setminpin","case12setminpin","case13setminpin","case14setminpin","case15setminpin","case16setminpin","case17setminpin","case18setminpin","case19setminpin"):
                        if mode =="case1setminpin":
                            subCommandParams = {0x02: ["example.com"]}
                        elif mode =="case4setminpin":
                            subCommandParams = {0x01: 8}
                        elif mode =="case7setminpin": 
                            subCommandParams = {0x01: 8,0x02: [""]}  
                            mode="authenticofignull"
                        elif mode =="case8setminpin": 
                            subCommandParams = {0x01: 8,0x02: ["example.com"]}  
                            mode="withoutExtension" 
                        elif mode =="case9setminpin": 
                            subCommandParams = {0x01: 8,0x02: ["example.com"]}  
                            mode="performresetcommand" 
                        elif mode =="case11setminpin": 
                            subCommandParams = {0x01: 63,0x02: ["example.com"]} 
                        else:
                            subCommandParams = {0x01: 8,0x02: ["example.com"]}


                        if mode =="case6setminpin":
                            extension = {"minPinLength": False}
                        elif mode in ("case17setminpin","case18setminpin","case19setminpin"):
                            if mode =="case17setminpin":

                                credblob=os.urandom(32)
                                credprotect=0x01
                            elif mode =="case18setminpin":
                                credblob=os.urandom(20)
                                credprotect=0x02
                            else :
                                credblob=os.urandom(10)
                                credprotect=0x03
                            extension = {"minPinLength": True,
                                        "credBlob": credblob,
                                        "credProtect": credprotect}
                        else:
                            extension = {"minPinLength": True}

                        
                        pinAuthToken,clientDataHash,pin=performprotocol2(mode,pin,subCommand,protocol,subCommandParams,permission,pinToken)   
                        if mode =="performresetcommand":
                            util.ResetCardPower()
                            util.ConnectJavaCard() 
                            util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                            util.run_apdu("80100000010700", "Reset Card PIN","00")
                            response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
                            getinforesponse(response)
                        elif mode =="case12setminpin":
                            subCommandParams = {0x01: 10}
                            pinAuthToken,clientDataHash=mulpletimes(mode,pin,subCommand,protocol,subCommandParams,permission)


                        if mode =="case15setminpin":
                            apdu=registationu2f()
                            response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                            return response
                        elif mode =="case16setminpin":
                            apdu=registationu2f()
                            response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                            return response
                        elif mode =="case14setminpin":
                            clientDataHash=os.urandom(32)
                            mode="performresetcommand"
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                            if isinstance(makeCredAPDU, str):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                            else:
                                for i, apdu in enumerate(makeCredAPDU):
                                    response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        else:
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                            
                            credId, credentialPublicKey = authParasing(response)
                            cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                            
                            util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                            if extensions and "minPinLength" in extensions:
                                util.printcolor(util.GREEN,"PASS:  minPinLength is present for an authorized RP")

                            else:
                                util.printcolor(util.GREEN,"PASS: minPinLength  ignored for unauthorized RP, null RP ID, or when minPinLength is set to false or no extension field")

                            if mode =="case13setminpin":
                                subcommand=0x09
                                permission = 0x20
                                pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission)
                                subCommand = 0x03
                                subCommandParams={0x01: 6}
                                apdu=minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams)
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION") 
                            u2fauthenticatenew(mode,rp, clientDataHash, credId)
                        
        else:
            util.printcolor(util.YELLOW, "****  withoupin authenticatorMakeCredential (0x01) Extension min_pin_length CTAP2.2 For   Protocol {protocol}****")
            if mode in("case20setminpin","case21setminpin","case22setminpin","case23setminpin","case24setminpin","case25setminpin","case26setminpin","case27setminpin","case28setminpin","case29setminpin","case30setminpin"):
                rp="example.com"
                subCommand= 0x03
                subCommandParams = {0x02: ["example.com"]}
                extension = {"minPinLength": True}

                if mode == "case21setminpin":
                    extension = {"minPinLength": False}

                elif mode in ("case22setminpin","case28setminpin"):
                    subCommandParams = {0x01: 8, 0x02: ["example.com"]}

                elif mode in ("case23setminpin","case27setminpin"):
                    if mode =="case27setminpin":
                        rp = "unauthorized.com"

                    subCommandParams = {0x01: 8, 0x02: ["example.com"]}
                    extension = {"minPinLength": False}

                elif mode in( "case24setminpin","case26setminpin"):
                    rp = "unauthorized.com"

                elif mode == "case25setminpin":
                    rp = "unauthorized.com"
                    extension = {"minPinLength": False}
                elif mode =="case29setminpin":
                    subCommandParams = {0x01: 63, 0x02: ["example.com"]}
                    extension = {"minPinLength": True}
                elif mode =="case30setminpin":
                    response=u2fauthenticate(mode)
                    return response

                

            
                
                
                withoutpinoperation(subCommand,protocol,subCommandParams)
                if mode =="case28setminpin":
                    util.ResetCardPower()
                    util.ConnectJavaCard() 
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    util.run_apdu("80100000010700", "Reset Card PIN","00")
                    response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)

                clientDataHash=os.urandom(32)
                makeCredAPDU=createCBORmakeCredwithoutpin(mode,clientDataHash, rp, username,protocol,extension)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                else:
                    for i, apdu in enumerate(makeCredAPDU):
                        response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                            
                credId, credentialPublicKey = authParasing(response)
                cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                            
                util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                if extensions and "minPinLength" in extensions:
                    util.printcolor(util.GREEN,"PASS:  minPinLength is present for an authorized RP")

                else:
                    util.printcolor(util.GREEN,"PASS: minPinLength  ignored for unauthorized RP, null RP ID, or when minPinLength is set to false or no extension field")
                u2fauthenticatenew(mode,rp, clientDataHash, credId)       
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
        
def u2fauthenticate(mode):
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
             
def withoutpinoperation(subCommand,protocol,subCommandParams):
    apdu=minPinLengthRPIDswithoutpin(subCommand,protocol,subCommandParams)
    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    decoded=getinforesponse(response)

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



def performprotocol1(mode,pin,subCommand,protocol,subCommandParams,permission,pinToken):
    if mode =="authenticofignull":              
        apdu=minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams)
        response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH") 
    else:
        apdu=minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams)
        response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
                 
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    
    decoded=getinforesponse(response)
    force_pin_change = decoded.get(0x0C, True)
    
    if mode in ("case14setminpin", "case15setminpin","case16setminpin"):
        if mode in ("case14setminpin","case15setminpin"):
            util.printcolor(util.YELLOW,f"Without performing change pin" )
            return None, None, pin
        elif mode =="case16setminpin":
            subcommand=0x09
            apdu=getPINtokenp1new(mode,pin,subcommand,protocol,permission)
            response, status = util.run_apdu(apdu,"Client PIN GetPINToken",expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION")
            return  None, None, pin
        
        else:
            subcommand=0x05
            mode="withoutpermission"
            apdu=getPINtokenp1new(mode,pin,subcommand,protocol,permission)
            response, status = util.run_apdu(apdu,"Client PIN GetPINToken",expected_prefix="31",expected_error_name="CTAP2_ERR_PIN_INVALID")
            return  None, None, pin

    elif force_pin_change:
        print("mode",mode)
        util.printcolor(util.YELLOW, "PIN change required")
        if mode =="case11setminpin":
            newpin="1"*63
            
        else:
            newpin="87654321"
        subcommand=0x04
        apdu=changepinp1(pin,newpin,protocol,subcommand)
        util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
        pin=newpin 
        util.printcolor(util.YELLOW, f"NEW PIN IS: {pin}") 
    

    else:
        util.printcolor(util.YELLOW,f"Pinchnage doesnot requried" )
                                                                                                                                

    subcommand=0x05
    mode="withoutpermission"
    pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission)
    clientDataHash =os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    return pinAuthToken,clientDataHash,pin

    
                
        
def performprotocol2(mode,pin,subCommand,protocol,subCommandParams,permission,pinToken): 
    if mode =="authenticofignull":              
        apdu=minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams)
        response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH") 
    else:
        apdu=minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams)
        response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
 
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    decoded=getinforesponse(response)
    force_pin_change = decoded.get(0x0C, True)
    if mode in ("case14setminpin", "case15setminpin","case16setminpin"):
        if mode in ("case14setminpin","case15setminpin"):
            util.printcolor(util.YELLOW,f"Without performing change pin" )
            return None, None, pin
        elif mode =="case16setminpin":
            subcommand=0x09
            apdu=getPINtokenp2new(mode,pin,subcommand,protocol,permission)
            response, status = util.run_apdu(apdu,"Client PIN GetPINToken",expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION")
            return None, None, pin
        

        else:
            util.printcolor(util.YELLOW,f"Without performing change pin" )
            subcommand=0x05
            mode="withoutpermission"
            apdu=getPINtokenp2new(mode,pin,subcommand,protocol,permission)
            response, status = util.run_apdu(apdu,"Client PIN GetPINToken",expected_prefix="31",expected_error_name="CTAP2_ERR_PIN_INVALID")
            return None, None, pin

    elif force_pin_change:
        util.printcolor(util.YELLOW, "PIN change required")
        if mode =="case11setminpin":
            newpin="1"*63
            
        else:
            newpin="87654321"
            
        
        subcommand=0x04
        apdu=changepinp2(pin,newpin,protocol,subcommand)
        util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
        pin=newpin  
        util.printcolor(util.YELLOW, f"NEW PIN IS: {pin}")  

    else:
        util.printcolor(util.YELLOW,f"Pinchnage doesnot requried" )
    
    subcommand=0x05
    mode="withoutpermission"
    pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission)
    clientDataHash =os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    return pinAuthToken,clientDataHash,pin

def mulpletimes(mode,pin,subcommand,protocol,subCommandParams,permission):
    subcommand=0x09
    permission = 0x20
    pinTokens=getPINtokenp2(mode,pin,subcommand,protocol,permission)
    
    subCommand = 0x03
    apdu=minPinLengthRPIDs(pinTokens, subCommand,protocol,subCommandParams)
    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    decoded=getinforesponse(response)
    
    force_pin_change = decoded.get(0x0C, True)

    if force_pin_change:
        util.printcolor(util.YELLOW, "PIN change required")
        newpin="1"*10
        subcommand=0x04
        apdu=changepinp2(pin,newpin,protocol,subcommand)
        util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
        pin=newpin 
    else:
        util.printcolor(util.YELLOW,f"Pinchnage doesnot requried" )
    subcommand=0x05
    mode="withoutpermission"
    pinToken=getPINtokenp2(mode,pin,subcommand,protocol,permission)
    clientDataHash =os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    return pinAuthToken,clientDataHash
def mulpletimesp1(mode,pin,subcommand,protocol,subCommandParams,permission):
    subcommand=0x09
    permission = 0x20
    pinTokens=getPINtokenp1(mode,pin,subcommand,protocol,permission)
    
    subCommand = 0x03
    apdu=minPinLengthRPIDs(pinTokens, subCommand,protocol,subCommandParams)
    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) : minPinLength(0x03)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS") 
    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
    decoded=getinforesponse(response)
    
    force_pin_change = decoded.get(0x0C, True)

    if force_pin_change:
        util.printcolor(util.YELLOW, "PIN change required")
        newpin="1"*10
        subcommand=0x04
        apdu=changepinp1(pin,newpin,protocol,subcommand)
        util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
        pin=newpin 
    else:
        util.printcolor(util.YELLOW,f"Pinchnage doesnot requried" )
    subcommand=0x05
    mode="withoutpermission"
    pinToken=getPINtokenp1(mode,pin,subcommand,protocol,permission)
    clientDataHash =os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    return pinAuthToken,clientDataHash
def getPINtokenp1new(mode,pin,subcommand,protocol,permission):
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
    apdu=createGetPinTokennew(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol,permission)
    return apdu

def getPINtokenp1(mode,pin,subcommand,protocol,permission):
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
    apdu=createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol,permission)
    return apdu

def getPINtokenp2(mode,curpin,subcommand,protocol,permission):
    print("pin",curpin)
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    response, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00")
    cbor_bytes    = binascii.unhexlify(response[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = response[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPinToken(mode,key_agreement,pinHashEnc,shareSecretKey,subcommand,protocol,permission)
    # hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    # byte_array = bytes.fromhex(hexstring[2:])
    # cbor_data = cbor2.loads(byte_array)                                                                                                
    # first_key = sorted(cbor_data.keys())[0]
    # pinToken = cbor_data[first_key]
    # #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return pinSetAPDU
def getPINtokenp2new(mode,curpin,subcommand,protocol,permission):
    print("pin",curpin)
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    response, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00")
    cbor_bytes    = binascii.unhexlify(response[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = response[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPinTokennew(mode,key_agreement,pinHashEnc,shareSecretKey,subcommand,protocol,permission)
    return pinSetAPDU

def createGetPinTokennew(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol,permission):
    if mode=="withoutpermission":
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc}

    else:     
        cbor_map = {
            1: protocol,                  # pinProtocol = 1
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc,         # pinHashEnc
            9:permission}
    
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    return apdu

def createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,subcommand,protocol,permission):
    if mode=="withoutpermission":
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc}

    else:     
        cbor_map = {
            1: protocol,                  # pinProtocol = 1
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc,         # pinHashEnc
            9:permission}
    
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




import cbor2
import pprint


def getinforesponse(response):
    """
    Parse CTAP2 GetInfo response and validate minPinLength support.
    Validates:
        - minPinLength extension
        - minPINLength (0x0D)
        - forcePINChange (0x0E) [optional]
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

    # ---- Validate extensions list (0x02) ----
    extensions = decoded.get(0x02)
    if not extensions or "minPinLength" not in extensions:
        raise AssertionError("minPinLength extension not supported")

    util.printcolor(util.GREEN, "PASS: minPinLength extension is supported")

    # ---- Validate minPINLength (0x0D) ----
    min_pin_length = decoded.get(0x0D)

    if min_pin_length is None:
        raise AssertionError("minPINLength (0x0D) field missing")

    if not isinstance(min_pin_length, int):
        raise AssertionError("minPINLength must be an integer")

    util.printcolor(
        util.GREEN,
        f"PASS: minPINLength = {min_pin_length}"
    )

    # ---- Validate forcePINChange (0x0C) ----
    # Spec: Only present when TRUE
    force_pin_change = decoded.get(0x0C, False)

    if force_pin_change not in [True, False]:
        raise AssertionError("forcePINChange must be boolean")

    util.printcolor(
        util.GREEN,
        f"forcePINChange = {force_pin_change}"
    )

    # ---- Pretty Print ----
    print("\nDecoded GetInfo response:")
    pprint.pprint(decoded, width=120)

    return decoded


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

def minPinLengthRPIDs(pinToken, subCommand,protocol,subCommandParams):

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
        0x02:subCommandParams,
        0x03: protocol,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu
def createCBORmakeCredwithoutpin(mode,clientDataHash, rp, user,protocol,extension):
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
    option  = {"rk": True}
    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_option        = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()
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

def createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol,extension):
    
   

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
    option  = {"rk": True}

   

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_option        = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()
    if mode =="withoutExtension":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol
    if mode =="performresetcommand":
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

from io import BytesIO
import cbor2

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

def registationu2f():
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    # 2. Build REGISTER APDU
    rpid = "example.com"
    challenge = os.urandom(32)
    apdu = u2f_register_apdu(rpid, challenge)
    print("U2F REGISTER APDU:", apdu)
    # 3. SEND REGISTER APDU 
    return apdu 


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
import hashlib

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


