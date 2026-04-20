
import util
import cbor2
import binascii
import Setpinp22
import os
import credentialManagement
import credBlob
import struct
import getpintokenCTAP2_2
import hashlib
import Setpinp1
from textwrap import wrap
import DocumentCreation

RP_domain          = "localhost"
user="bobsmith"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "GET PIN TOKEN PERMISSION"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def getPinUvAuthTokenP2_2(mode,pin,pinset,protocol):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL

    if protocol == 1:
        PROTOCOL = 1
    else:
        PROTOCOL = 2
    util.printcolor(util.YELLOW, "**** pinUvAuthToken  protocol 2.2****")
    util.ResetCardPower()
    util.ConnectJavaCard()

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
         "cmPermission": """Test started: P-1 : 
Preconditions:
1.The authenticator supports credential management.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required parameters.
Include the Credential Management permission (0x04) in the permissions field.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the cm permission.""",     
       
        "acfgPermission": """Test started: P-2 : 
Preconditions:
1.The authenticator supports Authenticator Configuration (authnrCfg) functionality.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Authenticator Configuration permission (0x20) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the authnrCfg permission.""",


        "mcPermission": """Test started: P-3 : 
Preconditions:
1.The authenticator supports the MakeCredential capability.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.
Test Steps:

Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the MakeCredential permission (0x01) in the permissions field.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the mc permission.""",

        "gaPermission": """Test started: P-4 : 
Preconditions:
1.The authenticator supports the GetAssertion capability.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the GetAssertion permission (0x02) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the ga permission.""",

       "lbwpermission": """Test started: p-5 : 
Preconditions:
The authenticator supports Large Blob Write functionality.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Large Blob Write permission (0x10) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the lbw permission.""",
        
        "bepermission": """Test started:  : F-1
Preconditions:
1.The authenticator does not support the Bio Enrollment capability.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Bio Enrollment permission (0x08) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the be permission, even though Bio Enrollment is not supported.""",
        
        "getpinToken": """Test started: F-2 : 
Preconditions:
1.The authenticator must be reset.
2.No PIN is currently set on the authenticator.
3.Send the GetInfo command to verify whether the authenticator supports Client PIN.
4.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request without specifying any permissions, using a valid pinHashEnc and all other required command parameters.
Expected Result:
The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

        "permission.zero": """Test started: F-3 : 
Preconditions:
1.The authenticator must be reset.
2.No PIN is currently set on the authenticator.
3.Send the GetInfo command to verify whether the authenticator supports Client PIN.
4.The authenticator supports PIN/UV protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with the permissions field set to zero (0x00), using a valid pinHashEnc and all other required command parameters.

Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

        "verifycmper": """Test started: P-6 : 
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator must be reset.
3.No PIN is currently set on the authenticator.
4.Send the GetInfo command to verify whether the authenticator supports Client PIN.
5.The authenticator supports PIN/UV protocols.

Test Steps:

Step 1:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Credential Management permission (0x04) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the cm permission.

Step 2 (Verification):
Use the returned pinUvAuthToken to perform a Credential Management command (0x0A).

Expected Result:
The authenticator returns CTAP2_OK, confirming that the token is valid and usable for Credential Management operations.""",
        
        "verifyacfgper": """Test started: P-7 : 
Preconditions:
1.The authenticator supports Authenticator Configuration.
2.The authenticator has a PIN already configured.
3.PIN/UV  suported Protocol  being used..

Test Steps:
Step 1:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Authenticator Configuration permission (0x20) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the acfg permission.

Step 2 (Verification):
Optionally, use the returned pinUvAuthToken to perform an Authenticator Configuration operation to verify the token’s validity.

Expected Result:
The authenticator returns CTAP2_OK, confirming the token is valid and can be used for Authenticator Configuration operations. """,       
        "verifymcper": """Test started: P-8 : 
Preconditions:
1.The authenticator supports the MakeCredential capability.
2.The authenticator has a PIN already configured.
3.PIN/UV  suported Protocol  being used.

Test Steps:
Step 1:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the MakeCredential permission (0x01) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the mc permission.

Step 2 (Verification):
Use the returned pinUvAuthToken to perform a MakeCredential command (0x01).

Expected Result:
The authenticator returns CTAP2_OK, confirming that the token is valid and can be used for MakeCredential operations.""",


"verifygaper": """Test started: P-9 : 
Preconditions:
1.The authenticator supports the GetAssertion capability.
2.The authenticator has a PIN already configured.
3.PIN/UV  suported Protocol  being used.

Test Steps:
Step 1:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the GetAssertion permission (0x02) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the ga permission.

Step 2(Verification):
Use the returned pinUvAuthToken to perform a GetAssertion command (0x02).

Expected Result:
The authenticator returns CTAP2_OK, confirming that the token is valid and can be used for GetAssertion operations.""",

        "withoutpingetpintoken": """Test started: P-10 : 
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator does not have a PIN configured.
3.PIN/UV  suported Protocol  being used.

Test Steps:
Step 1:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Credential Management permission (0x04) in the request.

Expected Result:
Since no PIN is configured on the authenticator, it shall return CTAP2_ERR_PIN_NOT_SET.""",
         
         "InvalidPIN": """Test started: F-4 :
Preconditions:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1:
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using all valid command parameters.
Include a permission such as Credential Management (0x04), but provide an incorrect PIN.

Expected Result:
The authenticator shall return CTAP2_ERR_PIN_INVALID.""",



"Invalidkey_agreement": """Test started: F-5 :
Preconditions:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid PIN hash (pinHashEnc) but with an invalid key_agreement. Ensure all other command parameters are correctly and validly specified. Include a permission such as Credential Management (0x04).
Expected Result: The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",



"Invalidpermission": """Test started: F-6 :
Precondition:
1.The authenticator supports Credential Management = true.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc, the key_agreement, and all other required command parameters.
Specify a permission such as Credential Management (0x04), but replace it with 0x00.

Expected Result:
The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",


"InvalidpinHashEnc": """Test started: F-7 :
Precondition:
1.The authenticator supports Credential Management = true.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a invalid pinHashEnc, the key_agreement, and all other required command parameters.
Specify a permission such as Credential Management (0x04),

Expected Result:
The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",
"Invalidsubcommand": """Test started: F-8 :
Precondition:
1.The authenticator supports Credential Management = true.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.


Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a invalid Subcommand, the key_agreement, and all other required command parameters.
Specify a permission such as Credential Management (0x04),

Expected Result:
The authenticator shall return CTAP2_ERR_INVALID_SUBCOMMAND.""",

"Invalidprotocol": """Test started: F-9 :
Precondition:
1.The authenticator supports Credential Management = true.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a invalid protocol, the key_agreement, and all other required command parameters.
Specify a permission such as Credential Management (0x04),

Expected Result:
The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",

"Invalidrpid": """Test started: F-9 :
Precondition:
1.The authenticator supports Credential Management = true.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using an invalid protocol, along with the key_agreement and all other required command parameters. Specify the MakeCredential permission (0x01), where an RP ID is mandatory.

Step 3:
In the MakeCredential (0x01) permission, provide an incorrect RP ID.

Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",


        "missingpinHashenc": """Test started: F-10 :
Preconditions:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid key_agreement, and all other required command parameters. Include a permission such as Credential Management (0x04), but omit the pinHashenc .

Expected Result:The authenticator shall return CTAP2_ERR_MISSING_PARAMETER.""",

"missingkeyAgreement": """Test started: F-11 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct pinHashEnc valid parameter.
Including a permission such as Credential Management (0x04),but keyAgreement parameter  is omitted.

Expected Result:the authenticator SHALL return CTAP2_ERR_MISSING_PARAMETER.""",


"missingsubcommand": """Test started: F-12 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions  request using the correct pinHashEnc, along with the key_agreement and valid command parameters.
Including a permission such as Credential Management (0x04),but subcommand parameter  is omitted.

Expected Result:the authenticator SHALL return CTAP2_ERR_MISSING_PARAMETER.""",

"missingprotocol": """Test started: F-13 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct pinHashEnc, along with the key_agreement and valid command parameters.
Including a permission such as Credential Management (0x04),but protocol is omitted.

Expected Result:the authenticator SHALL return CTAP2_ERR_MISSING_PARAMETER.""",
"missingpermission": """Test started: F-14 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct pinHashEnc, along with the key_agreement and valid command parameters.
Including a permission such as Credential Management (0x04),but that permission   is omitted.

Expected Result:the authenticator SHALL return CTAP2_ERR_MISSING_PARAMETER.""",

"missingrpid": """Test started: F-15 :
Precondition:
1.The authenticator supports Makecredential.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct pinHashEnc, along with the key_agreement and valid command parameters.
Including a permission such as Makrcredential (0x01),but that RPID   is omitted.

Expected Result:the authenticator SHALL return CTAP2_ERR_MISSING_PARAMETER.""",

"pinauthblocked": """Test started: F-15 :
Precondition:
1.The authenticator supports Credential Management = true.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using an incorrect PIN (for example, the actual PIN is "123456" but "654321" is provided), while including a permission such as Credential Management (0x04).
The authenticator should return CTAP2_ERR_PIN_INVALID for each incorrect attempt, and after multiple consecutive failures (e.g., three attempts),
Expected Result:The authenticator  return CTAP2_ERR_PIN_AUTH_BLOCKED.""",

"pinauthblocked.pin": """Test started: F-16 :
Precondition:                                  
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
With the PIN in a PIN_AUTH_BLOCKED state and without performing a power-cycle reset.
send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct PIN and including a permission such as Credential Management (0x04).

Expected Result:The authenticator shall return CTAP2_ERR_PIN_AUTH_BLOCKED..""",


"pinretry": """Test started: F-17 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using any PIN value—correct (e.g., 123456) or incorrect—and include a permission such as Credential Management (0x04).
With the PIN in a PIN_AUTH_BLOCKED state and without performing a power-cycle reset.
step 3:send getretries command .
Expected Result:
The authenticator shall not decrement the PIN retry counter..""",



"withpowercycle": """Test started: F-18 :
Precondition:

1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
After performing a power-cycle reset, send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the incorrect PIN, the proper pinHashEnc, and all other valid command parameters.
Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP2_PIN_INVALID.
Step 3:
Send getretries command and retries should be decress.
Expected result:The auhenticator retrurn getretries decress.""",



"pinblocked": """Test started: F-19 :
Preconditions:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request After performing the power recycle reset  but invalid pin multiple times after the PIN has been blocked due to multiple incorrect attempts, with all required command parameters supplied correctly. Include a permission such as Credential Management (0x04).
Expected Result:
The authenticator shall return CTAP2_ERR_PIN_BLOCKED.
Step 2:
Send getretries command and retries should be decress.
Expected result:The auhenticator retrurn getretries count 0.""",

"pinreset": """Test started: p-14 :
Preconditions:
1.The authenticator supports Credential Management.
2.PIN/UV Protocol 2 is being used.
3.The PIN was previously blocked.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Step 1: Perform a power-cycle reset of the authenticator .
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the newly set PIN, the proper pinHashEnc, and all other valid command parameters. Include a permission such as Credential Management (0x04).
Expected Result: The authenticator shall return CTAP2_OK.""",


"Invalidkey_sharesecret": """Test started: F-20 :
Preconditions:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using an invalid shared secret, ensuring that all other command parameters are correctly and validly specified. Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP2_ERR_PIN_INVALID.""",



"platformCOSKEY.notmap": """Test started: F-21 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with with platformCOSKEY not being a map (e.g., an array or string). 
Including a permission such as Credential Management (0x04)The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"pinHashEnc.notbyte": """Test started: F-22 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request where the platformCOSKEY is provided, but pinHashEnc is not of type bytes (e.g., provided as an integer or string).
Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",

"forcepinset": """Test started: F-23 :
Precondition:
1.The authenticator supports Authenticator config.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Steps:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Set the forcePINChange field to True.
Expected Result: The authenticator returns CTAP2_OK, but indicates that a PIN change is required.

Step 2: With the forcePINChange field set to true and the user not having changed their PIN, send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the old PIN and all other required parameters correctly. Include a permission such as Credential Management (0x04).
Expected Result: The authenticator shall return CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"changepin": """Test started: F-24 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Set the forcePINChange field to True.
Expected Result: The authenticator returns CTAP2_OK, but indicates that a PIN change is required.
Step 3:
If forcePINChange is set to true and the user has already changed their PIN, then sending a getPinUvAuthTokenUsingPinWithPermissions (0x09) request—using the currect PIN and all required parameters, 
including a permission such as Authenticator config (0x20). The authenticator returning CTAP2_OK.""",


"changewrongpin": """Test started: F-25 :
Precondition:
1.The authenticator supports Authenticator config.
2.The authenticator must  have a PIN configured.
3. PIN/UV Protocol 2 is being used.
Test Step:
Step 1: Set the forcePINChange field to True.
Expected Result: The authenticator returns CTAP2_OK, indicating that a PIN change is required.

Step 2: After the user has changed their PIN, send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the current PIN and all other required parameters. Include a permission such as Authenticator Configuration (0x20).
Expected Result: The authenticator shall return CTAP2_OK.""",

"forcechangepin.false": """Test started: F-26 :
Precondition:
1.The authenticator supports Authenticator config.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Set the forcePINChange field to False.
Expected Result: The authenticator returns CTAP2_OK, indicating that a PIN change is not required.

Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the current PIN and all other required parameters. Include a permission such as Authenticator Configuration (0x20).
Expected Result: The authenticator shall return CTAP2_OK.""",
"getpintokenmappingnotsequence": """Test started: F-27 :
Precondition:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with with platformCOSKEY not being a map (e.g., an array or string). 
Including a permission such as Credential Management (0x04)The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"withoutpermission.getasseration": """Test started: F-27 :
Precondition:
1.The authenticator supports Authenticator config.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Begin by requesting permission only for makeCredential and ensure this permission is granted successfully. After obtaining permission exclusively for makeCredential, attempt to run the other protected commands— authentication (getAssertion), authConfig and credential management using valid parameters. Since permission was granted only for makeCredential, all these other commands must fail, and the authenticator should return the appropriate error indicating that the operation is not permitted..""",


"withoutpermission.makecredential": """Test started: F-28 :
Precondition:
1.The authenticator supports Authenticator config.
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Begin by requesting permission only for authentication (getAssertion) and ensure this permission is granted successfully. 
After obtaining permission exclusively for authentication (getAssertion) , attempt to run the other protected commands—makeCredential, authConfig and credential management using valid parameters.
 Since permission was granted only for authentication (getAssertion) , all these other commands must fail, and the authenticator should return the appropriate error indicating that the operation is not permitted.""",



"withoutpermission.cm": """Test started: F-29 :
Precondition:
1.The authenticator supports Authenticator config.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Begin by requesting permission only for credential management and ensure this permission is granted successfully. 
After obtaining permission exclusively for credential management, attempt to run the other protected commands—makeCredential, authentication (getAssertion), authConfig, using valid parameters. 
Since permission was granted only for credential management, all these other commands must fail, and the authenticator should return the appropriate error indicating that the operation is not permitted.""",

"withoutpermission.afg": """Test started: F-30 :
Precondition:
1.The authenticator supports Authenticator config.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Begin by requesting permission only for authConfig and ensure this permission is granted successfully. 
After obtaining permission exclusively for authConfig, attempt to run the other protected commands—makeCredential, authentication (getAssertion),credential management, using valid parameters. 
Since permission was granted only for authConfig, all these other commands must fail, and the authenticator should return the appropriate error indicating that the operation is not permitted.""",
"permissionalloperation": """Test started: F-30 :
Precondition:
1.The authenticator supports Authenticator config.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Begin by requesting permission for all operations makeCredential, authentication (getAssertion),credential management and  authConfig, at once, proceed to run each protected command individually. 
Execute authentication (getAssertion),credential management and  authConfig, ensuring that every command is formatted correctly and uses valid parameters. 
Each operation should execute successfully, and the authenticator should return CTAP2_OK for all of them.""",


"rpidmatching": """Test started: F-31 :
Precondition:
1.The authenticator supports makecrdential.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Obtain a pinUvAuthToken with makeCredential permission for rpId = example.com; then run makeCredential with the same rpId (example.com).
 The operation should succeed ctap_ok..""",

"rpidnotmatching": """Test started: F-32 :
Precondition:
1.The authenticator supports makecrdential.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Obtain a pinUvAuthToken with makeCredential permission for rpId = example.com; then run makeCredential with the incorrect rpId (localhost).
 The operation should succeed ctap_ok..""",

"rpgetasseration": """Test started: F-32 :
Precondition:
1.The authenticator supports makecrdential and getasseration.
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Obtain a pinUvAuthToken with makeCredential permission for rpId = example.com; then run  authentication (getAssertion)  different rpId (localhost). The operation should failed.""",








    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode]) 
    util.printcolor(util.YELLOW, descriptions[mode])
    try:
        scenarioCount += 1
        if protocol==2:

            if str(pinset).lower() == "yes": 
                if mode == "getpinToken":
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission=4
                    response,status=getPINtokenwithPermission1(mode,pin,permission) #without providing the permisssion
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "cmPermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode =="acfgPermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # Authenticator Configuration permission
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "mcPermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "gaPermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x02  # GetAssertion permission
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "lbwpermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x10  # Large Blob Write permission
                    response, status=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "40":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_UNAUTHORIZED_PERMISSION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)


                elif mode == "bepermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x08  # Bio Enrollment permission
                    response, status=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "40":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_UNAUTHORIZED_PERMISSION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "permission.zero":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x00  # zer value  permission
                    response, status=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifycmper":
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    pinToken, pubkey,response, status = getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    #pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                    apdu =getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "verifyacfgper":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    response,status=util.APDUhex("80100000010400", "GetInfo .....")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifymcper":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken, pubkey,response,status=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol=2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,  pinAuthToken,protocol)

                    if isinstance(makeCredAPDU, str):
                        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            result, status = util.APDUhex(apdu,f"Rest of Data:",checkflag=(i == len(makeCredAPDU) - 1)
                    )
                    if result[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                    
                    return result
                
                elif mode == "verifygaper":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken, pubkey,response,status=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    credId=authParasing(result)
                    permission = 0x02  # GetAssertion permission
                    pinToken, pubkey,response,status = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    RP_domain="localhost"
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "InvalidPIN":
                    pin="123456"
                    restPin(pin)
                    wrongpin="654321" #wrong pin
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,status=getPINtokenwithPermission2(mode,wrongpin,permission)
                    if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "InvalidpinHashEnc":
                    pin="123456"
                    restPin(pin)
                    
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "Invalidkey_agreement":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "Invalidpermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x00  # invalid value of permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Invalidsubcommand":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "3E":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Invalidprotocol":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Invalidrpid":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MAKECREDENTIAL  permission RPID IS MADETORY
                    clientDataHash=os.urandom(32)
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission) 
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol=2
                    rpid="localhost"#wrong
                    makeCredAPDU = createCBORmakeCred(clientDataHash, rpid, user,  pinAuthToken,protocol);
                    if isinstance(makeCredAPDU, str):
                        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            result, status = util.APDUhex(apdu,f"Rest of Data:",checkflag=(i == len(makeCredAPDU) - 1)
                    )

                    return result

                elif mode == "missingpinHashenc":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingkeyAgreement":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingsubcommand":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingprotocol":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingpermission":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingrpid":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # formake credential properes
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinauthblocked":
                    pin="123456"
                    restPin(pin)
                    pin="654321"
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    
                    
                elif mode == "subcommandInvalid":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                
                elif mode == "pinauthblocked.pin":
                    pin="123456"
                    restPin(pin)
                    wrongpin="654321"
                    util.printcolor(util.YELLOW,f"  PIN IS: {wrongpin}")
                    permission = 0x04  # CredentialManagement permission
                    mode="pinauthblocked"
                    response,staus=getPINtokenwithPermission2(mode,wrongpin,permission)#pinauthblocked
                    mode="pinauthblocked.pin"
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "34":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinretry":
                    pin="123456"
                    restPin(pin)
                    
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    wrongpin="654321"
                    permission = 0x04  # CredentialManagement permission
                    mode="pinauthblocked"
                    response,staus=getPINtokenwithPermission2(mode,wrongpin,permission)#pinauthblocked
                    mode="pinauthblocked.pin"
                    util.printcolor(util.YELLOW, f"Pinauth is in a blocked state even though the user provided the correct PIN getretries XX:")
                
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "34":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    Setpinp1.pinGetRetries()

                elif mode == "withpowercycle":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    wrongpin="654321"
                    permission = 0x04  # CredentialManagement permission
                    mode="pinauthblocked"
                    response,staus=getPINtokenwithPermission2(mode,wrongpin,permission)#pinauthblocked
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                    mode="withpowercycle"
                    response,staus=getPINtokenwithPermission2(mode,wrongpin,permission)
                    if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "pinblocked":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    wrongpin="654321"
                    permission = 0x04  # CredentialManagement permission
                    for i in range(8):
                        
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.APDUhex("00a4040008a0000006472f0001","Select applet")
                        response,staus=getPINtokenwithPermission2(mode,wrongpin,permission)
                        if i==7:
                            if response[:2] == "32":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        else:
                            if response[:2] == "31":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        if i==7:
                            util.printcolor(util.YELLOW, f"User entered an incorrect PIN multiple times; the PIN is now blocked: {wrongpin}")
                
                        Setpinp1.pinGetRetries()
                    
                elif mode == "Invalidkey_sharesecret":
                    pin="12345699"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    Setpinp1.pinGetRetries()
                
                elif mode == "platformCOSKEY.notmap":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "pinHashEnc.notbyte":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "forcepinset":

                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    
                    permission = 0x20  # authenticator config
                    pinToken, pubkey,response,status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    apdu=newMinPinLength(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    response,status=util.APDUhex("80100000010400", "Get Info")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "changepin":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # authenticator config
                    pinToken, pubkey,response,status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    apdu=newMinPinLength(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    util.APDUhex("80100000010400", "Get Info")
                    newpin="654321"
                    response,status=changePin(pin,newpin)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    util.APDUhex("80100000010400", "Get Info")
                    token, pubkey,response, status=getPINtokenwithPermission(mode,newpin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "changewrongpin":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # authenticator config
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)
                    subCommand = 0x03
                    apdu=getpintokenCTAP2_2.newMinPinLength(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    newpin="654321"
                    getpintokenCTAP2_2.changePin(pin,pin)
                    util.APDUhex("80100000010400", "Get Info")
                    response,staus=getPINtokenwithPermission2(mode,newpin,permission)

                elif mode == "forcechangepin.false":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    
                    permission = 0x20  # authenticator config
                    pinToken, pubkey,response,status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    apdu=getpintokenCTAP2_2.newMinPinLength1(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "getpintokenmappingnotsequence":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 1 
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)

                elif mode == "withoutpermission.getasseration":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    #permission = 0x02 
                    credId=authParasing(result)
                    pinToken, pubkey ,response, status= getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    response, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                    #permission = 0x04  # CredentialManagement permission
                    pinToken, pubkey,response, status = getPINtokenwithPermission(mode,pin,permission)
                    #pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                    protocol=2
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,stataus=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    #permission = 0x20  # Authenticator Configuration permission
                    pinToken,pubkey,response, status=getPINtokenwithPermission(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "withoutpermission.makecredential":
                    pin="123456"
                    restPin(pin)
                    
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    mode="Anyrpid"
                    pinToken, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    mode="withoutpermission.makecredential"
                    permission = 0x02 
                    credId=authParasing(result)
                    pinToken, pubkey,response, status = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    #permission = 0x01  # MakeCredential permission
                    
                    pinToken, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    response, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    #permission = 0x04  # CredentialManagement permission
                    pinToken, pubkey,response, status = getPINtokenwithPermission(mode,pin,permission)
                    #pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                    protocol=2
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    #permission = 0x20  # Authenticator Configuration permission
                    pinToken, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    response, status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "withoutpermission.cm":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                
                    permission = 0x04  # CredentialManagement permission
                    pinToken, pubkey,response,status = getPINtokenwithPermission(mode,pin,permission)
                    #pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                    protocol=2
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    pinToken, pubkey,response,status = getPINtokenwithPermission(mode,pin,permission)
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    # MakeCredential permission
                    pinToken, pubkey,response,status=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    response, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    # pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    # pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    # apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    # result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                elif mode == "withoutpermission.afg":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                
                    permission = 0x20
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    util.APDUhex("80100000010400", "GetInfo .....")
                    #CredentialManagement permission
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                    protocol=2
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)

                    # MakeCredential permission
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    credId="d3630fcd31b33a02a8db15b0875f93cef94e1db65e841c64a7986e329d6049c97d8aa443dcd63d45e993fe4d58bd2f776c88e2fee435aa6a1a47cc8a8c1d4c8d246d1a05dc177fd27a8d8bc68031124080d9e983b6d3448c5fce746b7ae3fb93"
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                elif mode == "permissionalloperation":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    permission = 0x02 
                    credId=authParasing(result)
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

                    
                    permission = 0x04  # CredentialManagement permission
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)
                    #pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
                    protocol=2
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken, pubkey =getPINtokenwithPermission(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    util.APDUhex("80100000010400", "GetInfo .....")
                elif mode == "rpidmatching":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                elif mode == "rpidnotmatching":
                    pin="123456"
                    restPin(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    protocol =2
                    RP_domain="example.com"#wrong
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken,protocol);
                    response, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "35":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    


            else:
                if mode == "withoutpingetpintoken":
                    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                    util.APDUhex("80108000010700", "Reset Card PIN")
                    util.printcolor(util.YELLOW,f"  PIN NOT SET")
                    permission = 0x04  # CredentialManagement permission
                    response,staus=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "35":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)


        elif protocol==1:
            if str(pinset).lower() == "yes": 
                if mode == "cmPermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    pin_token,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode =="acfgPermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # Authenticator Configuration permission
                    pin_token,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "mcPermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pin_token,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "gaPermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x02  # GetAssertion permission
                    pin_token,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "lbwpermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x10  # Large Blob Write permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "40":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_UNAUTHORIZED_PERMISSION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "bepermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x08  # Bio Enrollment permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "40":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_UNAUTHORIZED_PERMISSION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "getpinToken":
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission=4
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "permission.zero":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x00  # zer value  permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifycmper":
                    pin="123456"
                    newpinset(pin)
                    permission = 4  # CredentialManagement permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    subCommand = 0x01  # getCredsMetadata
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    protocol=1
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifyacfgper":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    subCommand = 0x01
                    
                    protocol=1
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation( pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    response,status=util.run_apdu("80100000010400", "GetInfo","00")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifymcper":
                    pin="123456"
                    newpinset(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    response,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifygaper":
                    pin="123456"
                    newpinset(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    response,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    credId=authParasing(response)
                    permission = 0x02  # GetAssertion permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu = createCBORmakeAssertion1(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "InvalidPIN":
                    pin="123456"
                    newpinset(pin)
                    pin="654321" #wrong pin
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission) 
                    if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                if mode == "Invalidkey_agreement" : 
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Invalidpermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x00  # invalid value of permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "InvalidpinHashEnc":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x00  # invalid value of permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Invalidsubcommand":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "3E":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "Invalidprotocol":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingpinHashenc":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingkeyAgreement":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingsubcommand":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingprotocol":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingpermission":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missingrpid":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # Make crdential purpose madetory rpid
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                
                elif mode == "pinauthblocked":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    wrongpin="654321"
                    for i in range(3):
                        response, status=getPINtokenPubkeyfailedp1(mode,wrongpin,permission)
                        if i==2:
                            if response[:2] == "34":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        else:
                            if response[:2] == "31":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                elif mode == "pinauthblocked.pin":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    wrongpin="654321"
                    mode="pinauthblocked"
                    for i in range(3):
                        
                        response, status=getPINtokenPubkeyfailedp1(mode,wrongpin,permission)
                        if i==2:
                            if response[:2] == "34":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        else:
                            if response[:2] == "31":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                    util.printcolor(util.YELLOW, f"Pinauth is in a blocked state even though the user provided the correct PIN: {pin}")
                    response,status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "34":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinretry":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    wrongpin="654321"
                    mode="pinauthblocked"
                    for _ in range(3):
                        response, status=getPINtokenPubkeyfailedp1(mode,wrongpin,permission)
                    util.printcolor(util.YELLOW, f"Pinauth is in a blocked state even though the user provided the correct PIN {pin}")
                    response,status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "34":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                    util.printcolor(util.YELLOW, f"Without Performing power cycle Reset get retries count XX")
                    Setpinp1.pinGetRetries()
                elif mode == "withpowercycle":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    wrongpin="654321"
                    for i in range(3):
                        response, status=getPINtokenPubkeyfailedp1(mode,wrongpin,permission)
                        if i==2:
                            if response[:2] == "34":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        else:
                            if response[:2] == "31":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                    util.printcolor(util.YELLOW, f"With Performing power cycle Reset and User is giving wrong pin:{wrongpin}")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                    response, status=getPINtokenPubkeyfailedp1(mode,wrongpin,permission)
                    if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    Setpinp1.pinGetRetries()
                elif mode == "pinblocked":
                    pin="123456"
                    restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    wrongpin="654321"
                    permission = 0x04  # CredentialManagement permission
                    for i in range(8):
                        
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.APDUhex("00a4040008a0000006472f0001","Select applet")
                        
                        response, status=getPINtokenPubkeyfailedp1(mode,wrongpin,permission)
                        if i==7:
                            if response[:2] == "32":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        else:
                            if response[:2] == "31":
                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                            else:
                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                exit(0)
                        if i==7:
                            util.printcolor(util.YELLOW, f"User entered an incorrect PIN multiple times; the PIN is now blocked: {wrongpin}")
                
                        Setpinp1.pinGetRetries()
                elif mode == "Invalidkey_sharesecret" : 
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    Setpinp1.pinGetRetries()
                elif mode == "platformCOSKEY.notmap":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinHashEnc.notbyte":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "forcepinset":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # authenticator config
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    
                    apdu= newMinPinLengthp1(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    response,status=util.APDUhex("80100000010400", "Get Info")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    response,status=getPINtokenwithPermission2(mode,pin,permission)
                    if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "changepin":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # authenticator config
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    
                    apdu= newMinPinLengthp1(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    util.APDUhex("80100000010400", "Get Info")
                    newpin="65432100"
                    response=Setpinp1.changepin(pin,newpin)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    response,status=util.APDUhex("80100000010400", "Get Info")
                    token, pubkey,response, status=getPINtokenwithPermission(mode,newpin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "forcechangepin.false":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # authenticator config
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    
                    apdu= newMinPinLengthp1false(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    util.run_apdu("80100000010400", "Get Info","00")
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                
                elif mode == "forcechangepin.false1":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # authenticator config
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    subCommand = 0x03
                    
                    apdu= newMinPinLengthp1false(pinToken,subCommand)
                    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    util.run_apdu("80100000010400", "Get Info","00")
                    token, pubkey,response, status=getPINtokenwithPermission(mode,pin,permission)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Invalidrpid":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    clientDataHash=os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    RP_domain="example.com"#wrong
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)


                elif mode == "getpintokenmappingnotsequence":
                    pin="123456"
                    newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 1 # authenticator config
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    



                elif mode == "withoutpermission.getasseration":
                    pin="123456"
                    newpinset(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x01  # MakeCredential permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    credId=authParasing(result)
                    # permission = 0x02  # GetAssertion permission
                    pinToken,response= getPINtokenPubkeynewp1(mode,pin,permission)  #varify the piToken
                    clientDataHash=os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu = createCBORmakeAssertionp1(clientDataHash, RP_domain, pinAuthToken, credId)
                    response, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    # permission = 4  # CredentialManagement permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission)

                    subCommand = 0x01  # getCredsMetadata
                    print("pintoken",pinToken)
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    protocol=1
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    # permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    subCommand = 0x01
                    
                    protocol=1
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation( pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "withoutpermission.makecredential":
                    pin="123456"
                    newpinset(pin)
                    
                    #newpinset(pin)
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x02  # MakeCredential permission
                    mode="withoutpermission"
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    response,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    credId=authParasing(response)
                    # print("credid:----",credId)
                    #credId="d3630fcd31b33a02a8db15b0875f93cef94e1db65e841c64a7986e329d6049c97d8aa443dcd63d45e993fe4d58bd2f776c88e2fee435aa6a1a47cc8a8c1d4c8d246d1a05dc177fd27a8d8bc68031124080d9e983b6d3448c5fce746b7ae3fb93"
                    mode="withoutpermission.makecredential"
                    permission = 0x02  # GetAssertion permission
                    clientDataHash=os.urandom(32)
                    pinToken,response= getPINtokenPubkeynewp1(mode,pin,permission)  #varify the piToken
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    RP_domain="localhost"
                    apdu = createCBORmakeAssertionp1(clientDataHash, RP_domain, pinAuthToken, credId)
                    response, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                    
                    # MakeCredential permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    response,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    #permission = 4  # CredentialManagement permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    subCommand = 0x01  # getCredsMetadata
                    print("pintoken",pinToken)
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    protocol=1
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    #permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    subCommand = 0x01
                    
                    protocol=1
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation( pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "withoutpermission.cm":
                    pin="123456"
                    # CredentialManagement permission
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 4  # CredentialManagement permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission)
                    subCommand = 0x01  # getCredsMetadata
                    print("pintoken",pinToken)
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    protocol=1
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    response,status=util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    # Authenticator Configuration permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    subCommand = 0x01
                    protocol=1
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation( pinUvAuthParam,subCommand,protocol)
                    response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    # MakeCredential permission
                    pinToken,response=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    response,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    # credId="d3630fcd31b33a02a8db15b0875f93cef94e1db65e841c64a7986e329d6049c97d8aa443dcd63d45e993fe4d58bd2f776c88e2fee435aa6a1a47cc8a8c1d4c8d246d1a05dc177fd27a8d8bc68031124080d9e983b6d3448c5fce746b7ae3fb93"
                    # # GetAssertion permission
                    # #permission = 0x02  
                    # pinToken=getPINtokenPubkeynewp1(mode,pin,permission)  #varify the piToken
                    # pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    # apdu = createCBORmakeAssertionp1(clientDataHash, RP_domain, pinAuthToken, credId)
                    # result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                elif mode == "withoutpermission.afg":
                    pin="123456"
                    # Authenticator Configuration permission
                    permission = 0x20
                    clientDataHash=os.urandom(32)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    subCommand = 0x01
                    protocol=1
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation( pinUvAuthParam,subCommand,protocol)
                    util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    util.APDUhex("80100000010400", "GetInfo .....")
                    # CredentialManagement permission
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission)
                    subCommand = 0x01  # getCredsMetadata
                    print("pintoken",pinToken)
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    protocol=1
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    
                    # MakeCredential permission
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    credId="d3630fcd31b33a02a8db15b0875f93cef94e1db65e841c64a7986e329d6049c97d8aa443dcd63d45e993fe4d58bd2f776c88e2fee435aa6a1a47cc8a8c1d4c8d246d1a05dc177fd27a8d8bc68031124080d9e983b6d3448c5fce746b7ae3fb93"
                    # GetAssertion permission
                    #permission = 0x02  
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu = createCBORmakeAssertionp1(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                elif mode == "permissionalloperation":
                    pin="123456"
                    clientDataHash=os.urandom(32)
                    permission = 0x01  # MakeCredential permission
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken)
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    credId=authParasing(result)
                    permission = 0x02  # GetAssertion permission
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    permission = 4  # CredentialManagement permission
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission)
                    subCommand = 0x01  # getCredsMetadata
                    print("pintoken",pinToken)
                    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
                    protocol=1
                    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam,protocol)
                    util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken=getPINtokenPubkeynewp1(mode,pin,permission) #varify the piToken
                    print("pintoken",pinToken.hex())
                    subCommand = 0x01
                    
                    protocol=1
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation( pinUvAuthParam,subCommand,protocol)
                    util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
                    util.APDUhex("80100000010400", "GetInfo .....")
                elif mode == "rpidmatching":
                    pin="123456"
                    newpinset(pin)
                    clientDataHash=os.urandom(32)
                    permission = 0x01  # MakeCredential permission
                    pinToken=getPINtokenPubkeyrpId(mode,pin,permission)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                elif mode == "rpidnotmatching":
                    pin="123456"
                    newpinset(pin)
                    
                    clientDataHash=os.urandom(32)
                    permission = 0x01  # MakeCredential permission
                    pinToken=getPINtokenPubkeyrpId(mode,pin,permission)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    RP_domain="local.host"
                    
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                elif mode == "rpgetasseration":
                    pin="123456"
                    newpinset(pin)
                    clientDataHash=os.urandom(32)
                    permission = 0x01  # MakeCredential permission
                    pinToken=getPINtokenPubkeyrpId(mode,pin,permission)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCredp1(clientDataHash, RP_domain, user, pinAuthToken);
                    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                    credId=authParasing(result)
                    permission = 0x02  # GetAssertion permission
                    pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    RP_domain="example.com"#differnet
                    apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                    

                    
        
                    


            else:#pinnotset
                if mode == "withoutpingetpintoken":
                    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                    util.APDUhex("80108000010700", "Reset Card PIN")
                    util.printcolor(util.YELLOW,f"  PIN NOT SET")
                    permission = 0x04  # CredentialManagement permission
                    response, status=getPINtokenPubkeyfailedp1(mode,pin,permission)  
                    if response[:2] == "35":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

def createCBORmakeAssertionp1(cryptohash, rp, pinAuthToken, credId):
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
    apdu = "80100000" + format(length, '02X') + full_payload+"00"
    return apdu  
def createCBORmakeCredp1(clientDataHash, rp, user, pinAuthToken):

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

    option  = {"rk": False}

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

    APDUcommand = "80100000" +  format(length, '02X') + "01" + dataCBOR+"00"
    return APDUcommand  

def changePin(old_pin, new_pin):
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

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
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response,status


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
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu



def getPINtokenPubkeynewp1(mode,pin,permission):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:")
    response, status = util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True) 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    pin_token,response=createcbor(mode,key_agreement,pinHashEnc,shared_secret,permission)
    return pin_token,response




def getPINtokenPubkeyrpId(mode,pin,permission):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:")
    response, status = util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True) 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    apdu=createcborrp(key_agreement,pinHashEnc,shared_secret,permission)
    return apdu


def getPINtokenPubkeyfailedp1(mode,pin,permission):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:")
    response, status = util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True) 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    subcommand=9
    protocol=1

    if mode == "Invalidkey_agreement" : 
        key_agreement, shareSecretKey = util.wrongkeyagreement(peer_key)
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    if mode == "Invalidkey_sharesecret" :
        key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
        print("sharesecret",shared_secret.hex())
        shared_secret = os.urandom(32) #invalid
        pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
        pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash) 
        
        
        
    elif mode == "InvalidpinHashEnc" : 
        pinHashEnc = os.urandom(32)
    elif mode == "Invalidsubcommand" : 
        subcommand=0
    elif mode == "Invalidprotocol" : 
        protocol=3
    elif mode == "missingpinHashenc" : 
       print("missing missingpinHashenc")
    elif mode == "missingkeyAgreement":
       print("missingkeyAgreement")
    elif mode == "missingsubcommand":
       print("missingkeyAgreement")
    elif mode == "missingprotocol":
        print("missingprotocol")
    elif mode == "missingpermission":
        print("missing permission")
    elif mode == "pinauthblocked":
        util.printcolor(util.YELLOW,f"  PinAuth Is Block User Sending Wrong pin Multiple times:{pin}")
    elif mode == "platformCOSKEY.notmap":
        key_agreement, shared_secret = util.encapsulate_protocolkeyP1(peer_key)
        pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
        pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
        util.printcolor(util.YELLOW, f"platformCOSKEY is notmap : { pinHashEnc.hex()}")
    

    response, status=createGetPINtokenp1(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    return response, status

def createGetPINtokenp1(mode,pinHashEnc,key_agreement,permission,subcommand,protocol):
    

    if mode=="getpinToken":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    
    }
    elif mode == "Invalidsubcommand" : 
         cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    
    }
    elif mode == "missingpinHashenc" : 
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        9:permission
        }
    elif mode == "missingkeyAgreement" : 
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        6: pinHashEnc ,         # pinHashEnc
        9:permission
        }
    elif mode == "missingsubcommand" : 
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission
        }
    elif mode == "missingprotocol" : 
        cbor_map = {
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission
        }
    elif mode == "missingpermission" : 
        cbor_map = {
        1: protocol, 
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
        
        }
    elif mode =="pinHashEnc.notbyte":
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: 12 ,         # pinHashEnc
        9:permission

    }
    elif mode =="missingrpid":
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,        # pinHashEnc
        9:permission,

    }

    else:
        cbor_map = {
        1: protocol,                  # pinProtocol = 1
        2: subcommand,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission

    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x09 GetPINToken", checkflag=True)
    return response, status

def createcbor(mode,key_agreement,pinHashEnc,shared_secret,permission):
    print("mode",mode)
    RP_domain="localhost"
    if mode=="getpintokenmappingnotsequence":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        10:"localhost"

    } 
    elif mode in ("withoutpermission","pinauthoken","Anyrpid"):
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc         # pinHashEnc
        

    } 
    elif mode == "verifycmper":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
    }
    elif mode in ("makeCredUvNotRqdtrue","alwaysuvpinauthparam","resetcommannd","Verfysignature","signaturefailed"):
        
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        10:RP_domain}
    elif mode == "withoutpermission.getasseration" or mode == "withoutpermission.makecredential" or mode == "mcPermission" or mode == "gaPermission" or mode == "verifymcper" or mode == "verifygaper" or mode == "permissionalloperation" or mode =="Anyrpid":
       
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        10:RP_domain

    }
    elif mode in ("makecred","tmakecred"):
        RP_domain="enterprisetest.certinfra.fidoalliance.org"
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        10:RP_domain

    }

    else:
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        # 10:RP_domain

    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x09 GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.pintoken(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token,response

def createcborrp(key_agreement,pinHashEnc,shared_secret,permission):
 
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        10:"localhost"

    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x09 GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.pintoken(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token


            
        
def newpinsetnew(pin):
    
    util.run_apdu("00a4040008a0000006472f0001", "Select Applet")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    #util.run_apdu("80100000010700", "Reset Card PIN","00")
    

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocolP1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False)  # skips min length check
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)

    util.APDUhex("80100000010400", "GetInfo after SetPIN")
           
            





def newpinset(pin):
    
    util.run_apdu("00a4040008a0000006472f0001", "Select Applet")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN","00")
    

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocolP1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False)  # skips min length check
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)

    util.APDUhex("80100000010400", "GetInfo after SetPIN")


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
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
    return apdu







def getPINtokenwithPermission(mode,curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    protocol=2
    subcommand=9


    pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey,hexstring, status

def getPINtokenwithPermission2(mode,curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    subcommand=9
    protocol=2
 
    if mode == "Invalidkey_agreement" : 
        key_agreement, shareSecretKey = util.wrongkeyagreement(decoded_data[1])
        pin_hash    = util.sha256(curpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "InvalidPIN":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "bepermission":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "lbwpermission":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "permission.zero":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "InvalidpinHashEnc":
        pinHashEnc = os.urandom(64)
        print("Invalid pinhashenc: ",pinHashEnc.hex())
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "Invalidsubcommand":
        subcommand=0
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "Invalidprotocol":
        protocol=3
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "Invalidpermission":
        # permission=6
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "Invalidrpid":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)

    elif mode == "missingpinHashenc":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "missingkeyAgreement":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)#createGetPINtokenmissingkeyagrrement(pinHashEnc,permission)
    elif mode == "missingsubcommand":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "missingprotocol":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "missingpermission":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "missingrpid":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)

    elif mode == "pinauthblocked":
        for i in range(3):
            pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
            response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)
            if i==2:
                if response[:2] == "34":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            else:
                if response[:2] == "31":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
    elif mode == "Invalidkey_sharesecret" : 
        key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
        shareSecretKey = os.urandom(64) #invalid
        #util.APDUhex(util.YELLOW,f"Invalid ShareSecret:{shared_secret.hex()}")
        pin_hash    = util.sha256(curpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "platformCOSKEY.notmap":
        key_agreement, shareSecretKey = util.key_agreementnotmap(decoded_data[1])
        pin_hash    = util.sha256(curpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)

    elif mode == "pinHashEnc.notbyte":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)#createGetPINtokennotbyte
    
    
    elif mode == "pinauthblocked.pin":
        util.printcolor(util.YELLOW,f"  Pinauth is Blocked State User providing Correct Pin:{curpin}")
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
        

    elif mode == "withpowercycle":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "pinblocked":
         util.printcolor(util.YELLOW,f"  User Providing Wrong Pin:{curpin}")
         pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    elif mode == "forcepinset":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)





    elif mode == "missingpinauthparam":
         pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)                       #createGetPINtokenmissingparam(key_agreement,permission)
    elif mode == "withoutpingetpintoken":
        pinSetAPDU =createGetPINtoken(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    
    
    elif mode == "subcommandInvalid":
        pinSetAPDU =createGetPINtokenInvalidsub(pinHashEnc,key_agreement,permission)
    
    
    
    elif mode == "changewrongpin":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)


    response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)
    return response,status



def getPINtokenmissingparameter(mode,curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    key_agreement, shareSecretKey = util.wrongkeyagreement(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    #if mode == "piuvauthmissing" : 


    pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    

    


def getPINtokenwithPermission1(mode,curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPINtokenWithoutper(pinHashEnc,key_agreement)
    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)
    return hexstring, status
    
def createGetPINtoken(mode,pinHashenc, key_agreement,permission,subcommand,protocol):
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper()
    cbor_subcommand   = cbor2.dumps(subcommand).hex().upper()
    cbor_protocol   = cbor2.dumps(protocol).hex().upper()
    rpid="example.com"
    cbor_rpid       =cbor2.dumps(RP_domain).hex().upper()
     
    if mode == "Invalidsubcommand":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode == "wrongrpid":
        rpid="localhost"
        cbor_rpid       =cbor2.dumps(rpid).hex().upper()
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
 
    elif mode in ("makecred","tmakecred"):
        rpid="enterprisetest.certinfra.fidoalliance.org"
        cbor_rpid       =cbor2.dumps(rpid).hex().upper()
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode == "Anyrpid":
        subcommand=5
        cbor_subcommand   = cbor2.dumps(subcommand).hex().upper()
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
     
       
   
    elif mode == "pinHashEnc.notbyte":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ "01"#String
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="missingpinHashenc":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="missingkeyAgreement":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="missingsubcommand":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="missingprotocol":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="missingpermission":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode in ("mcPermission","verifymcper","verifygaper","withoutpermission.getasseration","withoutpermission.makecredential"):
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="gaPermission":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="missingrpid":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
       
    elif mode =="permissionalloperation":
       
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="getpintokenmappingnotsequence":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="Invalidpermission":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode =="Invalidrpid":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
       
    else:
       
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
       
 
    length = (len(dataCBOR) >> 1) +1    #have to add the 06
 
    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)
 
    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand
 

# def createGetPINtoken(mode,pinHashenc, key_agreement,permission,subcommand,protocol):
#     platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
#     cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
#     permission_hex   = cbor2.dumps(permission).hex().upper() 
#     cbor_subcommand   = cbor2.dumps(subcommand).hex().upper() 
#     cbor_protocol   = cbor2.dumps(protocol).hex().upper() 
#     rpid="example.com"
#     cbor_rpid       =cbor2.dumps(RP_domain).hex().upper()
     
#     if mode == "Invalidsubcommand":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand 
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode == "pinHashEnc.notbyte":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand 
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ "01"#String
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="missingpinHashenc":
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions 
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="missingkeyAgreement":
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions 
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="missingsubcommand":
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="missingprotocol":
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="missingpermission":
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="mcPermission":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="missingrpid":
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
        
#     elif mode =="permissionalloperation":
        
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="getpintokenmappingnotsequence":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="Invalidpermission":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode =="Invalidrpid":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     elif mode == "gaPermission" or mode == "verifymcper" or mode == "verifygaper" or mode == "withoutpermission.getasseration" or mode == "withoutpermission.makecredential":
#         dataCBOR = "A6"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
#         dataCBOR = dataCBOR + "09"+ permission_hex
#         dataCBOR = dataCBOR + "0A"+ cbor_rpid
#     else:
#         dataCBOR = "A5"
#         dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
#         dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
#         dataCBOR = dataCBOR + "03"+ platformCOSKEY
#         dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
#         dataCBOR = dataCBOR + "09"+ permission_hex
    

#     length = (len(dataCBOR) >> 1) +1    #have to add the 06

#     #util.printcolor(util.BLUE,dataCBOR)
#     #util.hex_string_to_cbor_diagnostic(dataCBOR)

#     APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
#     return APDUcommand



def createGetPINtokennotbyte(pinHashenc, key_agreement,permission):
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ "01" #string 
    dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def createGetPINtokenInvalidsub(pinHashenc, key_agreement,permission):
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "00" #wrong  getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createGetPINtokenmissingparam(key_agreement,permission):
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "09"+ permission_hex
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createGetPINtokenmissingkeyagrrement(pinHashenc,permission):
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def createGetPINtokenWithoutper(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    
    
    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
   

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

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


def getCredsMetadata_APDUp1(subCommand, pinUvAuthParam,protocol):
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
    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu
def enableEnterpriseAttestation(pinUvAuthParam, subCommand,protocol):
    
    

    cbor_map = {
        0x01: subCommand,      # enableEnterpriseAttestation
        0x03:protocol,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu


def createCBORmakeCred(clientDataHash, rp, user,  pinAuthToken,protocol):

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
        }
    ]

    option  = {"rk": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    cbor_protocol                = cbor2.dumps(protocol ).hex().upper()
    dataCBOR = "A7"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ cbor_protocol               # pin protocol V2 assumed

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
            p1 = "80"
            p2 = "00"
            lc = format(len(chunk) // 2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)

        return apdus  # list of chained APDUs
    

    
def authParasing(response):
    print("response",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info = parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credid",credentialId)
    return credentialId



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



def createCBORmakeAssertion(cryptohash, rp, pinAuthToken, credId):
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
    apdu = "80100000" + format(length, '02X') + full_payload+"00"
    return apdu

def createCBORmakeAssertion1(cryptohash, rp, pinAuthToken, credId):
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
    apdu = "80100000" + format(length, '02X') + full_payload+"00"
    return apdu


def restPin(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010700", "Reset Card PIN")
    util.APDUhex("80100000010400", "GetInfo")
    setpin(pin)


def setpin(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    
 
    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)




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
 
        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
        return APDUcommand


def newMinPinLength(pinToken, subCommand):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: True   # forcePINChange = True requied pin change
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

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu

def newMinPinLengthp1(pinToken, subCommand):
    subCommandParams = {
        0x01: 8,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: True   # forcePINChange = True requied pin change
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)

    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu
def newMinPinLengthp1false(pinToken, subCommand):
    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: False   # forcePINChange = True requied pin change
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)

    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (16 bytes) + 0d01
    # Compute pinUvAuthParam using HMAC-SHA256, full 16 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu