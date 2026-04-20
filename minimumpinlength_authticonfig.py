import util
import cbor2
import binascii
import os
import struct
import getpintokenpermissionp2
import Setpinp1
import getpintokenCTAP2_2
import getpinauthtokenP1
import pprint
from textwrap import wrap
import DocumentCreation
RP_domain          = "localhost"
user="bobsmith"
import toggleAlwaysUv
import authenticatorConfig
import enableEnterpriseAttestationctap2
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR CONFIG(MINIMUM PIN LENGTH)"
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

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
        "getinfo":"""Test started: P-1 :
        Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
Test Step:

Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send the GetInfo command to verify the default minimum PIN length.
Expected result: The authenticator returns CTAP2_OK.""",

"getinfowithoutpin":"""Test started: P-2 :
        Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:

Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send the GetInfo command to verify the default minimum PIN length.
Expected result: The authenticator returns CTAP2_OK.""",
"newpinlength":"""Test started: P-3 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
4.forcechangepin=false
Test Step:
Step 1:
Send GetInfo command default minimumpinlength . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig (0x0D) with the setMinPINLength (0x03) subcommandparam newMinPINLength (0x01) to increase the current minimum PIN length (for example, from 6 to 8).
Expected result: The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify whether the minimum PIN length value has changed.
Expected result:
1.The authenticator returns CTAP2_OK.
2.minimunpinlength is =8
3.forcechangepin=false""",

"newpinlengthwithpin":"""Test started: P-4 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.forcechangepin=false
Test Step:
Step 1:
Send GetInfo command default minimumpinlength . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig (0x0D) with the setMinPINLength (0x03) subcommandparam newMinPINLength (0x01) to increase the current minimum PIN length (for example, from 6 to 8).
Expected result: The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify whether the minimum PIN length value has changed.
Expected result:
1.The authenticator returns CTAP2_OK.
2.minimunpinlength is =8
3.forcechangepin=True""",

"forcechangepinTrue":"""Test started: P-5 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send the AuthenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommandparam forcechange (0x03) and set forceChangePin (0x03) to false.
Expected result:
The authenticator returns CTAP2_OK.
Step 2:
Send the AuthenticatorConfig (0x0D) command again with the setMinPINLength (0x03) subcommand.
Set newMinPINLength (0x01) to increase the current minimum PIN length to the maximum supported PIN length (for example, from 6 to 63).
Expected result: 
The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify that the minimum PIN length value has been updated.
Expected result:
1.The authenticator returns CTAP2_OK.
2.minimunpinlength is =63
3.forcechangepin=False""",


"forcechangepinTruewithpin":"""Test started: P-6 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send the AuthenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommandparam forcechange (0x03) and set forceChangePin (0x03) to true.
Expected result:
The authenticator returns CTAP2_OK.
Step 2:
Send the Changepin command (0x04).the authenticator return the CTAP2_OK.
Step 3:
Send the AuthenticatorConfig (0x0D) command again with the setMinPINLength (0x03) subcommand.
Set newMinPINLength (0x01) to increase the current minimum PIN length to the maximum supported PIN length (for example, from 6 to 63).
Expected result: 
The authenticator returns CTAP2_OK.
Step 4: Verification
Send the GetInfo command again to verify that the minimum PIN length value has been updated.
Expected result:
1.The authenticator returns CTAP2_OK.
2.minimunpinlength is =63
3.forcechangepin=True""",

"forcechangepinSetTrue":"""Test started: P-7 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send the AuthenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommandparam forcechange (0x03) and set forceChangePin (0x03) to true.
Expected result:
The authenticator returns CTAP2_OK.
Step 2:
Send the Changepin command (0x04).the authenticator return the CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify that the minimum PIN length value has been updated.
Expected result:
1.The authenticator returns CTAP2_OK.
3.forcechangepin=True""",

"Authrizedrp":"""Test started: P-8 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)w RPIDs set to (example.com), and see that authenticator succeeds .
Expected result: The authenticator returns CTAP2_OK.
Step 2:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID that is included in the authorized list (e.g., "example.com").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <current_minimum_value>""",

"Authrizedrpwithpinlengthset":"""Test started: P-9 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)w RPIDs set to (example.com), and increase the current minimum PIN length to the maximum supported PIN length see that authenticator succeeds .
subCommandParams = {0x01: 8,
0x02: ["example.com"] }
Expected result: The authenticator returns CTAP2_OK.
Step 2:
Send the Changepin command (0x04).the authenticator return the CTAP2_OK.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID that is included in the authorized list (e.g., "example.com").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <current_minimum_value>""",

"Authrizedrpwithallparam":"""Test started: P-10 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)w RPIDs set to (example.com), and increase the current minimum PIN length to the maximum supported PIN length see that authenticator succeeds .
subCommandParams = {0x01: 8,
0x02: ["example.com"] ,
0x03:True}
Expected result: The authenticator returns CTAP2_OK.
Step 2:
Send the Changepin command (0x04).the authenticator return the CTAP2_OK.
Step 3:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID that is included in the authorized list (e.g., "example.com").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains an "extensions" field.
3.The "extensions" field includes:"minPinLength": <current_minimum_value>""",

"unAuthrizedrp":"""Test started: P-11 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)w RPIDs set to (example.com), and see that authenticator succeeds .
Expected result: The authenticator returns CTAP2_OK.
Step 2:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID that is included in the unauthorized list (e.g., "local.host").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response contains no "extensions" field.""",

"resetauthenticator":"""Test started: P-12 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)w RPIDs set to (example.com), and increase the current minimum PIN length to the maximum supported PIN length see that authenticator succeeds .
subCommandParams = {0x01: 8,
0x02: ["example.com"] ,
0x03:True}
Expected result: The authenticator returns CTAP2_OK.
Step 2:
Send the Changepin command (0x04).the authenticator return the CTAP2_OK.
Step 3:
Send authenticator reset command(0x07).the authenticator return CTAP2_OK.
Step 4:
Create a new credential using authenticatorMakeCredential (0x01) with the extensions field containing:
minPinLength": true 
Use an RP ID  (e.g., "example.com").Verify that the operation succeeds and that the response contains the extension output.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS.
2.The response no "extensions" field.""",


"pincomplexity":"""Test started: P-13 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.pincomplexity=false

Test Step:
Step 1:
Send GetInfo command default pincomplexity . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig (0x0D) with the setMinPINLength (0x03) subcommandparam pinComplexityPolicy (0x04) Set to True.
Expected result: The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify whether thepincomplexity value has changed.
Expected result:
1.The authenticator returns CTAP2_OK.
2.pincomplexity=True""",


"pincomplexityapplication":"""Test started: P-14 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.pincomplexity=false


Test Step:
Step 1:
Send GetInfo command default pincomplexity . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig (0x0D) with the setMinPINLength (0x03) subcommandparam pinComplexityPolicy (0x04) Set to True and RP ID (example.com) set.
Expected result: The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify whether thepincomplexity value has changed.
Expected result:
1.The authenticator returns CTAP2_OK.
2.pincomplexity=True
Step 4: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 5: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=true""",


"pincomplexityapplicationfalse":"""Test started: P-15 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.pincomplexity=false


Test Step:
Step 1:
Send GetInfo command default pincomplexity . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig (0x0D) with the setMinPINLength (0x03) all subcommandparam  RP ID (example.com) set.
Expected result: The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify whether the pincomplexity value .is default or not
Expected result:
1.The authenticator returns CTAP2_OK.
2.pincomplexity=false
Step 4: (Create Credential with pinComplexityPolicy Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with the option rk = true.
Include the following extension in the request:
"pinComplexityPolicy": true
The rp.id must be part of the authorized RP ID list (example.com).
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticator returns contains "extensions" field in the authenticatorMakeCredential response.
Step 5: (Verify the PIN Complexity Policy)
Send the authenticatorGetInfo (0x04) command to the authenticator.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response includes the extensions field (0x02).
3.The "pinComplexityPolicy" extension is present in the list of supported extensions.
4.response  pinComplexityPolicy=false""",





"pinlengthdecreses":"""Test started: F-1 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.forcechangepin=false
Test Step:
Step 1:
Send GetInfo command default minimumpinlength . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig (0x0D) with the setMinPINLength (0x03) subcommandparam newMinPINLength (0x01) to decreses the current minimum PIN length (for example, from 6 to 4).
Expected result: The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",
"forcepintruepin":"""Test started: F-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)w RPIDs set to (example.com), and increase the current minimum PIN length to the maximum supported PIN length see that authenticator succeeds .
subCommandParams = {0x01: 8},
Expected result: The authenticator returns CTAP2_OK.
Step 3: Verification
Send the GetInfo command again to verify that the minimum PIN length value has been updated.
Expected result:
1.The authenticator returns CTAP2_OK.
3.forcechangepin=True
Step 3:
Send the Changepin command (0x04).the authenticator return the CTAP2_ERR_PIN_NOT_SET..""",


"keystoragefull":"""Test started: F-3 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false
Step 1:
Send authenticatorConfig (0x0D) with setMinPINLength (0x03) subcommandparam minPinLengthRPIDs(0X02)the maximum number of RP IDs has been reached(example.com,fidoalliance.com), it returns CTAP2_ERR_KEY_STORE_FULL .
Expected result: The authenticator returns CTAP2_ERR_KEY_STORE_FULL""",


"missingpinauthparam":"""Test started: F-4 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: The pinAuthParam is missing in this request.
Expected result: The authenticator returns CTAP2_ERR_PUAT_REQUIRED.""",

"protocolmissing":"""Test started: F-5 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: The protocol  is missing in this request.
Expected result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"subcommandismissing":"""Test started: F-6 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: The subcommand  is missing in this request.
Expected result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"subcommandparamismissing":"""Test started: F-7 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams  is missing in this request.
Expected result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"invalidpinauthparam":"""Test started: F-8 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: pinAuthParam is invalid in this request.
Expected result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",


"pinauthparamlengthinvalid":"""Test started: F-9 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: pinAuthParamlength  is invalid(protocol 1=32 byte protocol 2=16 byte ) in this request.
Expected result: The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",


"pinauthparamlengthless":"""Test started: F-9 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: pinAuthParamlength  is invalid(protocol 1=10 byte protocol 2=10 byte ) in this request.
Expected result: The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",

"invalidprotocol":"""Test started: F-10 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: invalid protocol.
Expected result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",


"invalidsubcommand":"""Test started: F-11 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: The subcommand  is missing in this request.
Expected result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",


"invalidsubcommandparam":"""Test started: F-12 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
4.The GetInfo response indicates:
    1.minPINLength = 6
    2.forcePINChange = false

Test Step:
Step 1:
Step 1:
Send the authenticatorConfig (0x0D) command with the setMinPINLength (0x03) subcommand. Include the parameter minPinLengthRPIDs (0x02) with RPIDs set to "example.com", and increase the current minimum PIN length to the maximum supported value. Verify that the authenticator processes the request successfully.
subCommandParams = {
  0x01: 8,
  0x02: ["example.com"],
  0x03: True
}
Note: The subcommandparam  is missing in this request.
Expected result: The authenticator returns CTAP1_ERR_INVALID_COMMAND.""",











}
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode]) 
    util.printcolor(util.YELLOW, descriptions[mode])
    util.printcolor(util.YELLOW, "****  Precondition authenticatorMakeCredential (0x01) Extension thirdPartyPayment CTAP2.2 ****")
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN")
    response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
    
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
                util.printcolor(util.YELLOW, f"****  authenticatorConfig (0x0D)subcommand setMinPINLength(0x03) CTAP2.2 For Protocol-{protocol}")
                if mode =="getinfo":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                else: 
                    if mode in("newpinlengthwithpin","forcechangepinTruewithpin","forcechangepinSetTrue","Authrizedrp","Authrizedrpwithpinlengthset","Authrizedrpwithallparam","unAuthrizedrp","resetauthenticator","pincomplexity","pincomplexityapplication","pincomplexityapplicationfalse","pinlengthdecreses","keystoragefull","missingpinauthparam","protocolmissing","subcommandismissing","subcommandparamismissing","invalidpinauthparam","pinauthparamlengthinvalid","pinauthparamlengthless","invalidprotocol","invalidsubcommand","invalidsubcommandparam"):
                        subCommand = 0x03
                        if mode in ("forcechangepinTruewithpin"):
                            forcechangepin(mode,pin,subCommand,protocol) 
                            newpin="654321"
                            if protocol ==1:
                                apdu=changepinP1(pin,newpin,protocol)
                            else:
                                apdu=changePin(pin,newpin,protocol) 
                            util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")                 
                            pin=newpin
                            subCommandParams = {0x01: 63 }
                        elif mode =="forcechangepinSetTrue":
                            subCommandParams = {0x03: True }
                        elif mode =="Authrizedrpwithpinlengthset":
                            subCommandParams ={0x01: 8,
                                0x02: ["example.com"]}
                        elif mode in ("Authrizedrpwithallparam","resetauthenticator","missingpinauthparam","protocolmissing","subcommandismissing","subcommandparamismissing","pinauthparamlengthinvalid","pinauthparamlengthless","invalidprotocol","invalidsubcommand"):
                            subCommandParams ={0x01: 8,
                                0x02: ["example.com"],
                                0X03:True}
                        elif mode =="invalidsubcommandparam":
                            subCommandParams =0

                    elif mode in ("Authrizedrp","unAuthrizedrp"):
                        subCommandParams ={0x02: ["example.com"]}
                    elif mode =="pinlengthdecreses":
                        subCommandParams = {0x01: 4 }
                    elif mode =="keystoragefull":
                        subCommandParams ={0x02: ["example.com","fidoaaliance.com"]}
                    elif mode =="pincomplexity":
                        subCommandParams = {0x04: True}
                    elif mode =="pincomplexityapplication":
                        subCommandParams = {0x02: ["example.com"],0x04: True}
                    elif mode =="pincomplexityapplicationfalse":
                        subCommandParams = {0x02: ["example.com"],0x04: False}

                    else:
                        subCommandParams = {0x01: 8 }

                        subCommandParams_cbor = cbor2.dumps(subCommandParams)
                        message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
                        print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                        subcommandper=0x09
                        if protocol ==1:
                            pinToken=getPINtokenp1(mode,pin,subcommandper,protocol)
                            pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                        elif protocol ==2 :
                            pinToken=getPINtokenp2(mode,pin,subcommandper,protocol)
                            pinUvAuthParam = util.hmac_sha256(pinToken, message)[:32]
                        if mode in ("invalidpinauthparam","pinauthparamlengthinvalid","pinauthparamlengthless"):
                            if protocol ==1:
                                if mode =="invalidpinauthparam":
                                    pinUvAuthParam = os.urandom(16)
                                elif mode =="pinauthparamlengthinvalid":
                                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:32]
                                elif mode =="pinauthparamlengthless":
                                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:10]
                                


                            else:
                                if mode =="invalidpinauthparam":
                                    pinUvAuthParam =os.urandom(32)
                                elif mode =="pinauthparamlengthinvalid":
                                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                                elif mode =="pinauthparamlengthless":
                                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:10]
                        if mode =="invalidprotocol":
                            protocol=0
                        if mode =="invalidsubcommand":
                            subCommand = 0x00
                        



                        apdu=newMinPinLengthwithpin(mode,subCommand,subCommandParams,protocol,pinUvAuthParam)
                        if mode in ("pinlengthdecreses","keystoragefull","missingpinauthparam","protocolmissing","subcommandismissing","subcommandparamismissing","invalidpinauthparam","pinauthparamlengthinvalid","pinauthparamlengthless","invalidprotocol","invalidsubcommand","invalidsubcommandparam"):
                            if mode =="keystoragefull":
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="28",expected_error_name="CTAP2_ERR_KEY_STORE_FULL" )
                            elif mode =="pinlengthdecreses":
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="37",expected_error_name="CTAP2_ERR_PIN_POLICY_VIOLATION." )
                            elif mode =="missingpinauthparam":
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED" )
                            elif mode in("protocolmissing","subcommandismissing","subcommandismissing","subcommandparamismissing"):
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER" )
                            elif mode in("invalidpinauthparam"):
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID" )
                            elif mode in("pinauthparamlengthinvalid","pinauthparamlengthless"):
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH" )
                            elif mode in ("invalidprotocol","invalidsubcommand"):
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER" )
                            # elif mode =="invalidsubcommand":
                            #     response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="01",expected_error_name="CTAP1_ERR_INVALID_COMMAND" )
                            elif mode =="invalidsubcommandparam":
                                response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE" )

                            return response

                    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam MinPINLength",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                    if mode =="resetauthenticator":
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        response,status=util.run_apdu("80100000010700", "Reset CCard", "00")
                        response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                        getinforesponse(response)
                    if mode in ("pincomplexityapplication","pincomplexityapplicationfalse"):
                        clientDataHash=os.urandom(32)
                        subcommandper=0x09
                        if mode =="pincomplexityapplicationfalse1":
                            extension = {"pinComplexityPolicy": False}


                        else:
                            extension = {"pinComplexityPolicy": True}
                        mode="pincomplexapp"
                        if protocol ==1:
                            pinToken=getPINtokenp1(mode,pin,subcommandper,protocol)
                            pinUvAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:16]
                        elif protocol ==2 :
                            pinToken=getPINtokenp2(mode,pin,subcommandper,protocol)
                            pinUvAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:32]
                        else:
                            print("protocol not matching")
                            exit(0)
                        username="bobsmith"
                        
                        
                        rp="example.com"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinUvAuthParam,protocol,extension)
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        credId, credentialPublicKey = authParasing(response)
                        cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        return extensions


                        if mode in("forcechangepinSetTrue","Authrizedrpwithpinlengthset","Authrizedrpwithallparam"):
                            newpin="65432111"
                            if protocol ==1:
                                apdu=changepinP1(pin,newpin,protocol)
                            else:
                                apdu=changePin(pin,newpin,protocol) 
                            util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")                 
                            pin=newpin
                        if mode in ("Authrizedrp","Authrizedrpwithpinlengthset","Authrizedrpwithallparam","unAuthrizedrp","resetauthenticator"):
                            if mode =="unAuthrizedrp":
                                rpids="localhost"
                            else:
                                rpids="example.com"
                            apdu=rpid(protocol,pin,rpids,mode)
                            response, status = util.run_apdu(apdu, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                            credId, credentialPublicKey = authParasing(response)
                            cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)
                            util.printcolor(util.YELLOW, f"Extensions: {extensions}")




        else:
            util.printcolor(util.YELLOW, f"****  authenticatorConfig (0x0D)subcommand setMinPINLength(0x03) CTAP2.2 For Protocol-{protocol}")
            if mode =="getinfowithoutpin":
                response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                getinforesponse(response)
            else: 
                    if mode in("newpinlength","forcechangepinTrue","forcepintruepin"):
                        subCommand = 0x03
                        if mode in ("forcechangepinTrue"):
                            forcepin(subCommand)
                            subCommandParams = {
                            0x01: 63 }
                        else:
                            subCommandParams = {0x01: 8 }
                    apdu=newMinPinLength(subCommand,subCommandParams)
                    util.APDUhex(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam newMinPINLength(0x01)", checkflag=True)
                    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam newMinPINLength(0x01)",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                    if mode =="forcepintruepin":
                        newpin="654321"
                        if protocol ==1:
                            apdu=changepinP1(pin,newpin,protocol)
                        else:
                            apdu=changePin(pin,newpin,protocol) 
                        util.run_apdu(apdu, "Client PIN subcmd 0x04 ChangePIN", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")                 
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1              




def rpid(protocol,pin,rp,mode):
    subcommandper=0x05
    clientDataHash=os.urandom(32)
    if mode =="resetauthenticator":
        pinUvAuthParam="null"
        username="bobsmith"
        extension = {"minPinLength": True}
        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinUvAuthParam,protocol,extension)
        return makeCredAPDU
    mode ="withoutpermission"
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommandper,protocol)
        pinUvAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:16]
    elif protocol ==2 :
        pinToken=getPINtokenp2(mode,pin,subcommandper,protocol)
        pinUvAuthParam = util.hmac_sha256(pinToken, clientDataHash)[:32]
    
    
    username="bobsmith"
    extension = {"minPinLength": True}
    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinUvAuthParam,protocol,extension)
    return makeCredAPDU

def forcechangepin(mode,pin,subCommand,protocol):
    subCommandParams = {0x03: True }
    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
    subcommandper=0x09
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommandper,protocol)
        pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommandper,protocol)
        pinUvAuthParam = util.hmac_sha256(pinToken, message)[:32]
        apdu=newMinPinLengthwithpin(mode,subCommand,subCommandParams,protocol,pinUvAuthParam)
        response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam forceChangePin(0x03)",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
           
def forcepin(subCommand):
    subCommandParams = {0x03: False }
    apdu=newMinPinLength(subCommand,subCommandParams)
    response, status = util.run_apdu(apdu, "authenticatorConfig(0x0D) :  setMinPINLength(0x03) subcommandparam forceChangePin(0x03)", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")


def changePin(old_pin, new_pin,protocol):
    
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo","00")

    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.run_apdu("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")

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

    apdu = createCBORchangePIN(pinHashEnc, newPinEnc, pinAuth, key_agreement,protocol)
    return apdu
def changepinP1(pin,newpin,protocol):
    response, status =util.run_apdu("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    
    current_pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, current_pin_hash)

    padded_new_pin = util.pad_pin_P1(newpin)
    newPinEnc = util.aes256_cbc_encryptP1(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = util.hmac_sha256P1(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN(pinHashEnc, newPinEnc, pinAuth, key_agreement,protocol)
    return apdu

def createCBORchangePIN(pinHashEnc, newPinEnc, pinAuth, key_agreement,protocol):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: protocol,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu              

def newMinPinLengthwithpin(mode,subCommand,subCommandParams,protocol,pinUvAuthParam):
    
    # if mode =="pinlength.change":
    #     cbor_map = {
    #         0x01: subCommand,      # newMinPINLength
    #         0x02: subCommandParams,
                
    #     }
    # elif mode =="pinauthparam.missing":
    #     cbor_map = {
    #         0x01: subCommand,      # newMinPINLength
    #         0x02:subCommandParams,
    #         0x03: protocol             # pinUvAuthProtocol = 2
            
    # }
    # elif mode =="pinUvAuthProtocol.missing":
    #     cbor_map = {
    #         0x01: subCommand,      # newMinPINLength
    #         0x02:subCommandParams,
    #         0x04: pinUvAuthParam
                        
    # }
        
    if mode =="missingpinauthparam":
        cbor_map = {
            0x01: subCommand,      # newMinPINLength
            0x02:subCommandParams,
            0x03: protocol,                    
    }
    elif mode =="protocolmissing":
        cbor_map = {
            0x01: subCommand,      # newMinPINLength
            0x02:subCommandParams,
            0x04: pinUvAuthParam
                        
    }
    elif mode =="subcommandismissing":
        cbor_map = {
            0x02:subCommandParams,
            0x03: protocol,
            0x04: pinUvAuthParam
                        
    }
    elif mode =="subcommandparamismissing":
        cbor_map = {
            0x01: subCommand,
            0x03: protocol,
            0x04: pinUvAuthParam
                        
    }


    else:
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
def newMinPinLength(subCommand,subCommandParams):
    
    cbor_map = {
            0x01: subCommand,      # newMinPINLength
            0x02: subCommandParams,


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
           
import hashlib
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
    permission=0x20
    if mode =="withoutpermission": 
        cbor_map = {
                1: protocol,                  # pinProtocol = 1
                2: subcommand,                  # subCommand = 0x05 (getPINToken)
                3: key_agreement,      # keyAgreement (MAP)
                6: pinHashEnc         # pinHashEnc
                }
    elif mode =="pincomplexapp":
        permission=0x01
        rp="example.com"
        cbor_map = {
            1: protocol,                  # pinProtocol = 1
            2: subcommand,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc ,        # pinHashEnc
            9: permission,
            10: rp
            }

    else:

        cbor_map = {
            1: protocol,                  # pinProtocol = 1
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



def getinforesponse(response):
    """
    Parse CTAP2 GetInfo response and report:
        - clientPin support
        - pinComplexity
        - minPINLength (0x0D)
        - forcePINChange (0x0C)
    """

    # Convert hex string to bytes if needed
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

    # ---- Client PIN & PIN Complexity (options -> 0x04) ----
    options = decoded.get(0x04, {})

    client_pin = options.get("clientPin")
    pin_complexity = options.get("pinComplexity")

    if client_pin is not None:
        util.printcolor(util.GREEN, f"clientPin supported = {client_pin}")
    else:
        util.printcolor(util.YELLOW, "clientPin option not present")

    

    # ---- minPINLength (0x0D) ----
    min_pin_length = decoded.get(0x0D)
    if min_pin_length is not None:
        util.printcolor(util.GREEN, f"minPINLength = {min_pin_length}")
    else:
        util.printcolor(util.YELLOW, "minPINLength not present")

    # ---- forcePINChange (0x0C) ----
    force_pin_change = decoded.get(0x0C)
    if force_pin_change is not None:
        util.printcolor(util.GREEN, f"forcePINChange = {force_pin_change}")
    else:
        util.printcolor(util.YELLOW, "forcePINChange not present")
    # ---- pinComplexity (0x1B / 27) ----
    pin_complexity = decoded.get(0x1B)

    if pin_complexity is not None:
        util.printcolor(util.GREEN, f"pinComplexity = {pin_complexity}")
    else:
        util.printcolor(util.YELLOW, "pinComplexity not present")

    return {
        "clientPin": client_pin,
        "pinComplexity": pin_complexity,
        "minPINLength": min_pin_length,
        "forcePINChange": force_pin_change
    }
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
    if pinAuthToken =="null":
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