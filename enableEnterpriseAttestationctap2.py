import util
import cbor2
import binascii
import Setpinp22
import os
import credentialManagement
import credBlob
import struct
import getpintokenCTAP2_2
import Setpinp1
import getpintokenpermissionp2
from textwrap import wrap
import make_credential_request
import getpinauthtokenP1
import toggleAlwaysUv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import DocumentCreation

RP_domain          = "localhost"
user="bobsmith"
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR CONFIG(ENABLE ENTERPRISE ATTESTATION)"
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

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
       "enable.atttrue": """Test started: P-1 : 
Test Step:
 If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
GetInfo.options.ep is set to true. The authenticator returning CTAP2_OK.""", 


"epundefined": """Test started: P-2: 
FOR ENTERPRISE PROFILE
If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by checking that GetInfo.options.ep options is not undefined!""",

"tmakecred":"""Test started: P-3: 
FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that:
        1) Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        2) Attestation.fmt is "packed"
        3) Attestation.attStmt.x5c batch certificate list is exactly 1 certificate long
        4) Attestation.attStmt.x5c fist certificate matches the required for test EPBatchCertificate
        b) Attestation.epAtt is a boolean and is set to true.""",
"attep2":"""Test started: P-4: 
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x02, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
Expected Result: The authenticator returns CTAP2_OK.""",
"randomep":"""Test started: F-1: 
FOR ENTERPRISE PROFILE
 If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to RANDOM TYPE, wait for the response, and check that Authenticator returns an error. CTAP2_ERR_INVALID_OPTION.
Expected Result: The authenticator returns  CTAP2_ERR_INVALID_OPTION.""",
"epincorrect":"""Test started: F-2: 
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, 
RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to a number that is NOT 0x01 and NOT 0x02, wait for the response, and check that Authenticator returns CTAP2_ERR_INVALID_OPTION(0x2C) error code.""",
"invalidrp":"""Test started: F-3: 
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with,
RPID set to the WRONG RPID(enterprisetest.certinfra.fidoalliance.org),and enterpriseAttestation set 0x01, wait for the response, 
and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

         "enable.attestation": """Test started: P-5 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
GetInfo.options.ep is set to true. The authenticator returning CTAP2_OK.""",  

"epfalse.subcommandmissing": """Test started: P-5 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01) and protocol param is paresent subcommand is missing.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"epfalse.subcommandinvalid": """Test started: P-6 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01) but providing invalid sucommand.
Expected Result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"always uvtrue": """Test started: P-7 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Always Uv=True.

Test Step:
Step 1:
Send GetInfo command options.ep =False and  alwaysUv =True. The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01). If pinUvAuthParam is absent from the input map, then end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
Expected Result: The authenticator returns CTAP2_ERR_PUAT_REQUIRED.""",


"always uvtrue.protocolmissing": """Test started: P-8 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Always Uv=True.

Test Step:
Step 1:
Send GetInfo command options.ep =False and  alwaysUv =True. The authenticator returning CTAP2_OK.a
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:Send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01). If pinUvAuthProtocol is absent from the input map, then end the operation by returning CTAP2_ERR_MISSING_PARAMETER.
Expected Result: The authenticator returns  CTAP2_ERR_MISSING_PARAMETER.""",

"always uvtrue.protocolinvalid": """Test started: P-9 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Always Uv=True.

Test Step:
Step 1:
Send GetInfo command options.ep =False and  alwaysUv =True. The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:Send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01). If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
Expected Result: The authenticator returns  CTAP1_ERR_INVALID_PARAMETER.""",


"alwaysuvtrue.verificationfailed": """Test started: P-10 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Always Uv=True.

Test Step:
Step 1:
Send GetInfo command options.ep =False and  alwaysUv =True. The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:Send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01). if verification is failed , return CTAP2_ERR_PIN_AUTH_INVALID.
Expected Result: The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",


"alwaysuvtrue.afgpermission": """Test started: P-11 : 
Precondition:
1.The authenticator supports Authenticator config=true
2.Always Uv=True.

Test Step:
Step 1:
Send GetInfo command options.ep =False and  alwaysUv =True. The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request without providing acfg permission..
Expected Result: The authenticator returns CTAP2_OK.
Step 4:Send authenticatorConfig(0x0D) subcommand  enableEnterpriseAttestation(0x01). Check whether the pinUvAuthToken has the acfg permission. If not, return CTAP2_ERR_PIN_AUTH_INVALID.
Expected Result: The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",


"enableattestaion.getinfo": """Test started: P-12: 
Precondition:
1.The authenticator supports Authenticator config=true
2Authenticator must Reset/No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4: If authenticator supports enteprise attestation, send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01).
Expected Result: The authenticator returns CTAP2_OK.
Step 5:(Verify)
GetInfo.options.ep is set to true. The authenticator returning CTAP2_OK.""",


"missing.protocol": """Test started: F-4: 
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator have a pin.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01), but omit the protocol parameter.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER .""",

"missing.pinUvAuthParam": """Test started: F-5: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01), but omit the pinUvAuthParam parameter.
Expected Result: The authenticator returns CTAP2_ERR_PUAT_REQUIRED .""",

"missing.subcommand": """Test started: F-6: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation subcomaand is omit .
Expected Result: The authenticator returns  CTAP2_ERR_MISSING_PARAMETER .""",

"invalidsubcomaand": """Test started: F-7: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation invalidsubcomaand  .
Expected Result: The authenticator returns  CTAP1_ERR_INVALID_PARAMETER.""",

"invalidprotocol": """Test started: F-8: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand, but use an invalid protocol value..
Expected Result: The authenticator returns  CTAP1_ERR_INVALID_PARAMETER.""",


"makecred": """Test started: p-13: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 6:FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that:
        1) Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        2) Attestation.fmt is "packed"
        3) Attestation.attStmt.x5c batch certificate list is exactly 1 certificate long
        4) Attestation.attStmt.x5c fist certificate matches the required for test EPBatchCertificate
        b) Attestation.epAtt is a boolean and is set to true.""",
"makecredepfalse": """Test started: F-9: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 4:FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that:
        1) Authenticator returns  error code CTAP1_ERR_INVALID_PARAMETER.""",
        


"attestion2": """Test started: p-14: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK..
Step 6:
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x02, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
Expected Result: The authenticator returns CTAP2_OK.""",


"attestion2epfalse": """Test started: F-10: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK..
Step 4:
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with,
RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x02, wait for the response, and check that Authenticator returns Authenticator returns  error code CTAP1_ERR_INVALID_PARAMETER.
Expected Result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",



"randomattestion": """Test started: F-11: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.

Step 6:FOR ENTERPRISE PROFILE
 If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to RANDOM TYPE, wait for the response, and check that Authenticator returns an error. CTAP2_ERR_INVALID_OPTION.
Expected Result: The authenticator returns  CTAP2_ERR_INVALID_OPTION.""",



"exceptattestion": """Test started: F-12: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 3:
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, 
RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to a number that is NOT 0x01 and NOT 0x02, wait for the response, and check that Authenticator returns CTAP2_ERR_INVALID_OPTION(0x2C) error code.""",

"Anyrpid": """Test started: P-15: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthToken (0x05) request.
Expected result: The authenticator returns CTAP2_OK.
Step 6 (Enterprise Profile):
If the vendor selects the Security Enterprise Profile, verify that the authenticator supports 
Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential (0x01) request with any RP ID set and enterpriseAttestation set to 0x01. 
Wait for the response and confirm that the authenticator returns CTAP2_OK.""",

"wrongrpid": """Test started: F-13: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.

Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID(localhost).
Expected result: The authenticator returns CTAP2_OK.                
Step 4:
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with,
RPID set to the WRONG RPID(enterprisetest.certinfra.fidoalliance.org),and enterpriseAttestation set 0x01, wait for the response, 
and check that Authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",






"verifyfailed": """Test started: F-14: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes an incorrect permission value (i.e., a value other than 0x20 for authenticatorConfig).
Expected Result:
The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01).If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"epvaluewrong": """Test started: F-15: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.               

Step 6:
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with,
RPID set to the  RPID(enterprisetest.certinfra.fidoalliance.org),and enterpriseAttestation set 0x05, wait for the response, 
and check that Authenticator returns CTAP2_ERR_UNAUTHORIZED_PERMISSION.
The authenticator responds with CTAP2_ERR_UNAUTHORIZED_PERMISSION.""",

"invalidpinauthparam": """Test started: F-16: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01), but provide an invalid pinUvAuthParam .
Expected Result:
The authenticator responds with CTAP2_ERR_PIN_AUTH_INVALID.""",


"messagelengthless": """Test started: F-17: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01), but provide an  the pinAuthParam data is required (16 bytes for PIN protocol 1 and 32 bytes for PIN protocol 2)but a shorter length is provided.
Expected Result:
The authenticator responds with CTAP1_ERR_INVALID_LENGTH.""",


"messagelengthgreater": """Test started: F-18: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.

Step 4:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01), but provide an  the pinAuthParam data is required (16 bytes for PIN protocol 1 and 32 bytes for PIN protocol 2)but a pinUvAuthParam with a length greater than the required size is provided.
Expected Result:
The authenticator responds with CTAP1_ERR_INVALID_LENGTH.""",

"messageformatnot": """Test started: F-19: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.

Step 4:
When the authenticator supports Enterprise Attestation, send an authenticatorConfig (0x0D) command enabling enableEnterpriseAttestation (0x01) with an invalid pinAuthParam that fails verification.
Expected result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",


"ep.false": """Test started: F-20: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4:(verify)
Send a Reset (0x07) command and verify that Enterprise Attestation (ep) is disabled.
Step 5:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.""",



"nonentrprise": """Test started: F-21: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:
If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a 
valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set , and enterpriseAttestation set 0x01, 
wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and make sure that normal, NON-Enterprise attestation is returned .""",

"pinauthnotbyte": """Test started: F-22: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes a permission (for example, Authenticator Configuration (0x20)).
Expected Result: The authenticator returns CTAP2_OK
Step 3:
If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01) pinuvauthparam is not byte .
Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"eptrytodisable": """Test started: F-23: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 3: f the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01),enterprise attestation feature is Enable
Step 4: Verify in GetInfo comamnd enterprise attestation feature is Enable
Step 5:If the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01),enterprise attestation feature is disabled
Expected Result: The authenticator responds take no action and return CTAP2_OK.
Step 6: Verify in GetInfo comamnd enterprise attestation feature is Enable; its should not be disable if it is unable until FIDO2 reset command.""",

"epdisable": """Test started: F-24: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 3: f the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01),enterprise attestation feature is Enable
Step 4: Verify in GetInfo comamnd enterprise attestation feature is Enable
Step 5:Send FIDO Reset Command.
Step 6: Verify in GetInfo comamnd enterprise attestation feature is Disbale its should  be disable by FIDO2 reset command.""",



"epdisableinitial": """Test started: F-25: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4: f the authenticator supports enterprise attestation, send an authenticatorConfig (0x0D) command with enableEnterpriseAttestation (0x01),enterprise attestation feature is Enable
Step 5: Verify in GetInfo comamnd enterprise attestation feature is Enable
Step 6:Send FIDO Reset Command.
Step 7: Verify in GetInfo comamnd enterprise attestation feature is Disbale its should  be disable by FIDO2 reset command.""",

"epdisabletrytoprovideep": """Test started: F-26: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK..
Step 4:
FOR ENTERPRISE PROFILE If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 
authenticatorMakeCredential(0x01) enterprise attestation:  If the authenticator is not enterprise attestation capable, or the authenticator is enterprise attestation capable but enterprise attestation is disabled, 
then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.""",


"notprovidingpermission": """Test started: F-27: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step 2: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a Get PINauthToken using subCommand: getPinToken (0x05) .
Expected result: The authenticator returns CTAP2_OK..
Step 4:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
returning CTAP1_OK.""",

"Verfysignature":"""Test started: p-16: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 6:
If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
Step 7 – GetAssertion
Send a valid CTAP2 authenticatorGetAssertion (0x02) request using the credential created in Step 6.
Wait for the response and ensure the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Concatenate the returned authenticatorData with clientDataHash and use the public key obtained from MakeCredential to prepare for signature verification.
Step 8 – Signature Verification
Verify that the assertion signature returned by the authenticator is valid using the public key from Step 6. The verification should succeed.""",



"signaturefailed":"""Test started: F-28: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.ep =False.The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the enableEnterpriseAttestation (0x01) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command options.ep =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 6:
If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that:
Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
Step 7 – GetAssertion
Send a valid CTAP2 authenticatorGetAssertion (0x02) request using the credential created in Step 6.
Wait for the response and ensure the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Concatenate the returned authenticatorData with clientDataHash and use the public key obtained from MakeCredential to prepare for signature verification.
Step 8 – Signature Verification
Attempt to verify the assertion signature returned by the authenticator using the public key from Step 6.
If the public key does not match or is invalid, the signature verification fails.""",














    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])

    try:
        scenarioCount += 1
        if protocol==1:
            if str(pinset).lower() == "yes":
                util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                util.run_apdu("80100000010700", "Reset Card PIN",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                
                if mode == "enable.atttrue":
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output (CTAP2_OK)")

                        cbor_data = bytes.fromhex(response[2:])
                        decoded = cbor2.loads(cbor_data)
                        options = decoded.get(4, {})
                        ep_enabled = options.get("ep", False)

                        if ep_enabled:
                            util.printcolor(util.GREEN, f"  Enterprise Attestation (ep)={ep_enabled}")
                        else:
                            util.printcolor(util.RED, f"  Enterprise Attestation (ep)={ep_enabled}")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                if mode == "tmakecred":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "attep2": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x02, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "randomep": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x08, '02X')#random value
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    if response[:2] == "2C":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "epincorrect": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x03, '02X')#not 01 and 02
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    if response[:2] == "2C":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "invalidrp": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="getpintokenmappingnotsequence"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)


                elif mode == "enable.attestation":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation(ep=True)")
                    response, status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "epfalse.subcommandmissing":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "epfalse.subcommandinvalid":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    subCommand = 0x00
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "always uvtrue":
                    subCommand = 0x02
                    apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRE") 
                    if response[:2] == "36":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PUAT_REQUIRED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "always uvtrue.protocolmissing":
                    
                    subCommand = 0x02
                    apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=getpintokenpermissionp2.newpinsetp1(pin)
                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x03 SetPIN", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
        
                    
                    
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    mode="missing.protocol"
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name=" CTAP2_ERR_MISSING_PARAMETER") 
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "always uvtrue.protocolinvalid":
                    
                    subCommand = 0x02
                    apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=getpintokenpermissionp2.newpinsetp1(pin)
                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x03 SetPIN", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
        
                    
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=0
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "alwaysuvtrue.verificationfailed":
                    
                    subCommand = 0x02
                    apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=getpintokenpermissionp2.newpinsetp1(pin)
                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x03 SetPIN", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
        
                    
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "alwaysuvtrue.afgpermission":
                    
                    subCommand = 0x02
                    apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=getpintokenpermissionp2.newpinsetp1(pin)
                    response,status=util.run_apdu(apdu, "Client PIN subcmd 0x03 SetPIN", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x04  # invalidpermission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                

                elif mode == "enableattestaion.getinfo":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 4: send Getinfo Verify  enableEnterpriseAttestation")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "missing.protocol":
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name=" CTAP2_ERR_MISSING_PARAMETER") 
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "missing.pinUvAuthParam":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED") 
                    if response[:2] == "36":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PUAT_REQUIRED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "missing.subcommand":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name=" CTAP2_ERR_MISSING_PARAMETER") 
                    if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 

                elif mode == "invalidsubcomaand":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=1
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    subCommand=0x00
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "invalidprotocol":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    protocol=0
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "makecred": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "makecredepfalse": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER")
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                
                elif mode == "attestion2": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x02, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "attestion2epfalse": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x02, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER")
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)



                elif mode == "randomattestion": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x08, '02X')#random value
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    if response[:2] == "2C":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "exceptattestion": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x03, '02X')#not 01 and 02
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    if response[:2] == "2C":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Anyrpid": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x00  #nopermission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_Ok)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)



                
                elif mode == "wrongrpid": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="getpintokenmappingnotsequence"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "epundefined": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation(ep=True)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verifyfailed": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x01  # mc
                    mode="getpintokenmappingnotsequence"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) #verify wrong
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                
                elif mode == "epvaluewrong": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 4: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 5: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x03, '02X')#wrong
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    if response[:2] == "2C":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "invalidpinauthparam": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # afg
                    
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) #verify wrong
                    pinUvAuthParam =os.urandom(16)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                elif mode == "messagelengthless": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    pinUvAuthParam =os.urandom(10)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH") 
                    if response[:2] == "03":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_LENGTH)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    
                elif mode == "messagelengthgreater": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:32]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH") 
                    if response[:2] == "03":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_LENGTH)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "messageformatnot": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "ep.false": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a Reset (0x07) command and verify that Enterprise Attestation (ep) is disabled. ")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "GetInfo") 
                    response, status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_Ok)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "nonentrprise": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 4: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 5: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x04  # cm
                    mode="Anyrpid"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "pinauthnotbyte":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE") 
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                    
                elif mode == "eptrytodisable":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation ")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)try feature is disabled", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation ")
                    response, status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "epdisable":
                    
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # afg
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    util.printcolor(util.YELLOW,f"  Step 3: authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01) ")
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 4: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 5: send Reset command:")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "GetInfo")
                    util.printcolor(util.YELLOW,f"  Step 6: send Getinfo Verify  enableEnterpriseAttestation Disable or not")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)  
                elif mode == "epdisableinitial":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x20  # afg
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    util.printcolor(util.YELLOW,f"  Step 4: authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01) ")
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 5: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 6: send Reset command:")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "GetInfo")
                    util.printcolor(util.YELLOW,f"  Step 7: send Getinfo Verify  enableEnterpriseAttestation Disable or not")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)  
                elif mode == "epdisabletrytoprovideep":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    mode="makecred"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="enterprisetest.certinfra.fidoalliance.org"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER")
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)  
                elif mode == "notprovidingpermission":
                    
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    subCommand = 0x01
                    permission = 0x00  # mc
                    mode="Anyrpid"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
                elif mode == "Verfysignature":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    credId,publickey =authParasing(response)
                    print("credId",credId)
                    print("publickey",publickey)
                    rp="localhost"
                    mode="Anyrpid"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    protocol=0x01
                    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                    result, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    print("response",result)
                    authData, signature=getasserationparssing(result)
                    verify_getassertion_signature(publickey, authData, clientDataHash, signature)
                elif mode == "signaturefailed":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinsetnew(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    attestationdata=format(0x01, '02X')
                    RP_domain="localhost"
                    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    credId,publickey =authParasing(response)
                    publickey="a5010203262001215820e197766f8b71adf5be90bd7eea4db5af635b328ba9c3d8cd5a0f13c1c9d48a1e22582043dd5751be05dde187ead2ead783b37fe2254ec8fb3028e8c3195c6066f7542e"
                    print("credId",credId)
                    print("publickey",publickey)
                    rp="localhost"
                    mode="Anyrpid"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    protocol=0x01
                    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                    result, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    print("response",result)
                    authData, signature=getasserationparssing(result)
                    verify_getassertion_signature(publickey, authData, clientDataHash, signature)


                    
                
                    
                    
                
            
                    
                    
                    
                
            
                    
                

                

                

                
                
                


                
                

        else:
            util.run_apdu("00A4040008A0000006472F0001", "Select applet")
            util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.run_apdu("00A4040008A0000006472F0001", "Select applet")
            util.run_apdu("80100000010700", "Reset Card PIN",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
            
            if  mode == "enable.atttrue":
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "tmakecred": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)  
            elif mode == "attep2": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x02, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "randomep": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x08, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                if response[:2] == "2C":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalidrp": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "epincorrect": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x03, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                if response[:2] == "2C":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "enable.attestation":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation(ep=True)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "epfalse.subcommandmissing":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
            
            elif mode == "epfalse.subcommandinvalid":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                subCommand = 0x00
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "always uvtrue":
                subCommand = 0x02
                apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED") 
                if response[:2] == "36":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PUAT_REQUIRED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "always uvtrue.protocolmissing":
                subCommand = 0x02
                apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                mode="missing.protocol"
                protocol=0
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                if response[:2] == "14":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "always uvtrue.protocolinvalid":
                subCommand = 0x02
                apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=0
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuvtrue.verificationfailed":
                subCommand = 0x02
                apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuvtrue.afgpermission":
                subCommand = 0x02
                apdu=toggleAlwaysUv.toggleAlwaysUvwithoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep =False and  alwaysUv =True)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x04  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            
            elif mode == "enableattestaion.getinfo":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 5: send Getinfo Verify  enableEnterpriseAttestation")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)  
            elif mode == "missing.protocol":
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                if response[:2] == "14":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "missing.pinUvAuthParam":
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                pin="123456"
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED") 
                if response[:2] == "36":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PUAT_REQUIRED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "missing.subcommand":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                if response[:2] == "14":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "invalidsubcomaand":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=2
                subCommand = 0x00
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalidprotocol":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                protocol=0
                subCommand = 0x01
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "makecred": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "makecredepfalse": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER")
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)  

                    
            elif mode == "attestion2": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x02, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "attestion2epfalse": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x02, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER")
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 


            elif mode == "randomattestion": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x08, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                if response[:2] == "2C":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode == "exceptattestion": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x03, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                if response[:2] == "2C":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "Anyrpid": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X00  
                
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            
            elif mode == "wrongrpid": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode == "epundefined": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation(ep=True)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "verifyfailed": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    subCommand = 0x01
                    permission = 0X04  #mc
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])#verify failed
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

            elif mode == "epvaluewrong": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x03, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                if response[:2] == "2C":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_OPTION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalidpinauthparam": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    subCommand = 0x01
                    permission = 0X20
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])#verify failed
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam =os.urandom(32)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

            elif mode == "messagelengthless": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    subCommand = 0x01
                    permission = 0X20  
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])#verify failed
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:10]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH")
                    if response[:2] == "03":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_INVALID_LENGTH)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "messagelengthgreater": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    subCommand = 0x01
                    permission = 0X20  
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])#verify failed
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    pinUvAuthParam =os.urandom(64)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH")
                    if response[:2] == "03":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP1_ERR_INVALID_LENGTH)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "messageformatnot": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    subCommand = 0x01
                    permission = 0X20  
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 10 + b'\x0D' + bytes([subCommand])#verify failed
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "ep.false": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a Reset (0x07) command and verify that Enterprise Attestation (ep) is disabled. ")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "GetInfo") 
                    response, status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_Ok)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "nonentrprise": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X04  # cm
                mode="Anyrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_Ok)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauthnotbyte": 
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    subCommand = 0x01
                    permission = 0X20  
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ")
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#verify failed
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=enableEnterpriseAttestation(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE") 
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "eptrytodisable":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x01
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation ")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=epwitoutparam(mode,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)try feature is disabled", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation ")
                    response, status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
            elif mode == "epdisable":
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 4: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 5: send Reset command:")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "GetInfo")
                    util.printcolor(util.YELLOW,f"  Step 6: send Getinfo Verify  enableEnterpriseAttestation Disable or not")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "epdisableinitial":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 5: send Getinfo Verify  enableEnterpriseAttestation")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.printcolor(util.YELLOW,f"  Step 6: send Reset command:")
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "GetInfo")
                    util.printcolor(util.YELLOW,f"  Step 7: send Getinfo Verify  enableEnterpriseAttestation Disable or not")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output( CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0) 
            elif mode == "epdisabletrytoprovideep":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="makecred"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="enterprisetest.certinfra.fidoalliance.org"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status =util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)  

            elif mode == "notprovidingpermission":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation(ep=False)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x00  # Authenticator Configuration permission
                    mode="Anyrpid"
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with enableEnterpriseAttestation(0x01) ") 
                    protocol=2
                    subCommand = 0x01
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=apdu=getpintokenpermissionp2.enableEnterpriseAttestation(pinUvAuthParam,subCommand,protocol)
                    response, status =util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)  
            elif mode == "Verfysignature": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)    
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="localhost"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                credId,publickey =authParasing(response)
                print("credId",credId)
                print("publickey",publickey)
                mode="Anyrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)    
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                protocol=0x02
                rp="localhost"
                apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                result, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                print("response",result)
                authData, signature=getasserationparssing(result)
                verify_getassertion_signature(publickey, authData, clientDataHash, signature)

            elif mode == "signaturefailed": 
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x01
                apdu=epwitoutparam(mode,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  enableEnterpriseAttestation")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0X01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)    
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                attestationdata=format(0x01, '02X')
                RP_domain="localhost"
                makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user,pinAuthToken,attestationdata,protocol);
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                credId,publickey =authParasing(response)
                publickey="a5010203262001215820e197766f8b71adf5be90bd7eea4db5af635b328ba9c3d8cd5a0f13c1c9d48a1e22582043dd5751be05dde187ead2ead783b37fe2254ec8fb3028e8c3195c6066f7542e"
                print("credId",credId)
                print("publickey",publickey)
                mode="Anyrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)    
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                protocol=0x02
                rp="localhost"
                apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                result, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                print("response",result)
                authData, signature=getasserationparssing(result)
                verify_getassertion_signature(publickey, authData, clientDataHash, signature) 
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1           
            
                
        
            
                
def newMinPinLength(pinToken, subCommand):

    subCommandParams = {
        0x01: 8,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: False   # forcePINChange = False
    }


    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    #pinUvAuthParam=os.urandom(10)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu

def getPINtokenPubkeynew(curpin):
    util.run_apdu("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    protocol=2
    pinSetAPDU = createGetPINtoken1(pinHashEnc,key_agreement,protocol)
    hexstring, status= util.run_apdu(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS");
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


def createGetPINtoken1(pinHashenc, key_agreement,protocol):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    cbor_protocol  = cbor2.dumps(protocol).hex().upper()


    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ cbor_protocol# Fido2 protocol 
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand
def getasserationparssing(response):
    response_bytes = bytes.fromhex(response)

    # Check status byte
    if response_bytes[0] != 0x00:
        raise ValueError(f"CTAP error: 0x{response_bytes[0]:02X}")

    # Decode CBOR response
    cbor_payload = response_bytes[1:]
    decoded_cbor = cbor2.loads(cbor_payload)
    print("Decoded CBOR keys:", decoded_cbor.keys())  # Should show [1, 2, 3]
    # Extract required fields
    authData = decoded_cbor.get(2)
    signature = decoded_cbor.get(3)

    if authData is None or signature is None:
        raise ValueError("Invalid GetAssertion response: missing authData or signature")

    return authData, signature

def verify_getassertion_signature(publickey, authData, clientDataHash, signature):
    # Build signed data
    signedData = authData + clientDataHash

    # Decode COSE public key
    x, y = decode_cose_public_key(publickey)

    # Build EC public key
    pub_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"),
        int.from_bytes(y, "big"),
        ec.SECP256R1()
    )
    pub_key = pub_numbers.public_key()

    # Verify signature
    try:
        pub_key.verify(
            signature,
            signedData,
            ec.ECDSA(hashes.SHA256())
        )
        print("✅ Signature verification SUCCESS")
        return True
    except InvalidSignature:
        print(" Signature verification FAILED")
        return False
def decode_cose_public_key(publickey):
    # publickey may be hex string or bytes
    if isinstance(publickey, str):
        publickey = bytes.fromhex(publickey)

    # Decode COSE key
    cose_key = cbor2.loads(publickey)

    # COSE EC2 key labels
    x = cose_key[-2]
    y = cose_key[-3]

    if not x or not y:
        raise ValueError("Invalid COSE public key")

    return x, y
def authParasing(response):
    print("response>>>",response)
    authdata=extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info =parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    publickey=credential_info["credentialPublicKey"]
    print("credid",credentialId)
    return credentialId,publickey

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
def createCBORmakeAssertion(cryptohash, rp, pinAuthToken, credId,protocol):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = cbor2.dumps(protocol).hex().upper()                                         # 0x07: pinProtocol = 2

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

def getPINtokenPubkeyrp(curpin):
    util.run_apdu("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.run_apdu("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    protocol=2
    pinSetAPDU = createGetPINtoken11(pinHashEnc,key_agreement,protocol)
    hexstring, status= util.run_apdu(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS");
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


def createGetPINtoken11(pinHashenc, key_agreement,protocol):
    rp="localhost"
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    cbor_protocol  = cbor2.dumps(protocol).hex().upper()
    cbor_rp  = cbor2.dumps(rp).hex().upper()

    


    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_protocol# Fido2 protocol 
    dataCBOR = dataCBOR + "02"+ "09" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    dataCBOR = dataCBOR + "10"+ cbor_rp 
    
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand
def createCBORmakeCred(clientDataHash, rp, user,  pinAuthToken,attestationdata,protocol):

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
    rk                 = cbor2.dumps(option).hex().upper()
    cbor_protocol          = cbor2.dumps(protocol).hex().upper()

    
    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ cbor_protocol               # pin protocol V2 assumed
    dataCBOR = dataCBOR + "0A"+ attestationdata   #enterpriseAttestation

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

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



def enableEnterpriseAttestation(mode,pinUvAuthParam, subCommand,protocol):
    if mode == "missing.protocol":
        cbor_map = {
            0x01: subCommand,      # enableEnterpriseAttestation
            0x04: pinUvAuthParam
        }
    elif mode == "missing.pinUvAuthParam":
        cbor_map = {
            0x01: subCommand,      # enableEnterpriseAttestation
            0x03:protocol
        }
    elif mode == "missing.subcommand":
        cbor_map = {
            
            0x03:protocol,
            0x04: pinUvAuthParam

        }
    # elif mode =="makecred":
    #     cbor_map = {
    #         0x01: subCommand,      # enableEnterpriseAttestation
    #         0x04: pinUvAuthParam
    #     }

    elif mode == "invalidsubcomaand":
        cbor_map = {
            0x01: subCommand,      # enableEnterpriseAttestation
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
        }
    elif mode == "pinauthnotbyte":
        cbor_map = {
            0x01: subCommand,      # enableEnterpriseAttestation
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: "010203"
        }



    else:
        cbor_map = {
            0x01: subCommand,      # enableEnterpriseAttestation
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu 
import hashlib
def getPINtokenPubkey(pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")

    response, status = util.run_apdu("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.run_apdu(apdu, "Client PIN subcmd 0x05 GetPINToken", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.aes256_cbc_decryptP1(shared_secret, enc_pin_token)
    return pin_token


def getPINtokenPubkey111(pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")

    response, status = util.run_apdu("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc,          # pinHashEnc
        10:"localhost"
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.run_apdu(apdu, "Client PIN subcmd 0x05 GetPINToken", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.aes256_cbc_decryptP1(shared_secret, enc_pin_token)
    return pin_token
  

def epwitoutparam(mode,subCommand,protocol):
    if mode =="epfalse.subcommandmissing":
      cbor_map = {
        0x03:protocol  
    } 
    elif mode =="epfalse.subcommandinvalid":
      cbor_map = {
        0x01: subCommand   
    }   
    else:     
        cbor_map = {
            0x01: subCommand      # enableEnterpriseAttestation    
        }
    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu   
    
            