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
import DocumentCreation
RP_domain          = "localhost"
user="bobsmith"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR CONFIG(TOGGLE ALWAYS UV)"
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
        "alwaysuvwitoutpin":"""Test started: P-1 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
GetInfo.Alwaysuv is set to true. The authenticator returning CTAP2_OK.""",


"makeCredUvNotRqd":"""Test started: P-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command makeCredUvNotRqd =True . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
GetInfo makeCredUvNotRqd =False. The authenticator returning CTAP2_OK.""",


"alwaysuv":"""Test started: P-3 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02)
Expected Result: The authenticator returns CTAP2_OK.""",

 "alwaysuv.getinfo":"""Test started: P-4 :
 Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02)
Expected Result: The authenticator returns CTAP2_OK..
Step 5:
Send The getinfo command for verify Alwaysuv =True.
Expected Result: The authenticator returns CTAP2_OK.""",


"alwaysuv.makecred":"""Test started: P-5 :
 Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02)
Expected Result: The authenticator returns CTAP2_OK..
Step 5:
Send The getinfo command for verify Alwaysuv =True and makeCredUvNotRqd =false.
Expected Result: The authenticator returns CTAP2_OK.
Step 6:
Sending a valid CTAP2 authenticatorMakeCredential(0x01) alwaysuv is present and true and pinuvauthparam is absent.Expected Result: The authenticator returns CTAP2_OK.
.Expected Result: The authenticator returns CTAP2_ERR_PUAT_REQUIRED.

""",


"makeCredUvNotRqdtrue":"""Test started: P-6 :
 Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command makeCredUvNotRqd =True . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such asauthenticatorMakeCredential(0x01).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:

Sending a valid CTAP2 authenticatorMakeCredential(0x01) alwaysuv is false  and pinuvauthparam is absent.Expected Result: The authenticator returns CTAP2_OK.
.Expected Result: The authenticator returns CTAP2_Ok.""",

"alwaysuvpinauthparam":"""Test started: P-7 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02)
Expected Result: The authenticator returns CTAP2_OK..
Step 5:
Send The getinfo command for verify Alwaysuv =True and makeCredUvNotRqd =false.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as authenticatorMakeCredential(0x01).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:
Sending a valid CTAP2 authenticatorMakeCredential(0x01) alwaysuv is present and true and pinuvauthparam is Present.Expected Result: The authenticator returns CTAP2_OK.
.Expected Result: The authenticator returns CTAP2_OK.""",

"resetcommannd":"""Test started: P-8 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:
Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02)
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send The getinfo command for verify Alwaysuv =True .
Expected Result: The authenticator returns CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as authenticatorMakeCredential(0x01).
Expected Result: The authenticator returns CTAP2_OK..
Step 6:
Sending The Fido Resetcommand(0x07). The authenticator returns CTAP2_OK.
Step 7:
Sending a valid CTAP2 authenticatorMakeCredential(0x01) and pinuvauthparam is Present.Expected Result: The authenticator returns CTAP2_OK.""",

"alwaysuv.paramadded":"""Test started: P-9 :
 Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig(0x0D) The toggleAlwaysUv subcommand must ignore subCommandParams. If subCommandParams are added.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",


"alwaysuvtrueminimumpinlength":"""Test started: P-10 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
Send GetInfo commandalwaysUv =True. The authenticator returning CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:Send authenticatorConfig(0x0D) subcommand  setMinPINLength(0x03). If pinUvAuthParam is absent from the input map, then end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
Expected Result: The authenticator returns CTAP2_ERR_PUAT_REQUIRED.""",


"alwaysuvtrueprotocol":"""Test started: F-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
Send GetInfo commandalwaysUv =True. The authenticator returning CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:Send authenticatorConfig(0x0D) subcommand  setMinPINLength(0x03). If pinUvAuthProtocol is absent from the input map, then end the operation by returning CTAP2_ERR_MISSING_PARAMETER.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",


"alwaysuvtrueinvalidprotocol":"""Test started: F-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
Send GetInfo commandalwaysUv =True. The authenticator returning CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:Send authenticatorConfig(0x0D) subcommand  setMinPINLength(0x03). If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
Expected Result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"alwaysuvtrueverificationfailed":"""Test started: F-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
Send GetInfo commandalwaysUv =True. The authenticator returning CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 6:Send authenticatorConfig(0x0D) subcommand  setMinPINLength(0x03). If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID .
Expected Result: The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",


"withoutafgpermission":"""Test started: F-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.Authenticator must Reset/No Pin is set.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2:Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) (without pinUvAuthProtocol (0x03) and pinUvAuthParam (0x04)).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:(Verify)
Send GetInfo commandalwaysUv =True. The authenticator returning CTAP2_OK.
Step 4: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request without providing acfg permission.
Expected Result: The authenticator returns CTAP2_OK.
Step 6:Send authenticatorConfig(0x0D) subcommand  setMinPINLength(0x03).  
Expected Result: The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",





"alwaysUv.opposite":"""Test started: P-3 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
If authenticator supports alwaysUv: Collect GetInfo.options.alwaysUv value. Send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02),
        and check that:
            a) If authenticator supports alwaysUv, check that GetInfo.options.alwaysUv is opposite value
            b) Or if alwaysUv was true, and authenticator does not support disabling alwaysUv, check that authenticator returns CTAP2_ERR_OPERATION_DENIED(0x27).""",

"subcommand.missing":"""Test started: F-1 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) when the subcommand(0x01) is missing.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"pinUvAuthParam.missing":"""Test started: F-2 :
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) If pinUvAuthParam is absent from the input map.
Expected Result: The authenticator returns CTAP2_ERR_PUAT_REQUIRED.""",

"pinUvAuthProtocol.missing":"""Test started: F-3:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports alwaysUv, retrieve the GetInfo.options.alwaysUv value. Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02).
If pinUvAuthProtocol is absent from the input map.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"invalid.subcommand":"""Test started: F-4:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) using an invalid subcommand (0x01).
Expected Result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"invalid.pinUvAuthParam":"""Test started: F-5:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) using an invalid pinUvAuthParam .
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"invalid.pinUvAuthProtocol":"""Test started: F-6:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports alwaysUv, retrieve the GetInfo.options.alwaysUv value. Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) using an invalid pinUvAuthProtocol.
Expected Result: The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"verification.failed":"""Test started: F-7:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports alwaysUv, retrieve the GetInfo.options.alwaysUv value. Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02).
All input data is valid; however, data verification fails during validation.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"pinauthparm.lengthless":"""Test started: F-8:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports alwaysUv, retrieve the GetInfo.options.alwaysUv value and send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02).
All input data is valid; however, during verification, the pinAuthParam data is required (16 bytes for PIN protocol 1 and 32 bytes for PIN protocol 2)but a shorter length is provided.

Expected Result:
The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",

"pinauthparm.lengthgreater":"""Test started: F-9:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
If the authenticator supports alwaysUv, retrieve the GetInfo.options.alwaysUv value and send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02).
All input data is valid; however, during verification, the pinAuthParam data is required (16 bytes for PIN protocol 1 and 32 bytes for PIN protocol 2)but a greater length is provided.

Expected Result:
The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",

"toggleAlwaysUv.disable":"""Test started: F-10:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) using an incorrect parameter, causing the toggleAlwaysUv operation to fail (remain disabled).
Expected Result:
The authenticator returns CTAP1_ERR_INVALID_PARAMETER.
.""",

"toggleAlwaysUv.enable":"""Test started: F-11:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK toggleAlwaysUv
enable.
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send The getinfo command for verify  makeCredUvNotRqd set to  false.
Expected Result: The authenticator returns CTAP2_OK.""",

"messageformat.wrong":"""Test started: F-12:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) using improperly formatted verification message data.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"afgpermission.notprovide":"""Test started: F-13:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Without providing authenticatorConfig permission (0x20)Send a getPinUvAuthToken (0x05) providing all are vaild commnad.
Expected Result: The authenticator returns CTAP2_OK.
Step 4: 
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02)  all are vaild command.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID
.""",

"protocolviceversa":"""Test started: F-14:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes a permission (for example, Authenticator Configuration (0x20)).
When performing a Protocol 1 operation, send a Protocol 2 getPinToken request; when performing a Protocol 2 operation, send a Protocol 1 getPinToken request.
Expected Result: The authenticator returns CTAP2_OK
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) using improperly formatted verification message data.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",


"pinauthparam.notbyte":"""Test started: F-15:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.
Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes a permission (for example, Authenticator Configuration (0x20)).
Expected Result: The authenticator returns CTAP2_OK
Step 4:
Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) pinuvauthparam is not byte .
Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",

"toggleAlwaysUvreset":"""Test started: F-16:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) feature is Enable
Step 5: Verify in GetInfo comamnd toggleAlwaysUv feature is Enable
Step 6:Send FIDO Reset Command.
Step 7: Verify in GetInfo comamnd toggleAlwaysUv feature is Disbale its should  be disable by FIDO2 reset command.""",


"pinauthoken":"""Test started: F-17:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command options.AlwaysUv  =False.The authenticator returning CTAP2_OK.
Step 2: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3:
Send a Get PINauthToken using subCommand: getPinToken (0x05) .
Expected result: The authenticator returns CTAP2_OK..
Step 4:
Send an authenticatorConfig (0x0D) command with the AlwaysUv  (0x02) subcommand.The authenticator returning CTAP2_ERR_PIN_AUTH_INVALID.""",

"featurenotbedisable":"""Test started: F-18:
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step 2: Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with include a permission such as Authenticator config (0x20).
Expected Result: The authenticator returns CTAP2_OK.
Step 4:Send authenticatorConfig (0x0D) with toggleAlwaysUv (0x02) feature is Enable
Step 5: Verify in GetInfo comamnd AlwaysUv feature is Enable  
Step 5:If the authenticator supports AlwaysUv , send an authenticatorConfig (0x0D) command with toggleAlwaysUv (0x02),AlwaysUv feature is disabled
Expected Result: The authenticator  return CTAP2_OK.
Step 6: Verify in GetInfo comamnd AlwaysUv  feature is Disable.
""",


"Verfysignature":"""Test started: p-16: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the toggleAlwaysUv (0x02) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command Send GetInfo command Alwaysuv =True . The authenticator returning CTAP2_OK.
 =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 6:
sending a valid CTAP2 authenticatorMakeCredential(0x01)and pinuvauthparam is present , 
Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
Step 7 – GetAssertion
Send a valid CTAP2 authenticatorGetAssertion (0x02) request using the credential created in Step 6.
Wait for the response and ensure the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Concatenate the returned authenticatorData with clientDataHash and use the public key obtained from MakeCredential to prepare for signature verification.
Step 8 – Signature Verification
Verify that the assertion signature returned by the authenticator is valid using the public key from Step 6. The verification should succeed.""",



"signaturefailed":"""Test started: p-17: 
Precondition:
1.The authenticator supports Authenticator config=true
2.No PIN is currently set on the authenticator.
3.The authenticator supports PIN/UV Protocols.

Test Step:
Step 1:(verify)
Send GetInfo command Alwaysuv =false . The authenticator returning CTAP2_OK.
Step2:
Send an authenticatorConfig (0x0D) command with the toggleAlwaysUv (0x02) subcommand.The authenticator returning CTAP2_OK
Step 3:
Send GetInfo command Send GetInfo command Alwaysuv =True . The authenticator returning CTAP2_OK.
 =True . The authenticator returning CTAP2_OK.
Step 4: 
Perform the setPIN operation using Supported Protocol.
Expected Result: The authenticator returns CTAP2_OK.
Step 5:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request that includes the MakeCredential (0x01) permission and the RP ID.
Expected result: The authenticator returns CTAP2_OK.
Step 6:
sending a valid CTAP2 authenticatorMakeCredential(0x01)and pinuvauthparam is present , 
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
            util.printcolor(util.YELLOW, "**** toggleAlwaysUv CTAP2.2 For   Protocol 1****")
            if str(pinset).lower() == "yes":
                util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                util.run_apdu("80100000010700", "Reset Card PIN",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                
                if mode == "alwaysuvwitoutpin":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case PassedExpected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                if mode == "makeCredUvNotRqd":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  makeCredUvNotRqd True or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  makeCredUvNotRqd=False")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case PassedExpected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "alwaysuv":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case PassedExpected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "alwaysuv.getinfo":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case PassedExpected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                    
                elif mode == "alwaysuv.makecred":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    permission = 0x01  # mc
                    mode="Anyrpid"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    rp="localhost"
                    mode="alwaysuv.makecred"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                    if response[:2] == "36":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PUAT_REQUIRED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "alwaysuvpinauthparam":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    rp="localhost"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "makeCredUvNotRqdtrue":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    rp="localhost"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "resetcommannd":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    subCommand = 0x02
                    util.printcolor(util.YELLOW,f"  Step 2: Performing  AlwaysUv Feature enable.")
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 4: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 5: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    
                    permission = 0x01  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 6: send fidoResetcommand(0x07) ")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "Reset Card PIN",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    rp="localhost"
                    mode ="alwaysuv.makecred"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)


                
                elif mode == "alwaysuv.paramadded":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response, status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)


                elif mode == "alwaysuvtrueminimumpinlength":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 4: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 5: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x03
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    subCommandParams = {0x01: 8}
                    apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED") 
                    if response[:2] == "36":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PUAT_REQUIRED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "alwaysuvtrueprotocol":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 4: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 5: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x03
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    subCommandParams = {0x01: 8}
                    apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                    if response[:2] == "14":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "alwaysuvtrueinvalidprotocol":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 4: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 5: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x03
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    subCommandParams = {0x01: 8}
                    apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                    if response[:2] == "02":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "alwaysuvtrueverificationfailed":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 4: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 5: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x03
                    message = b'\xFF' * 10 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    subCommandParams = {0x01: 8}
                    mode="alwaysuvtrueverificationfailed"
                    apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "withoutafgpermission":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 4: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x40  # Authenticator Configuration permission
                    mode="nonentrprise"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 5: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x03
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    subCommandParams = {0x01: 8}
                    mode="alwaysuvtrueverificationfailed"
                    apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)



                elif mode == "alwaysUv.opposite":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 4:GetInfo.options.alwaysUv is opposite value ")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "subcommand.missing":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    
                    mode="subcommand.missing"
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                    if response [:2]== "14":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinUvAuthParam.missing":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED") 
                    if response[:2] == "36":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PUAT_REQUIRED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinUvAuthProtocol.missing":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                    if response[:2] == "14":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_MISSING_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                elif mode == "invalid.subcommand":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x00
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                    if response [:2]== "02": 
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "invalid.pinUvAuthParam":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = os.urandom(16)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33": 
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "invalid.pinUvAuthProtocol":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=0
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                    if response[:2] == "02": 
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "verification.failed":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand]) #message invalid
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33": 
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinauthparm.lengthless":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = os.urandom(10)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH") 
                    if response[:2] == "03": 
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_INVALID_LENGTH)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinauthparm.lengthgreater":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = os.urandom(32)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH") 
                    if response[:2] == "03": 
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_LENGTH)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "toggleAlwaysUv.disable":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=0
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                    
                    if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_PARAMETER)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "toggleAlwaysUv.enable":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) 
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "messageformat.wrong":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 16 + b'\x0D' + bytes([subCommand]) #message invalid
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "afgpermission.notprovide":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    
                    pinToken=Setpinp1.getPINtokenPubkey(pin)
                    #pinToken=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) #message invalid
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "protocolviceversa":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)  
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) #message invalid
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinauthparam.notbyte":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) #message invalid
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE") 
                    
                    if response[:2] == "11":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "toggleAlwaysUvreset":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "Authenticator Reset ",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "pinauthoken":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthToken (0x05) include permission Authenticator config(0x20) ")
                    permission = 0x00  # Authenticator Configuration permission
                    
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    protocol=1
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand]) #message invalid
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "featurenotbedisable":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x20  # Authenticator Configuration permission
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ")
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)[:16]
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                    util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")  
                    util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                elif mode == "Verfysignature":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    rp="localhost"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                            
                    credId,publickey =enableEnterpriseAttestationctap2.authParasing(response)
                    print("credId",credId)
                    print("publickey",publickey)
                    rp="localhost"
                    mode="Anyrpid"
                    permission = 0x02
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    protocol=0x01
                    apdu = enableEnterpriseAttestationctap2.createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                    result, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    print("response",result)
                    authData, signature=enableEnterpriseAttestationctap2.getasserationparssing(result)
                    enableEnterpriseAttestationctap2.verify_getassertion_signature(publickey, authData, clientDataHash, signature)
                elif mode == "signaturefailed":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 1: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.newpinset(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x01  # mc
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                    rp="localhost"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                            
                    credId,publickey =enableEnterpriseAttestationctap2.authParasing(response)
                    publickey="a5010203262001215820e197766f8b71adf5be90bd7eea4db5af635b328ba9c3d8cd5a0f13c1c9d48a1e22582043dd5751be05dde187ead2ead783b37fe2254ec8fb3028e8c3195c6066f7542e"
                
                    print("credId",credId)
                    print("publickey",publickey)
                    rp="localhost"
                    permission = 0x02
                    mode="Anyrpid"
                    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    protocol=0x01
                    apdu = enableEnterpriseAttestationctap2.createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                    result, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    print("response",result)
                    authData, signature=enableEnterpriseAttestationctap2.getasserationparssing(result)
                    enableEnterpriseAttestationctap2.verify_getassertion_signature(publickey, authData, clientDataHash, signature)

                    
                

    

        #protocol 2
        else:
            util.printcolor(util.YELLOW, "**** toggleAlwaysUv CTAP2.2 For Protocol 2****")
            util.run_apdu("00A4040008A0000006472F0001", "Select applet")
            util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.run_apdu("00A4040008A0000006472F0001", "Select applet")
            util.run_apdu("80108000010700", "Reset Card PIN","00")

            if mode == "alwaysuvwitoutpin":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "makeCredUvNotRqd":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  makeCredUvNotRqd True or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  makeCredUvNotRqd False")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuv":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                if response[:2] == "00":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "alwaysuv.getinfo":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuv.makecred":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                clientDataHash =os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                rp="localhost"
                mode="alwaysuv.makecred"
                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                if response[:2] == "36":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PUAT_REQUIRED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "makeCredUvNotRqdtrue":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
    
                clientDataHash =os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                rp="localhost"
                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuvpinauthparam":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                mode="wrongrpid"
                permission=0x01
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                clientDataHash =os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                rp="localhost"
                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "alwaysuvtrueminimumpinlength":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x03
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                subCommandParams = {0x01: 8}
                apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED") 
                if response[:2] == "36":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PUAT_REQUIRED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)


            elif mode == "resetcommannd":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send FidoResetCommand(0x07) ") 
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                util.run_apdu("80100000010700", "Reset Card PIN",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                clientDataHash =os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                rp="localhost"
                mode ="alwaysuv.makecred"
                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuvtrueprotocol":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x03
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                subCommand = 0x03
                subCommandParams = {0x01: 8}
                apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)",expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                if response[:2] == "14":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "alwaysuvtrueinvalidprotocol":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x03
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                subCommand = 0x03
                subCommandParams = {0x01: 8}
                apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                if response[:2] == "02":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "alwaysuvtrueverificationfailed":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x03
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                subCommandParams = {0x01: 8}
                apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "withoutafgpermission":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: send Getinfo Verify  toggleAlwaysUv(0x02)")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x04  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x03
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                subCommandParams = {0x01: 8}
                mode="alwaysuvtrueverificationfailed"
                apdu=newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol) 
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03) subcommandparam newMinPINLength (0x01)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "alwaysUv.opposite":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 5: GetInfo.options.alwaysUv is opposite value ")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "subcommand.missing":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                if response[:2] == "14":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "pinUvAuthParam.missing":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                if response[:2] == "36":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PUAT_REQUIRED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "pinUvAuthProtocol.missing":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER") 
                if response[:2] == "14":  
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed{status}")
                    exit(0)
            elif mode == "invalid.subcommand":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x00
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                if response[:2] == "02": 
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalid.pinUvAuthParam":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 3: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                #pinUvAuthParam = util.hmac_sha256(pinToken, message)
                pinUvAuthParam=os.urandom(32)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33": 
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalid.pinUvAuthProtocol":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=0
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                #pinUvAuthParam = util.hmac_sha256(pinToken, message)
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER") 
                if response[:2] == "02": 
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "verification.failed":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0B' + bytes([subCommand])#messagewrong
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                #pinUvAuthParam = util.hmac_sha256(pinToken, message)
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33": 
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauthparm.lengthless":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#messagewrong
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                #pinUvAuthParam = util.hmac_sha256(pinToken, message)
                pinUvAuthParam = os.urandom(20)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH") 
                if response[:2] == "03": 
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_LENGTH)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauthparm.lengthgreater":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#messagewrong
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                #pinUvAuthParam = util.hmac_sha256(pinToken, message)
                pinUvAuthParam = os.urandom(64)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="03",expected_error_name="CTAP2_ERR_INVALID_LENGTH") 
                if response[:2] == "03": 
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_LENGTH)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "toggleAlwaysUv.disable":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=0
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#messagewrong
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER") 
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "toggleAlwaysUv.enable":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#messagewrong
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "messageformat.wrong":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 16 + b'\x0D' + bytes([subCommand])#messagewrong format
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "afgpermission.notprovide":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x04  # Authenticator Configuration permission
                #pinToken, pubkey=getpintokenCTAP2_2.getPINtokenPubkey(pin)
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#messagewrong format
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "protocolviceversa":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x04  # Authenticator Configuration permission
                #pinToken, pubkey=getpintokenCTAP2_2.getPINtokenPubkey(pin)
                pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])#messagewrong format
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauthparam.notbyte":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                protocol=2
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 16 + b'\x0D' + bytes([subCommand])#messagewrong format
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE") 
                if response[:2] == "11":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "toggleAlwaysUvreset":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                    util.run_apdu("80100000010700", "Authenticator Reset",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "pinauthoken":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                    getpintokenpermissionp2.restPin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                    permission = 0x00  # Authenticator Configuration permission
                    mode="Anyrpid"
                    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                    util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                    protocol=2
                    subCommand = 0x02
                    # Message: 32x0xFF || 0x0D || subCommand
                    message = b'\xFF' * 16 + b'\x0D' + bytes([subCommand])#messagewrong format
                    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                    pinUvAuthParam = util.hmac_sha256(pinToken, message)
                    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                    apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                    response,status=util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID") 
                    if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

            elif mode == "featurenotbedisable1":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x20  # Authenticator Configuration permission
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)   
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                util.printcolor(util.YELLOW,f"  Step 5: Verify toggleAlwaysUv Using Getinfo ")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission) 
                util.printcolor(util.YELLOW,f"  Step 4: send authenticatorConfig(0x0D) with toggleAlwaysUv(0x02) ") 
                subCommand = 0x02
                # Message: 32x0xFF || 0x0D || subCommand
                message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
                print(f"Message: {message.hex()}")  # (32 bytes) + 0d01
                # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
                pinUvAuthParam = util.hmac_sha256(pinToken, message)
                print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")
                apdu=toggleAlwaysUv(mode,pinUvAuthParam,subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS") 
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "featurenotbedisable":
                    util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                    util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    subCommand = 0x02
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                    util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                    util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv(0x02)")
                    if response[:2] == "00":  
                        util.printcolor(util.GREEN, "  ✅ Test Case PassedExpected Result(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "Verfysignature":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)     
                clientDataHash =os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                rp="localhost"
                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                credId,publickey =enableEnterpriseAttestationctap2.authParasing(response)
                print("credId",credId)
                print("publickey",publickey)
                mode="Anyrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)    
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                protocol=0x02
                rp="localhost"
                apdu = enableEnterpriseAttestationctap2.createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                result, status = util.run_apdu(apdu, "GetAssertion 0x02",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                print("response",result)
                authData, signature=enableEnterpriseAttestationctap2.getasserationparssing(result)
                enableEnterpriseAttestationctap2.verify_getassertion_signature(publickey, authData, clientDataHash, signature)
            elif mode == "signaturefailed":
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                subCommand = 0x02
                apdu=toggleAlwaysUvwithoutparam(mode, subCommand,protocol)
                util.run_apdu(apdu, "authenticatorConfig(0x0D) :  toggleAlwaysUv(0x02)",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 3: send Getinfo Verify  toggleAlwaysUv")
                response,status=util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 1: send Getinfo Verify  toggleAlwaysUv False or not")
                util.run_apdu("80100000010400", "GetInfo",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
                getpintokenpermissionp2.restPin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
                permission = 0x01  # Authenticator Configuration permission
                mode="wrongrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)     
                clientDataHash =os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                rp="localhost"
                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                if isinstance(makeCredAPDU, str):
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                credId,publickey =enableEnterpriseAttestationctap2.authParasing(response)
                publickey="a5010203262001215820e197766f8b71adf5be90bd7eea4db5af635b328ba9c3d8cd5a0f13c1c9d48a1e22582043dd5751be05dde187ead2ead783b37fe2254ec8fb3028e8c3195c6066f7542e"
            
                print("credId",credId)
                print("publickey",publickey)
                mode="Anyrpid"
                pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)    
                clientDataHash=os.urandom(32)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                protocol=0x02
                rp="localhost"
                apdu = enableEnterpriseAttestationctap2.createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,protocol)
                result, status = util.run_apdu(apdu, "GetAssertion 0x02",  expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
                print("response",result)
                authData, signature=enableEnterpriseAttestationctap2.getasserationparssing(result)
                enableEnterpriseAttestationctap2.verify_getassertion_signature(publickey, authData, clientDataHash, signature)
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


     

           

           

def  toggleAlwaysUvwithoutparam(mode, subCommand,protocol):
    cbor_map = {
            0x01: subCommand          # toggleAlwaysUv      
        }
    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu


def toggleAlwaysUv(mode,pinUvAuthParam, subCommand,protocol):
    if mode == "subcommand.missing":
        
        util.printcolor(util.YELLOW,f"  Missing toggleAlwaysUv subCommand(0x02) ") 
        cbor_map = {
        0x03:protocol,               # pinUvAuthProtocol 
        0x04: pinUvAuthParam
       }
        
    elif mode == "always uvtrue":
        util.printcolor(util.YELLOW,f"  alwaysuv true ") 
        cbor_map = {
            0x01: subCommand            # toggleAlwaysUv
           
        }
    
    elif mode == "pinUvAuthParam.missing":
        util.printcolor(util.YELLOW,f"  Missing toggleAlwaysUv pinUvAuthParam ")
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x03:protocol              # pinUvAuthProtocol
            
        }
    elif mode == "pinUvAuthProtocol.missing":
        util.printcolor(util.YELLOW,f"  Missing toggleAlwaysUv pinUvAuthProtocol ")
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x04: pinUvAuthParam
           
            
        }
    elif mode == "invalid.subcommand":
        util.printcolor(util.YELLOW,f"   toggleAlwaysUv invalid subcommand value:{subCommand}")
        
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
           
            
        }
    elif mode == "invalid.pinUvAuthParam":
        util.printcolor(util.YELLOW,f"   toggleAlwaysUv invalid pinUvAuthParam value:{subCommand}")
        
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
           
            
        }
    elif mode == "invalid.pinUvAuthProtocol":
        util.printcolor(util.YELLOW,f"   toggleAlwaysUv invalid pinUvAuthParam value:{subCommand}")
        
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
           
            
        }
    elif mode == "pinauthparam.notbyte":
        util.printcolor(util.YELLOW,f"   toggleAlwaysUv invalid pinUvAuthParam value:{subCommand}")
        
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: "0111"
           
            
        }
    elif mode =="alwaysuv.paramadded":
        subCommandParams = {
                0x01: 8 }
        
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x02:subCommandParams,
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
        }



    else:
        cbor_map = {
            0x01: subCommand,            # toggleAlwaysUv
            0x03:protocol,               # pinUvAuthProtocol = 2
            0x04: pinUvAuthParam
        }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu

def createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol):

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

    option  = {"rk": True}#alwaysUv,makeCredUvNotRqd

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    uv                 = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()

    if mode =="alwaysuv.makecred":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + uv
        #dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol               # pin protocol V2 assumed
    else:
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + uv
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




def newMinPinLength1(mode,subCommand,subCommandParams,pinUvAuthParam,protocol):

    if mode =="alwaysuvtrueprotocol":
        cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02: subCommandParams,
        0x04: pinUvAuthParam        
    }
    elif mode =="alwaysuvtrueinvalidprotocol":
        protocol=0x00
        cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02: subCommandParams,
        0x03: protocol        
    }
    elif mode =="alwaysuvtrueverificationfailed":
        
        cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02: subCommandParams,
        0x03: protocol,
        0x04: pinUvAuthParam  }



    else:
     cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02: subCommandParams
             
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()+"00"
    return apdu