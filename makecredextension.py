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
import DocumentCreation

permissionRpId = ""
rp="localhost"
username="bobsmith"

SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - CRED PROTECT)"
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
            "credprotect01":"""Test started: P-1 :
Precondition:; 
1.The authenticator supports the authenticatorMakeCredential (0x01).;
2.The authenticator is reset.;
3.authenticatorGetInfo response includes "credProtect" in the extensions list.;
4.A PIN is set on the authenticator.;;
Test Description:;
P-1 Create a new (discoverable if supported) credential, with "extensions" containing a valid "credProtect" extension set to userVerificationOptional(0x01), 
and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Send a valid GetAssertion(0x02) request with previously recorded credId and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. 
If rk is supported, send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. """,   
"credprotect02":"""Test started: P-2 :
Precondition:; 
1.The authenticator supports the authenticatorMakeCredential (0x01).;
2.The authenticator is reset.;
3.authenticatorGetInfo response includes "credProtect" in the extensions list.;
4.A PIN is set on the authenticator.;
Test Description:;
P-2 Create a new (discoverable if supported) credential, with "extensions" containing valid "credProtect" extension set to userVerificationOptionalWithCredentialIDList(0x02), 
and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Send a valid GetAssertion(0x02) request with previously recorded credId and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. 
Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns an error""",

"credprotect03":"""Test started: P-3 :
Precondition:; 
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.

Test Description:
P-3 Create a new (discoverable if supported) credential, with "extensions" containing valid "credProtect" extension set to userVerificationRequired(0x03), 
and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Send a valid GetAssertion(0x02) request with previously recorded credId and UV/UP set to false, 
and check that Authenticator returns an error Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns an error""",


"credmanagement":"""Test started: P-4 :
Precondition: 
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
P-4 If rk and CredentialManagement is supported: (a) Create a new discoverable credential, with "extensions" containing valid "credProtect" extension set to a random level. 
(b) Call CredentialManagementAPI, find the corresponding credential, and check that credProtect level matches the set value.""",

"getinfo.extension":"""Test started: P-5 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
Test Description
Send a CTAP2 authenticatorGetInfo (0x04) request to the authenticator.Check the extensions field in the response to see whether the platform supports the credProtect extension.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The response MUST include "credProtect" in the extensions (0x02) field, indicating that the authenticator supports the CredProtect extension as defined by the CTAP2 specification.
""",




"uvoptional":"""Test started: P-7 :
Preconditions:
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
5 option rk =false or not include

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01

Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS .
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",



"rktruecred01":"""Test started: P-8 :
Preconditions:
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
5.While doing authenticatorMakeCredential add  option rk = true

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01

Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP1_ERR_SUCCESS (0x00)
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",




"uvwithcredId":"""Test started: P-8 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
5.While doing authenticatorMakeCredential add  option rk = False

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02

Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS.
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS .
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",




"uvwithcredIdrktrue":"""Test started: P-9 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
5.While doing authenticatorMakeCredential add  option rk = true

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02.
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns error code XX (check error code with other authenticator)
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",




"uvrequried":"""Test started: P-10 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
5.While doing authenticatorMakeCredential add  option rk = false

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03  for high-security.This explicitly sets user userVerificationRequired.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",


"uvrequrieduvtrue":"""Test started: P-11 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
5.While doing authenticatorMakeCredential add  option rk = true

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03  for high-security.This explicitly sets user userVerificationRequired.

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS.
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",


"uvoptionalwithoutpin":"""Test started: P-6 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
5.While doing authenticatorMakeCredential add  option rk = false

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.
This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01.
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",

"uvoptinalwithoutpinverify":"""Test started: p-15 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = false


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",


"uvoptinalwithoutpinrktrue":"""Test started: p-15 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = True


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP1_ERR_SUCCESS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP1_ERR_SUCCESS
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",

"credidwithoutpinverify":"""Test started: p-16 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = false

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS  error code
Verify that the authenticator returns CTAP1_ERR_SUCCESS
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",

"credidwithoutpinrktrue":"""Test started: p-16 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = True

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification.
Verify that the authenticator returns CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification .
Verify that the authenticator returns CTAP1_ERR_SUCCESS
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP1_ERR_SUCCESS
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",




"uvrequriedwithoutpinverify":"""Test started: p-16 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = False.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user uvrequried.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step 3:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification .
Verify that the authenticator returns CTAP1_ERR_SUCCESS
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",


"uvrequriedwithoutpinrktrue":"""Test started: p-16 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = True.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user uvrequied.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
Step 3:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification .
Verify that the authenticator returns CTAP1_ERR_SUCCESS
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP1_ERR_SUCCESS
Step 6:
Send a valid U2F Authentication request with previously recorded credentialID  and expect authentication successfull.""",


"newtestcase":"""Test started: p-16 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.While doing authenticatorMakeCredential add  option rk = True.


Test Description:
Step 1:
Two  valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user uvrequied.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credentialID with pinUvAuthParam (0x06) or pin Verification .
Verify that the authenticator returns CTAP1_ERR_SUCCESS.
Step 3:
Send a valid authenticatorGetNextAssertion (0x08).Verify that the authenticator returns CTAP1_ERR_SUCCESS.
""",



"u2fauthentication":"""Test started: P-6 :
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
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns  CTAP1_ERR_SUCCESS  error code
Verify that the authenticator returns  CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
""",


"u2fauthenticationwithpin":"""Test started: P-6 :
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
Send a valid GetAssertion(0x02) request with previously recorded credentialID without pinUvAuthParam (0x06) or pin Verification check that Authenticator returns  CTAP1_ERR_SUCCESS  error code
Verify that the authenticator returns  CTAP1_ERR_SUCCESS.
Step 3:
Send a valid GetAssertion (0x02) request using the previously recorded credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP1_ERR_SUCCESS (0x00).
Step 4:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, without providing pinUvAuthParam (0x06) or performing PIN verification.
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS
Step 5:
Send a valid GetAssertion (0x02) request without an allowList (0x03) / credentialId, with pinUvAuthParam (0x06) or PIN verification performed.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.
""",








"uvwithcredIdwithoutpin":"""Test started: P-9 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.


Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02""",


"uvrequried":"""Test started: P-10 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03  for high-security.This explicitly sets user userVerificationRequired.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03""",

"uvrequriedwithoupin":"""Test started: P-11 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.


Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03  for high-security.This explicitly sets user userVerificationRequired.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03""",

"uvoptinalverify":"""Test started: P-12 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credId and UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
Expected Result:
The authenticator returns CTAP1_ERR_SUCCESS (0x00).""",
"credidverify":"""Test started: P-13 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credId and UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",

"uvrequriedverify":"""Test started: F-1 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x03
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credId and UP set to false, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS.""",



"value01withnocredid":"""Test started: P-14 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01
Step 2:
 If rk is supported, send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code..""",

"value02withnocredid":"""Test started: F-2 :
 Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
If rk is supported, send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",
 


"value03withnocredid":"""Test started: F-3 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns an error CTAP2_ERR_NO_CREDENTIALS.""",
"credvaluewrong":"""Test started: F-4 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.


Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to an invalid value 0x00
Expected Result:
The authenticator returns CTAP2_ERR_INVALID_OPTION.""",

"credvaluewrongwithpin":"""Test started: F-5 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.


Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to an invalid value 0x00
Expected Result:
The authenticator returns CTAP2_ERR_INVALID_OPTION.""",


"uvoptinalwithoutpinverify1":"""Test started: p-15 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.


Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01
Step 2:
Send a valid GetAssertion(0x02) request with previously recorded credId and UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""",





"value01withnocredidnopin":"""Test started: F-7 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x01.This explicitly sets user verification optional for the credential.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x01
Step 2:
 If rk is supported, send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code..""",



"value02withnocredidnopin":"""Test started: F-8 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
If rk is supported, send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS error code.""",
 
"value03withnocredidnopin":"""Test started: F-9 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.

Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns an error CTAP2_ERR_NO_CREDENTIALS.""",
 "mapsizewrong":"""Test started: F-1 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.

Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request that includes the extensions map with a valid credProtect value set to 0x01, explicitly indicating that user verification is optional for the credential. 
The request intentionally uses an incorrect CBOR map size.
Expected Result:
1.The authenticator returns CTAP2_ERR_INVALID_CBOR""",

"upturewith02":"""Test started: F-10 :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x02.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to True, and check that Authenticator returns an error CTAP2_ERR_NO_CREDENTIALS.""",



"cred03withpinauthparam":"""Test started: P :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion (0x02) request in resident key (RK) mode, with UV and UP set to false, and a valid pinAuthParam provided. Verify that the authenticator returns CTAP_OK.""",

"cred03withpinauthparamwithoutcred":"""Test started: p- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion (0x02) request in resident key (RK) mode (no credentialId provided), with UV and UP set to false, and include a valid pinAuthParam.
Verify that the authenticator returns CTAP_OK.""",

"pinauthparampasswithouprotocol":"""Test started: F- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion (0x02) request in resident key (RK) mode (no credentialId provided), with UV and UP set to false, and include a valid pinAuthParam while omitting the protocol parameter.
Verify that the authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",


"invaliddata":"""Test started: F- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Step 1:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include "extensions" with a valid "credProtect" set to 0x03.This explicitly sets user userVerificationOptionalWithCredentialIDList.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes credProtect value =0x02
Step 2:
 Send a valid GetAssertion (0x02) request in resident key (RK) mode (no credentialId provided), with UV and UP set to false, while supplying invalid parameter data.
Verify that the authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",



"extensionnotmap":"""Test started: F- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.
Include an extensions field with a valid credProtect value set to 0x01, explicitly indicating uvOptional, but provide the extension in a non-map format.
Expected Result:
1.The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"keyordernotproper":"""Test started: P- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request where the CBOR map entries are encoded in an incorrect key order.
Expected Result:
1.The authenticator returns CTAP2_OK.""",


"datainvalidformat":"""Test started: P- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.
Include an extensions field with a valid credProtect value set to 0x01, explicitly indicating uvOptional, but provide invalid data.
Expected Result:
1.The authenticator returns CTAP2_OK.""",

"credIdwrong":"""Test started: P- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include an extensions field with a valid credProtect value set to 0x02 userVerificationOptionalWithCredentialIDList.
Expected Result:
The authenticator returns CTAP2_OK.

Step 2:
Send a valid GetAssertion (0x02) request in resident key (RK) mode, with UV and UP set to false, and provide a credentialId, but with an incorrect credentialId value.
Verify that the authenticator returns CTAP2_ERR_NO_CREDENTIALS.""",

"pinauthparaminvalid":"""Test started: P- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include an extensions field with a valid credProtect value set to 0x01 uvoptional.
Expected Result:
The authenticator returns CTAP2_OK.

Step 2:
Send a valid GetAssertion (0x02) request in resident key (RK) mode, with UV and UP set to false, invalidpinauthparam.
Verify that the authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"pinauthparamlengthinvalid":"""Test started: P- :
Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator is reset.
3.authenticatorGetInfo response includes "credProtect" in the extensions list.
4.A PIN is set on the authenticator.
Test Description:
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include an extensions field with a valid credProtect value set to 0x01 uvoptional.
Expected Result:
The authenticator returns CTAP2_OK.

Step 2:
Send a valid GetAssertion (0x02) request in resident key (RK) mode, with UV and UP set to false, and provide an invalid pinAuthParam (for example, a 32-byte value for protocol 2 or a 16-byte value for protocol 1).Verify that the authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",


}
    

    if mode not in descriptions:
                    raise ValueError("Invalid mode!")  
    SCENARIO = util.extract_scenario(descriptions[mode]) 
    util.printcolor(util.YELLOW, descriptions[mode])
    if mode in("credprotect01","credprotect02","credprotect03","credmanagement"):
         util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Precondition : CTAP2.2 authenticatorMakeCredential (0x01) using CredProtect extension Protocol-{protocol}****")
    else:
         util.printcolor(util.YELLOW, f"**** Precondition based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with CredProtect extension Protocol-{protocol} ****")
    
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN","00")
    util.run_apdu("80100000010400", "GetInfo", "00")
    subcommand=0x03
    if protocol == 1:
        protocol = 0x01
        if mode in ["getinfo.extension", "uvoptinalwithoutpinrktrue","uvrequriedwithoutpinrktrue","credidwithoutpinrktrue","uvoptionalwithoutpin","uvwithcredIdwithoutpin","uvrequriedwithoupin","credvaluewrong","uvoptinalwithoutpinverify","credidwithoutpinverify","value01withnocredidnopin","value02withnocredidnopin","value03withnocredidnopin"]:
            print("Authenticator client PIN is not set")
        elif mode =="u2fauthentication":
             print("Perform U2F Registation")
        else:
            clentpinsetp1(pin, protocol, subcommand)
            pinset = "yes"
    else:
        if mode in ["getinfo.extension", "uvoptinalwithoutpinrktrue","uvrequriedwithoutpinrktrue","uvoptinalwithoutpinverify","credidwithoutpinrktrue","uvoptionalwithoutpin","uvwithcredIdwithoutpin","uvrequriedwithoupin","credvaluewrong","credidwithoutpinverify","value01withnocredidnopin","value02withnocredidnopin","value03withnocredidnopin"]:
            print("Authenticator client PIN is not set")
        elif mode =="u2fauthentication":
             print("Perform U2F Registation")
        else:
            clentpinsetp2(pin, protocol, subcommand)
            pinset = "yes"

    if mode in("credprotect01","credprotect02","credprotect03","credmanagement"):
             util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Implementation: CTAP2.2 authenticatorMakeCredential (0x01) using CredProtect extension Protocol-{protocol} ****")
    else:
             util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Implementation: CTAP2.2 authenticatorMakeCredential (0x01) using CredProtect extension Protocol-{protocol} ****")
    try:
        scenarioCount += 1
        if protocol==1:
            
            if str(pinset).lower() == "yes":

                if mode=="credprotect01":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="credprotect02":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E")
                elif mode=="credprotect03":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E")

                elif mode=="credmanagement":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    
                    mode ="cmpermission"
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    subCommand=0X04
                    apdu=enumerateCredentials(subCommand, pinToken, rp, protocol)
                    response, status=util.run_apdu(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    raw = unhexlify(response)
                    decoded = cbor2.loads(raw[1:])  # skip CTAP status byte
                    util.printcolor(util.YELLOW,f" Credprotect value is matching 10:{decoded.get(10)}")
                elif mode=="uvoptional":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    #responseparsing
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    mode ="uvoptional"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                    
                
                elif mode=="rktruecred01":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    #responseparsing
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    u2fauthenticatenew(mode,rp, clientDataHash, credId) 

                elif mode=="uvwithcredId":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    mode ="uvoptional"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                    
                
                
                
                elif mode=="uvwithcredIdrktrue":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    u2fauthenticatenew(mode,rp, clientDataHash, credId) 

                elif mode=="uvrequried":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    mode ="uvoptional"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId) 

                elif mode=="uvrequrieduvtrue":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                elif mode =="uvrequriedwithoutpinverify":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
    
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")  
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")    
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    
                    clientDataHash =os.urandom(32)
                    
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    mode ="uvoptional"
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
                    
                    credId= credential_id.hex() 
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                #not reqried

























                elif mode=="uvoptinalverify":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

                elif mode=="credidverify":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="uvrequriedverify":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="value01withnocredid":
                    print("Hii")
                    
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

                elif mode=="value02withnocredid":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="value03withnocredid":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")

                elif mode=="credvaluewrongwithpin":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=0
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    
                elif mode=="upturewith02":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="cred03withpinauthparam":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="cred03withpinauthparamwithoutcred":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="pinauthparampasswithouprotocol":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="withoutprotocol"
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")

                elif mode=="invaliddata":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    mode="invalidparameter"
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")

                elif mode=="extensionnotmap":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                elif mode=="keyordernotproper1":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                elif mode=="datainvalidformat":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
            
                elif mode=="credIdwrong":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="pinauthparaminvalid":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                elif mode=="pinauthparamlengthinvalid1":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
                elif mode=="pinauthparamlengthinvalid":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    

                elif mode=="mapsizewrong":
                    subcommand=0x05
                    pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="12",expected_error_name="CTAP2_ERR_INVALID_CBOR")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
            
            
            # withoutClientpinset
            else:
                if mode == "getinfo.extension":
                    response,status=util.run_apdu("80100000010400","GetInfo",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    getinforesponse(response)

                elif mode =="credvaluewrong":
                        clientDataHash =os.urandom(32)
                        extension=0
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                elif mode =="uvoptinalwithoutpinverify":
                        
                        clientDataHash =os.urandom(32)
                        extension=1
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        mode ="uvoptional"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                        
                elif mode =="uvoptinalwithoutpinrktrue":
                        clientDataHash =os.urandom(32)
                        extension=1
                        mode="rktrue"
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                        
                elif mode =="credidwithoutpinverify":
                        clientDataHash =os.urandom(32)
                        extension=2
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        mode ="uvoptional"
                        u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                elif mode =="credidwithoutpinrktrue":
                        clientDataHash =os.urandom(32)
                        extension=2
                        mode="rktrue"
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        u2fauthenticatenew(mode,rp, clientDataHash, credId) 
                        

            
                elif mode =="uvrequriedwithoutpinrktrue":
                        clientDataHash =os.urandom(32)
                        extension=3
                        mode="rktrue"
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        response, status = util.run_apdu(makeCredAPDU,f" Make Cred Chaining data subcmd 0x01 make Credential:",expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                        
                elif mode=="u2fauthentication":
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
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinAuthToken = "00"
                    mode="withpinauthparam"
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredandpinauth"
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                



                #not requred










                
                
                elif mode =="value01withnocredidnopin":
                        clientDataHash =os.urandom(32)
                        extension=1
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId=authParasing(response)
                        print("credId:>>>>>",credId)
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode =="value02withnocredidnopin":
                        clientDataHash =os.urandom(32)
                        extension=2
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId=authParasing(response)
                        print("credId:>>>>>",credId)
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode =="value03withnocredidnopin":
                        clientDataHash =os.urandom(32)
                        extension=2
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId=authParasing(response)
                        print("credId:>>>>>",credId)
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                

                
            
                
                
                    
                    

        else:
            util.printcolor(util.YELLOW, "****  authenticatorMakeCredential (0x01) Extension CTAP2.2 For   Protocol 2****")
            if str(pinset).lower() == "yes": 
                if mode=="credprotect01":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="credprotect02":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                elif mode=="credprotect03":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="credmanagement":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    mode="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    mode ="cmpermission"
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    subCommand=0X04
                    apdu=enumerateCredentials(subCommand, pinToken, rp, protocol)
                    response, status=util.run_apdu(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    raw = unhexlify(response)
                    decoded = cbor2.loads(raw[1:])  # skip CTAP status byte
                    util.printcolor(util.YELLOW,f" Credprotect value is matching 10:{decoded.get(10)}")
                elif mode=="uvoptional":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    #responseparsing
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                #U2F
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apdu(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                
                
                
                
                elif mode=="rktruecred01":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    #responseparsing
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

                    #U2F
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apdu(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                

                elif mode=="uvwithcredId":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    print("credId:>>>>>",credId)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)withOUT credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")

                    #U2F
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apdu(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                




                elif mode=="uvwithcredIdrktrue":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    #U2F
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                

                elif mode=="uvrequried":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                    #U2F
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                



                elif mode=="uvrequrieduvtrue":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    mode ="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")

                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                
                    #U2F
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    # 2. Build REGISTER APDU
                    rpid = "example.com"
                    challenge = os.urandom(32)
                    apdu = u2f_register_apdu(rpid, challenge)
                    print("U2F REGISTER APDU:", apdu)
                    # 3. SEND REGISTER APDU 
                    response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                
                elif mode=="u2fauthenticationwithpin":

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
                    
                    credId= credential_id.hex() 
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, challenge)
                    
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    
                    pinAuthToken = util.hmac_sha256(pinToken, challenge)
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode =="uvrequriedwithoutpinverify":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    response, status = util.run_apdu(makeCredAPDU,f" Make Cred Chaining data subcmd 0x01 make Credential:",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    credId,credentialPublicKey=authParasing(response)
                    print("credentialPublicKey",credentialPublicKey)
                    cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                    util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    mode ="uvoptional"
                    u2fauthenticatenew(mode,rp, clientDataHash, credId)
                







                
                
                
                
                
                














                
                
                
                
                
                
                
                elif mode=="uvoptinalverify":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="credidverify":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="uvrequriedverify":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
            
                elif mode=="value01withnocredid":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    mode =="rktrue"
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId,credentialPublicKey=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="value02withnocredid":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
            
                elif mode=="value03withnocredid":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="credvaluewrongwithpin":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=0
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    
                elif mode=="upturewith02":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
        
                elif mode=="cred03withpinauthparam":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="cred03withpinauthparamwithoutcred":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode=="pinauthparampasswithouprotocol1":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    mode="withoutprotocol"
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
        

                elif mode=="invaliddata":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    mode="invalidparameter"
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
                elif mode=="extensionnotmap1":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                elif mode=="keyordernotproper":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                elif mode=="datainvalidformat":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=3
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    
                elif mode=="credIdwrong":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=2
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode=="pinauthparaminvalid":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                elif mode=="pinauthparamlengthinvalid1":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    
                    apdu=createCBORmakeAssertion1(mode,clientDataHash, rp,  credId,protocol,pinAuthToken)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
        
                elif mode=="pinauthparamlengthinvalid":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                


                    


                elif mode=="mapsizewrong":
                    subcommand=0x05
                    pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                    clientDataHash =os.urandom(32)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    extension=1
                    makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension)
                    
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="12")
                    else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    util.printcolor(util.GREEN, "ERROR CODE: (CTAP2_ERR_INVALID_CBOR)")




            
            # withoutClientpinset
            else:
                if mode == "getinfo.extension":
                    response,status=util.run_apdu("80100000010400","GetInfo",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    getinforesponse(response)

                elif mode in ["uvoptionalwithoutpin","uvwithcredIdwithoutpin","uvrequriedwithoupin"]:
                    clientDataHash = os.urandom(32)
                    extension_map = {
                        "uvoptionalwithoutpin": 1,
                        "uvwithcredIdwithoutpin":2,
                        "uvrequriedwithoupin": 3
                        
                    }
                    extension = extension_map[mode]

                    makeCredAPDU = createCBORmakeCredwithoutpinauth(mode, clientDataHash, rp, username, protocol, extension)

                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(
                                apdu,"Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                # elif mode =="uvoptinalwithoutpinverify":
                #     clientDataHash =os.urandom(32)
                #     extension=1
                #     makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                #     if isinstance(makeCredAPDU, str):
                #             response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                #     else:
                #         for i, apdu in enumerate(makeCredAPDU):
                #             response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                #     credId=authParasing(response)
                #     print("credId:>>>>>",credId)
                #     clientDataHash =os.urandom(32)
                #     apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                #     response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode =="uvoptinalwithoutpinverify":
                        
                        clientDataHash =os.urandom(32)
                        extension=1
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        
                        #U2F
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        # 2. Build REGISTER APDU
                        rpid = "example.com"
                        challenge = os.urandom(32)
                        apdu = u2f_register_apdu(rpid, challenge)
                        print("U2F REGISTER APDU:", apdu)
                        # 3. SEND REGISTER APDU 
                        response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                
                elif mode =="uvoptinalwithoutpinrktrue":
                        clientDataHash =os.urandom(32)
                        extension=1
                        mode="rktrue"
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        
                        #U2F
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        # 2. Build REGISTER APDU
                        rpid = "example.com"
                        challenge = os.urandom(32)
                        apdu = u2f_register_apdu(rpid, challenge)
                        print("U2F REGISTER APDU:", apdu)
                        # 3. SEND REGISTER APDU 
                        response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                
                elif mode =="credidwithoutpinverify":
                        clientDataHash =os.urandom(32)
                        extension=2
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        
                        #U2F
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        # 2. Build REGISTER APDU
                        rpid = "example.com"
                        challenge = os.urandom(32)
                        apdu = u2f_register_apdu(rpid, challenge)
                        print("U2F REGISTER APDU:", apdu)
                        # 3. SEND REGISTER APDU 
                        response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode =="credidwithoutpinrktrue":
                        clientDataHash =os.urandom(32)
                        extension=2
                        mode="rktrue"
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        else:
                            for i, apdu in enumerate(makeCredAPDU):
                                response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                        credId,credentialPublicKey=authParasing(response)
                        print("credentialPublicKey",credentialPublicKey)
                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp, credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without pinAuthParam and with credentialId", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                        clientDataHash =os.urandom(32)
                        pinAuthToken = "00"
                        mode="withpinauthparam"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        clientDataHash =os.urandom(32)
                        mode="withoutcredId"
                        apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                        
                        util.printcolor(util.YELLOW, f"credId: {credId}")
                        
                        clientDataHash =os.urandom(32)
                        
                        mode="withoutcredandpinauth"
                        apdu=createCBORmakeAssertion1(mode,clientDataHash, rp, credId,protocol,pinAuthToken)
                        response, status = util.run_apdu(apdu, "GetAssertion (0x02)without credentialId and with pinAuthParam ", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                        
                        #U2F
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        # 2. Build REGISTER APDU
                        rpid = "example.com"
                        challenge = os.urandom(32)
                        apdu = u2f_register_apdu(rpid, challenge)
                        print("U2F REGISTER APDU:", apdu)
                        # 3. SEND REGISTER APDU 
                        response, status = util.run_apduu2f(apdu,"U2F REGISTER",expected_prefix="05",expected_error_name="CTAP1_ERR_SUCCESS")
            

                
                elif mode =="uvrequriedwithoutpinrktrue":
                        clientDataHash =os.urandom(32)
                        extension=3
                        mode="rktrue"
                        makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                        response, status = util.run_apdu(makeCredAPDU,f" Make Cred Chaining data subcmd 0x01 make Credential:",expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                    
                elif mode=="u2fauthentication":
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
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    pinAuthToken = "00"
                    mode="withpinauthparam"
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                    
                    util.printcolor(util.YELLOW, f"credId: {credId}")
                    mode="withoutcredandpinauth"
                    apdu=createCBORmakeAssertion1(mode,challenge, rpid,  credId,protocol,pinAuthToken)
                    response, status = util.run_apduu2f(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
                



                
                elif mode =="credidwithoutpinverify":
                    clientDataHash =os.urandom(32)
                    extension=2
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                
                elif mode =="value01withnocredidnopin":
                    clientDataHash =os.urandom(32)
                    extension=1
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                elif mode =="value02withnocredidnopin":
                    clientDataHash =os.urandom(32)
                    extension=2
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
                elif mode =="value03withnocredidnopin":
                    clientDataHash =os.urandom(32)
                    extension=3
                    makeCredAPDU=createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, username,protocol,extension)
                    if isinstance(makeCredAPDU, str):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                    else:
                        for i, apdu in enumerate(makeCredAPDU):
                            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                    credId=authParasing(response)
                    print("credId:>>>>>",credId)
                    clientDataHash =os.urandom(32)
                    mode="withoutcredId"
                    apdu=createCBORmakeAssertion(mode,clientDataHash, rp,  credId,protocol)
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    finally:
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1
        
                         
            
         
         
              


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
     # Convert hex string → bytes if needed
    if isinstance(response, str):
        response = bytes.fromhex(response)

                # If response starts with CTAP status byte 0x00, strip it
    if response and response[0] == 0x00:
        response = response[1:]

                # Now the first byte MUST be a CBOR map (0xA0–0xBF)
    print("First CBOR byte:", hex(response[0]))

    decoded = cbor2.loads(response)

    # decoded must be a dict
    assert isinstance(decoded, dict), f"Unexpected CBOR type: {type(decoded)}"

    # Extensions field (key 0x02)
    extensions = decoded.get(0x02)
    assert extensions is not None, "Extensions field missing"

    assert "credProtect" in extensions, "credProtect not supported"

    print("PASS: credProtect extension is supported")
     

def createCBORmakeCredwithoutpinauth(mode,clientDataHash, rp, user,protocol,credprotect):

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
    if mode=="rktrue":
        option  = {"rk": True}#alwaysUv,makeCredUvNotRqd
    else:
         option  = {"rk": False}
         
    extension={"credProtect": credprotect}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    uv                 = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()

    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "06"+ cbor_extension
    dataCBOR = dataCBOR + "07" + uv

    #dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    #dataCBOR = dataCBOR + "09"+ cbor_protocol 

    

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
import cbor2
from io import BytesIO
def parse_credential_pubkey_and_extensions(hex_data):
    raw = bytes.fromhex(hex_data)
    bio = BytesIO(raw)
    decoder = cbor2.CBORDecoder(bio)

    cose_key = decoder.decode()       # First CBOR object
    extensions = decoder.decode()     # Second CBOR object

    return cose_key, extensions

def createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol,credprotect):
    
   

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
    if mode =="rktrue":    
        option  = {"rk": True}#alwaysUv,makeCredUvNotRqd
    else:
         option  = {"rk": False}

    extension={"credProtect": credprotect}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_option        = cbor2.dumps(option).hex().upper()
    cbor_protocol      = cbor2.dumps(protocol).hex().upper()
    cbor_extension      = cbor2.dumps(extension).hex().upper()

    if mode == "mapsizewrong":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol 
    elif mode == "extensionnotmap":
        extension=["credProtect",credprotect]
        cbor_extension      = cbor2.dumps(extension).hex().upper()

        dataCBOR = "A8"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol 
    elif mode == "keyordernotproper":
        dataCBOR = "A8"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol 
    elif mode == "datainvalidformat":
        extensionivalid={"credProtect":True}
        cbor_extension1      = cbor2.dumps(extensionivalid).hex().upper()
        dataCBOR = "A8"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_extension1
        #dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol
    elif mode == "pinauthparamlengthinvalid":
        if protocol ==1:
             pinAuthToken=os.urandom(32)
        else:
             pinAuthToken=os.urandom(64)

        cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
        dataCBOR = "A8"
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
    
def u2fauthenticatenew(mode,rp, clientDataHash, credId):
    print("mode-->",mode)
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    #clientDataHash1=os.urandom(32)
    apdu = u2f_authenticate_apdunew(rp, clientDataHash, credId)
    print("U2F AUTHENTICATE APDU:", apdu)
                    # 4. Send AUTHENTICATE APDU
    if mode in ("uvoptional"):
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

import hashlib
import os

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


import os
import hashlib

import hashlib
import os

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



import binascii

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


def extract_makecredential_response(hex_response):
    response_bytes = bytes.fromhex(hex_response)

    # Strip CTAP status byte if present
    if response_bytes[0] == 0x00:
        response_bytes = response_bytes[1:]

    decoded_cbor = cbor2.loads(response_bytes)

    print("Decoded CBOR keys:", decoded_cbor.keys())

    # --- authData ---
    authdata = decoded_cbor.get(0x02)
    if not isinstance(authdata, bytes):
        raise TypeError("authData must be bytes")

    # --- extensions ---
    extensions = decoded_cbor.get(0x04)
    if extensions is None:
        print("No extensions returned")
    else:
        print("Extensions returned:", extensions)

    return authdata, extensions

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

def createCBORmakeAssertion(mode,cryptohash, rp,  credId,protocol):
    

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
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    pin_protocol       = cbor2.dumps(protocol).hex().upper()                                      # 0x07: pinProtocol = 2
    if mode=="withoutcredId":
        dataCBOR = "A4"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + pin_protocol
    else:
              
    # 5-element map
        dataCBOR = "A4"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        #dataCBOR += "07" + pin_protocol
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80100000" + format(length, '02X') + full_payload
    return apdu



def createCBORmakeAssertion1(mode,cryptohash, rp,  credId,protocol,pinauthtoken):
    # yubikey 48
    # card 80 thales 16

    if mode=="credIdwrong":
         credId=os.urandom(80)
         allow_list = [{
        "id": credId,
        "type": "public-key"
        
    }]
         
    else:
        allow_list = [{
            "id": bytes.fromhex(credId),
            "type": "public-key"
            
        }]
    
     
    option= {"up":False}
   
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinauth       = cbor2.dumps(pinauthtoken).hex().upper()
    pin_protocol       = cbor2.dumps(protocol).hex().upper()                                      # 0x07: pinProtocol = 2
    if mode=="withoutcredId":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="withpinauthparam":
        if protocol==1:
            pinauthtoken=os.urandom(16)
        else:
            pinauthtoken=os.urandom(32)
        cbor_pinauth       = cbor2.dumps(pinauthtoken).hex().upper()
             
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutcredandpinauth":
        if protocol==1:
            pinauthtoken=os.urandom(16)
        else:
            pinauthtoken=os.urandom(32)
        cbor_pinauth       = cbor2.dumps(pinauthtoken).hex().upper()
             
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="withoutprotocol":
        dataCBOR = "A4"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        #dataCBOR += "07" + pin_protocol
    elif mode=="invalidparameter":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_option
        dataCBOR += "07" + pin_protocol
    elif mode=="pinauthparaminvalid":
        if protocol ==1:
           pinauthtoken=os.urandom(16)
        else:
           pinauthtoken=os.urandom(32)  
        cbor_pinauth       = cbor2.dumps(pinauthtoken).hex().upper()
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    elif mode=="pinauthparamlengthinvalid":
        if protocol ==1:
           pinauthtoken=os.urandom(32)
        else:
           pinauthtoken=os.urandom(64)  
        cbor_pinauth       = cbor2.dumps(pinauthtoken).hex().upper()
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    else:
              
    # 5-element map
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "05" + cbor_option
        dataCBOR += "06" + cbor_pinauth
        dataCBOR += "07" + pin_protocol
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80100000" + format(length, '02X') + full_payload+"00"
    return apdu
def enumerateCredentials(subCommand, pinToken, rp, protocol):
    # Compute rpIdHash
    rpIDHash = hashlib.sha256(rp.encode("utf-8")).digest()

    # Build subCommand parameters
    subCommandParams = {
        0x01: rpIDHash
    }

    # Encode parameters and build auth message
    subCommandParamsBytes = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + subCommandParamsBytes

    # Generate pinUvAuthParam based on protocol
    if protocol == 1:
        pinUvAuthParam = hmac.new(
            pinToken, auth_message, digestmod="sha256"
        ).digest()[:16]
    else:
        pinUvAuthParam = hmac.new(
            pinToken, auth_message, digestmod="sha256"
        ).digest()[:32]

    # Final CBOR map
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: protocol,               # pinUvAuthProtocol
        0x04: pinUvAuthParam
    }

    # Encode CBOR
    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()

    # Debug output
    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    # Build APDU (CTAP command 0x0A)
    lc = len(cbor_bytes) + 1  # +1 for CTAP command byte
    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex+"00"

    return apdu

# import cbor2
# def extension(resp):
#  cbor_payload = resp[1:]  

# # Decode CBOR
# decoded = cbor2.loads(cbor_payload)

# print("Decoded GetInfo response:", decoded)

# # CTAP2 GetInfo: extensions field key = 0x02
# extensions = decoded.get(0x02)

# if extensions is None:
#     raise AssertionError("Extensions field (0x02) not present in GetInfo response")

# # Check for credProtect support
# if "credProtect" not in extensions:
#     raise AssertionError("credProtect extension not supported")

# print("PASS: credProtect extension is supported")
     


                