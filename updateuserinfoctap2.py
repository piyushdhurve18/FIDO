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
import DocumentCreation


permissionRpId = ""
rp="localhost"
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "UPDATE USER INFORMATION"
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
        "updateuserinfo.T":"""Test started: P-1 :
        Precondition: Reset Authenticator, Set PIN and Create one discoverable credential
 If authenticator supports Credential Management API:  Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that: (a) At least Response.user.id is present and matches new value. (b) If authenticator supports name and displayName fields, make sure that updated value is corrent and missing field is now removed.""",

"updateuserinfo.D":"""Test started: P-1 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0D) command with the updateUserInformation (0x07) subcommand, providing non-empty values for user.name and user.displayName (e.g., username: bobsmith, displayName: techhub). Verify that the authenticator updates the matching credential’s user.name and user.displayName accordingly, while the user.id remains unchanged.

Expected Result:The authenticator returns
1.user.name and user.displayName reflect the provided values.
2.user.id remains unchanged.
The operation returns CTAP2_OK.""",



"emptyuser&display":"""Test started: P-2 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0D) command with the updateUserInformation (0x07) subcommand, providing non-empty values for user.name and user.displayName (e.g., username: bobsmith, displayName: techhub). Verify that the authenticator updates the matching credential’s user.name and user.displayName accordingly, while the user.id remains unchanged.

Expected Result:The authenticator returns
1.user.name and user.displayName reflect the provided values.
2.user.id remains unchanged.
The operation returns CTAP2_OK.""",
"missing.emptyuser&display":"""Test started: P-3 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0D) command with the updateUserInformation (0x07) subcommand, omitting the user.name and user.displayName fields entirely. Verify that the authenticator removes the missing fields from the matching credential, while the user.id remains unchanged.
Expected Result:The authenticator returns
1.user.name and user.displayName are removed from the credential.
2.user.id remains unchanged.
The operation returns CTAP2_OK.""",
"useridlength20":"""Test started: P-4 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is createdwith the userId length set to 20 bytes

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Attempt to update the credential’s user.name to a new value. Verify that the user.name field in the response reflects the updated value.
Expected Result:
The authenticator returns CTAP2_OK.""",

"useridlength64":"""Test started: P-5 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is createdwith the userId length set to 64 bytes

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Attempt to update the credential’s user.name to a new value. Verify that the user.name field in the response reflects the updated value.
Expected Result:
The authenticator returns CTAP2_OK.""",

"emptyuser&display.length4update":"""Test started: P-6 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 4 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",
"emptyuser&display.length4":"""Test started: P-7 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Step 1:
If the authenticator supports the Credential Management API, create a discoverable credential. Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value that is exactly 4 bytes long. Verify that the user.name field in the response has a length of 4 bytes.
Expected Result:
The authenticator returns CTAP2_OK.

Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",

"username.length20update":"""Test started: P-8 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 20 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",

"username.length20":"""Test started: P-9 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 20 bytes. Verify that the user.name (UserName) field in the response has a length of exactly 20 bytes.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",

"username.length50update":"""Test started: P-10 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 50 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",
"username.length50":"""Test started: P-11 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 50 bytes. Verify that the user.name (UserName) field in the response has a length of exactly 50 bytes.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"username.length100update":"""Test started: P-12 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 100 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",

"username.length100":"""Test started: P-13 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, create a discoverable credential and send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.name to a value of 100 bytes. Verify that the user.name (UserName) field in the response has a length of exactly 100 bytes.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"username.lengthemptyupdated":"""Test started: P-14 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s  user.name to an empty value. 
Expected Result:
The authenticator returns CTAP2_OK.""",
"username.lengthempty":"""Test started: P-15 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s  user.name to an empty value. Verify that the  user.name field is absent or has a zero-length value in the response.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",

"username.fieldabsentupdated":"""Test started: P-16 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Update the credential such that the user.displayName field is present while the user.name field is absent. Verify that the user.name field remains absent.
Expected Result:
The authenticator returns CTAP2_OK.""",

"username.fieldabsent":"""Test started: P-17 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Update the credential such that the user.displayName field is present while the user.name field is absent. Verify that the user.name field remains absent.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",

"userdisplayname.4byte":"""Test started: P-18 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 4 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",

"userdisplayname.4byteverify":"""Test started: P-19 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 4 bytes. Verify that the user.displayName field in the response has a length of exactly 4 bytes.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"userdisplayname.20byte":"""Test started: P-20 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 20 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",
"userdisplayname.20byteverify":"""Test started: P-21 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 20 bytes. Verify that the user.displayName field in the response has a length of exactly 20 bytes.

Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"userdisplayname.50byte":"""Test started: P-22 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 50 bytes. 

Expected Result:
The authenticator returns CTAP2_OK.""",
"userdisplayname.50byteverify":"""Test started: P-23 :

Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 50 bytes. Verify that the user.displayName field in the response has a length of exactly 50 bytes.

Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",

"userdisplayname.100byte":"""Test started: P-24 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 100 bytes. 
Expected Result:
The authenticator returns CTAP2_OK.""",

"userdisplayname.100byteverify":"""Test started: P-25 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to a value of 100 bytes. Verify that the user.displayName field in the response has a length of exactly 100 bytes.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"emptyuserdisplayname":"""Test started: P-26 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to an empty value. 
Expected Result:
The authenticator returns CTAP2_OK.""",
"emptyuserdisplayname.verify":"""Test started: P-27 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, updating the credential’s user.displayName to an empty value. Verify that the user.displayName field is absent or has a zero-length value in the response.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information was updated successfully. Send the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"displaynameabsent":"""Test started: P-28 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
f the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand while omitting the credential’s user.displayName field.
Expected Result: The authenticator returns CTAP2_OK.""",

"displaynameabsent.verify":"""Test started: P-29 :
Preconditions:
1The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand while omitting the credential’s user.displayName field. Verify that the user.displayName field is absent in the response.
Expected Result:
The authenticator returns CTAP2_OK.
Step 2:
Verify that the user information has been updated successfully by sending the authenticatorCredentialManagement (0x0A) command with the enumerateCredentialsBegin (0x04) subcommand using valid parameters.
Expected Result:
The authenticator returns a response containing the updated user information.""",
"randomupdate":"""Test started: P-30 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Randomly modify the user.displayName and user.name fields.
Expected Result: The authenticator returns CTAP2_OK.""",

"pinUvAuthParam.missing":"""Test started: F-1 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand without including pinUvAuthParam.The authenticator terminates the operation and returns CTAP2_ERR_PUAT_REQUIRED.
Expected Result:
The authenticator returns CTAP2_ERR_PUAT_REQUIRED.""",
"subCommandParams.missing":"""Test started: F-2 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand without including the mandatory parameters in subCommandParams.The authenticator rejects the request and returns CTAP2_ERR_MISSING_PARAMETER.
Expected Result:
The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",
"unsupportedprotocol":"""Test started: F-3 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
If the authenticator supports the Credential Management API, send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07)  using an unsupported pinUvAuthProtocol.
Expected Result:
The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",
"invalid.pinauthparam":"""Test started: F-4 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, including subCommandParams for an existing credential, but provide an invalid pinUvAuthParam.so verification failed  
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",
"withoutcm.permission":"""Test started: F-5 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) using a pinUvAuthToken without cm permission.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"rpidnotmatch":"""Test started: F-6 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) using a pinUvAuthToken whose permissions RP ID does not match the RP ID of the credential. 
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"credidnotmatch":"""Test started: F-6 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand using a credentialId that does not match any existing credential. Attempt to update the user information.
Expected Result:
The authenticator returns CTAP2_ERR_NO_CREDENTIALS.""",

"storgefull":"""Test started: F-6 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, using a valid credentialId. Attempt to update the user information for an existing credential while the authenticator’s internal storage is full. Verify that the authenticator rejects the request and returns CTAP2_ERR_KEY_STORE_FULL.
Expected Result:
The authenticator returns CTAP2_ERR_KEY_STORE_FULL.""",

"useridnotmatch":"""Test started: F-7 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, using a credentialId that corresponds to an existing credential, but include a user parameter whose user.id does not match the credential’s existing user ID. Attempt to update the user information while the user ID does not match. Verify that the authenticator rejects the request and returns CTAP1_ERR_INVALID_PARAMETER.

Expected Result:
The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",
"useridlengthexceed":"""Test started: F-8 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, using a valid credentialId for an existing credential. Provide a user.id whose length exceeds the allowed limit.
Expected Result:
The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",
"emptycredId":"""Test started: F-9 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Provide an empty credentialId while using a correct userId. Attempt to update the user information.
Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
"invalidcredId":"""Test started: F-10 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. Provide an invalid  credentialId while using a correct userId. Attempt to update the user information.

Expected Result:
The authenticator returns CTAP2_ERR_NO_CREDENTIALS	""",

"useridnotencoded":"""Test started: F-11 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, providing user information userid not encoded as a map for user (0x03) and does not follow the PublicKeyCredentialUserEntity format.
Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
"useridisempty":"""Test started: F-12 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand. The credential exists, but an empty userId is provided while the credentialId is valid.
Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
"subcommand.missing":"""Test started: F-12 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07)with missing subcommand.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER""",

"userentity.null":"""Test started: F-13 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) parameter is present but the user (0x03) updated user entity field is null.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",

"credidfield.null":"""Test started: F-14 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) map is present and contains a valid user (0x03) PublicKeyCredentialUserEntity, but the credentialId (0x02) field is null.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER""",

"publickeytyemissing":"""Test started: F-15 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) map is present and includes a valid user (0x03) PublicKeyCredentialUserEntity, but the credentialId (0x02) parameter is present with the "type": "public-key" field missing.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER.""",

"subcommandparamfeildnull":"""Test started: F-16 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) map is present but empty.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER . .""",

"credidtagwrong":"""Test started: F-17 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) map is present, the credentialId field is included with a tag other than 0x02, and the user (0x03) PublicKeyCredentialUserEntity field is present.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER .""",

"userentitytagwrong":"""Test started: F-18 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) map is present, the credentialId field is valid, and the PublicKeyCredentialUserEntity field is included but uses a tag other than 0x03.
Expected Result:
The authenticator is expected to return CTAP2_ERR_MISSING_PARAMETER .""",
"credidtypenotpublickey":"""Test started: F-19 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) map includes all fields (credentialId and userentity), but the credentialId type is not "public-key".
Expected Result:
The authenticator is expected to return CTAP2_ERR_NO_CREDENTIALS.""",

"subcommandparamnotmap":"""Test started: F-20 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.


Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where all fields of subCommandParams (0x02) are present, but subCommandParams is not encoded as a map.
Expected Result:
The authenticator is expected to return CTAP2_ERR_CBOR_UNEXPECTED_TYPE .""",

"invalidsubcommand":"""Test started: F-22 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07)where pinUvAuthParam is computed using a different subCommand value. The authenticator is expected to return CTAP2_ERR_INVALID_SUBCOMMAND.

Expected Result:
The authenticator returns CTAP2_ERR_INVALID_SUBCOMMAND.""",

"invalidsubcommandparam":"""Test started: F-23 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where the subCommandParams (0x02) parameter contains an unexpected or invalid value. The authenticator is expected to return CTAP1_ERR_INVALID_COMMAND.

Expected Result:
The authenticator returns CTAP1_ERR_INVALID_COMMAND.""",
"pinauthparamlengthgreter":"""Test started: F-24 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07)using a pinUvAuthParam longer than the expected length. The authenticator is expected to return CTAP1_ERR_INVALID_LENGTH.
Expected Result:
The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",
"pinauthparamlengthless":"""Test started: F-25 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07)using a pinUvAuthParam less than the expected length. The authenticator is expected to return CTAP1_ERR_INVALID_LENGTH.
Expected Result:
The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",
"withoutregistercredid":"""Test started: F-26 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07) subcommand, where pinUvAuthParam is computed using one set of subCommandParams containing a specific credentialId and user information, but the request is sent with a  random credentialId in subCommandParams. Verify that the authenticator rejects the request and returns CTAP2_ERR_PIN_AUTH_INVALID
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",
"pinauthparamTruncate":"""Test started: F-27 :
Preconditions:
1.The authenticator supports the Credential Management API.
2.The authenticator is reset.
3.A PIN is set on the authenticator.
4.One discoverable credential is created.

Test Description:
Send the authenticatorCredentialManagement (0x0A) command with the updateUserInformation (0x07)using a truncated pinUvAuthParam. The authenticator is expected to return CTAP2_ERR_PIN_AUTH_INVALID.
Expected Result:
The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

          }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])

    util.printcolor(util.YELLOW, "****  Precondition Update user info CTAP2.2 ****")
 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80108000010700", "Reset Card PIN", "00")
    util.run_apdu("80100000010400", "GetInfo", "00")
    
    if protocol==1:
        if mode=="useridlength20":
            user="sasmitasahufidoallia"
            response=precoditionp1(pin,mode,protocol,user)
            
        elif mode =="useridlength64":
            user="a*64"
            response=precoditionp1(pin,mode,protocol,user)
        elif mode =="useridlengthexceed":
            user="a"*64
            response=precoditionp1(pin,mode,protocol,user)
            #user="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        elif mode =="withoutregistercredid":
            getpintokenpermissionp2.setpin(pin)
            user="a"*4
        else:
            user="bobsmith"
            response=precoditionp1(pin,mode,protocol,user)
            print(response)
            
        pinset="yes"



    else:
        if mode=="useridlength20":
            user="sasmitasahufidoallia"
            response=precoditionp2(pin,mode,protocol,user)
            
        elif mode =="useridlength64":
            user="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            response=precoditionp2(pin,mode,protocol,user)
        elif mode =="useridlengthexceed":
            user="a"*64
            response=precoditionp2(pin,mode,protocol,user)
            #user="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        elif mode =="withoutregistercredid":
            getpintokenpermissionp2.setpin(pin)
            user="a"*4
        else:
            user="bobsmith"
            response=precoditionp2(pin,mode,protocol,user)
            
        pinset="yes"
    try:
        scenarioCount += 1
        if protocol==1:
                util.printcolor(util.YELLOW, "**** updateUserInformation CTAP2.2 For   Protocol 1****")
                if str(pinset).lower() == "yes":
                    if mode == "updateuserinfo.T":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita",  # name 
                            "displayName": "unifyia",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "updateuserinfo.D":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "fidoalliance",  # name 
                            "displayName": "fidotool",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptyuser&display":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "missing.emptyuser&display":
                        updated_user_entity= {
                            "id": user.encode() # id: byte sequence
                            
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridlength20":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridlength64":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptyuser&display.length4update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasm",  # name 
                            "displayName": "unif", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "emptyuser&display.length4":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)


                    elif mode == "username.length20update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length20":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length50update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length50":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length100update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length100update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.lengthemptyupdated":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.lengthempty":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "username.fieldabsentupdated":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.fieldabsent":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.4byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.4byteverify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.20byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.20byteverify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.50byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.50byteverify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "userdisplayname.100byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.100byteverify":
                        displayName="a"*70

                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptyuserdisplayname":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": ""
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptyuserdisplayname.verify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": ""
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "displaynameabsent":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu"  # name 
                            
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "displaynameabsent.verify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu"  # name 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp1(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "randomupdate":
                        if response[:2] == "00":
                            print("Make Cred Done ")
                        else:
                            print("Make Cred Failed ")
                            exit(0)
                        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
                        print("credId>>>>>",credential_id)
                        userId=user.encode()   
                        permission=0x04   
                        for i in range(50):
                            util.ResetCardPower()
                            util.ConnectJavaCard()
                            username = f"username{i}"   #  
                            displayName = f"display{i}"
                            updated_user_entity= {
                                "id": userId, # id: byte sequence
                                "name":username,  # name 
                                "displayName": displayName
                            }
                            response1=updateinfop11(mode,credential_id,protocol,pin,updated_user_entity,permission)
                            print(f"Iteration {i}: {response1}")
                            if response1[:2] == "00":
                                    print("update userinfo Done >> "+str(i+1)+" Time")
                            else:
                                print("update userinfo Failed >> "+str(i+1)+" Time")
                                exit(0)
                    
                    elif mode == "pinUvAuthParam.missing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()

                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        # if response[:2] == "36":
                        #    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PUAT_REQUIRED)")
                        # else:
                        #     util.printcolor(util.RED, "  ❌ Test Case Failed")
                        #     exit(0)
                    elif mode == "subCommandParams.missing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()

                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "unsupportedprotocol":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()

                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "invalid.pinauthparam":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        pinUvAuthParam=os.urandom(16)
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "withoutcm.permission":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x20  #without Credential Management
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "rpidnotmatch":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x03  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    
                    elif mode == "credidnotmatch":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "storgefull":
                        response,status=util.APDUhex("80100000010400", "GetInfo")
                        maxcredcount=getInfoMaximumCredsCountsInteger(response)
                        permission=0x01
                        # mode="cmpermission"
                        for i in range(maxcredcount):
                            util.ResetCardPower()
                            util.ConnectJavaCard()
                            global permissionRpId
                            rp="localhost"+str(i)+".com"
                            permissionRpId = rp
                            pinToken=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
                            clientDataHash =os.urandom(32)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
                            util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                            
                            makeCredAPDU=toggleAlwaysUv.createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                            if isinstance(makeCredAPDU, str):
                                response, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                            else:
                                for i, apdu in enumerate(makeCredAPDU):
                                    response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                            # if status == "00":
                            #     print("Make Cred Done >> "+str(i+1)+" Time")
                            # else:
                            #     print("Make Cred Failed >> "+str(i+1)+" Time")
                            #     exit(0)
                            if response[:2] == "00":
                                print("Make Cred Done >> "+str(i+1)+" Time")
                            else:
                                print("Make Cred Failed >> "+str(i+1)+" Time")
                                exit(0)






                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "28":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)


                    elif mode == "useridnotmatch":
                        user="sasmita"
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridlengthexceed":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId1=user.encode()
                        userId="B"*70
                        userId=userId.encode()
                        print("userid>>>>",userId)
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptycredId":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        print("userid>>>>",userId)
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE	)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "invalidcredId":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        print("userid>>>>",userId)
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        mode="credidnotmatch"
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS	)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridnotencoded":
                        displayName="unifyia"
                        username="sasmita sahu"
                        #userId=user.encode()
                        
                        updated_user_entity= {
                            "id": user, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridisempty":
                        displayName="unifyia"
                        username="sasmita sahu"
                        #userId=user.encode()
                        
                        updated_user_entity= {
                            "id":"", # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "subcommand.missing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userentity.null":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                        
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "credidfield.null":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "publickeytyemissing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "subcommandparamfeildnull":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "credidtagwrong":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userentitytagwrong":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "credidtypenotpublickey":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "subcommandparamnotmap":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "invalidsubcommand":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "3E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    
                    elif mode == "pinauthparamlengthgreter":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "pinauthparamlengthless":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "withoutregistercredid":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        response="00"
                        permission = 0x04  #mc and ga
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "pinauthparamTruncate":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        
                        permission = 0x04  
                        response=updateinfop1(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    
                    

                        

        





        elif protocol ==2:
            util.printcolor(util.YELLOW, "**** updateUserInformation CTAP2.2 For   Protocol 2****")
            if str(pinset).lower() == "yes":
                    if mode == "updateuserinfo.T":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita",  # name 
                            "displayName": "unifyia",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "updateuserinfo.D":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "fidoalliance",  # name 
                            "displayName": "fidotool",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)


                    elif mode == "emptyuser&display":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "missing.emptyuser&display":
                        updated_user_entity= {
                            "id": user.encode() # id: byte sequence
                            
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridlength20":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita",  # name 
                            "displayName": "unifyia",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridlength64":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita",  # name 
                            "displayName": "unifyia",  # displayName
                        #"icon": "https://example.com/redpath.png"  # icon (optional)
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "emptyuser&display.length4update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasm",  # name 
                            "displayName": "unif", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptyuser&display.length4":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasm",  # name 
                            "displayName": "unif", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length20update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length20":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length50update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length50":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length100update":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.length100":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.lengthemptyupdated":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.lengthempty":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "",  # name 
                            "displayName": "unifyia", 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.fieldabsentupdated":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "displayName": "unifyia" 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "username.fieldabsent":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "displayName": "unifyia" 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.4byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.4byteverify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.20byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.20byteverify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "userdisplayname.50byte":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.50byteverify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.100byte":
                        displayName="a"*100
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userdisplayname.100byteverify":
                        displayName="a"*100
                        updated_user_entity= {
                            
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName":displayName 
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    
                    elif mode == "emptyuserdisplayname":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": ""
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "emptyuserdisplayname.verify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu",  # name 
                            "displayName": ""
                            #"displayName":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"#64
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "displaynameabsent":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu" # name 
                            
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "displaynameabsent.verify":
                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name": "sasmita sahu"  # name 
                        
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=permissionp2(response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "pinUvAuthParam.missing":
                        displayName="unifyia"
                        username="sasmita sahu"

                        updated_user_entity= {
                            "id": user.encode(), # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "36":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PUAT_REQUIRED)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "subCommandParams.missing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()

                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "unsupportedprotocol":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()

                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "invalid.pinauthparam":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()

                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  # Credential Management
                        pinUvAuthParam=os.urandom(32)
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "withoutcm.permission":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x20  #without Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "rpidnotmatch":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x03  #without Credential Management
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "credidnotmatch":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "storgefull":
                        response1,s=util.APDUhex("80100000010400", "GetInfo")
                        maxcredcount=getInfoMaximumCredsCountsInteger(response1)
                        permission=0x01
                        #mode="rpidnotmatch"
        
                        # mode="cmpermission"
                        for i in range(maxcredcount+1):
                            util.ResetCardPower()
                            util.ConnectJavaCard()
                            rp="localhost"+str(i)+".com"
                            permissionRpId = rp
                            pinToken, pubkey=getPINtokenwithPermission2(mode,pin,permission)  
                            clientDataHash =os.urandom(32)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                            util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
                            
                            makeCredAPDU=toggleAlwaysUv.createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
                            if isinstance(makeCredAPDU, str):
                                response, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
                            else:
                                for i, apdu in enumerate(makeCredAPDU):
                                    response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
                            if response[:2] == "00":
                                print("Make Cred Done >> "+str(i+1)+" Time")
                                result=response
                            else:
                                print("Make Cred Failed >> "+str(i+1)+" Time")
                                

                        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(result)
                        #credential_id="7d97b5c9d6c164656d474517a1bab855e5e8150283662b697a52896a4136d5a9d2a4580bb85c5471421da90240992defcab1131fc1b2fce30d38195f2c97edd683a6a95547a67288af86bdee33c5e969"
                        userId=user.encode()   
                        permission=0x04   
                        for i in range(100):
                            util.ResetCardPower()
                            util.ConnectJavaCard()
                            
                            username = f"username{i}"   #  
                            displayName = f"display{i}"
                            updated_user_entity= {
                                "id": userId, # id: byte sequence
                                "name":username,  # name 
                                "displayName": displayName
                            }
                            response1=updateinfop21(mode,credential_id,protocol,pin,updated_user_entity,permission)
                            print(f"Iteration {i}: {response1}")
                            if response1[:2] == "00":
                                print("update userinfo Done >> "+str(i+1)+" Time")
                            else:
                                print("update userinfo Failed >> "+str(i+1)+" Time")
                                exit(0)

                    elif mode == "useridnotmatch":
                        user="sasmita"
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridlengthexceed":
                        
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId1=user.encode()
                        print("userid>>>>",userId1)
                        userId="B"*70
                        userId=userId.encode()
                        print("userid>>>>",userId)
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "02":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "emptycredId":
                        
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        print("userid>>>>",userId)
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE	)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "invalidcredId":
                        
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        print("userid>>>>",userId)
                        updated_user_entity= {
                            "id": userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        mode="credidnotmatch"
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS	)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "useridnotencoded":
                        displayName="unifyia"
                        username="sasmita sahu"
                        #userId=user.encode()
                        
                        updated_user_entity= {
                            "id": user, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "useridisempty":
                        displayName="unifyia"
                        username="sasmita sahu"
                        #userId=user.encode()
                        
                        updated_user_entity= {
                            "id":"", # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "subcommand.missing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userentity.null":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                        
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "credidfield.null":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "publickeytyemissing":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "subcommandparamfeildnull":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    elif mode == "credidtagwrong":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "userentitytagwrong":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "14":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "credidtypenotpublickey":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "subcommandparamnotmap":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "invalidsubcommand":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "3E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "pinauthparamlengthgreter":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "pinauthparamlengthless":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        print("crdential response:",response)
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "withoutregistercredid":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        response="00"
                        permission = 0x04  #mc and ga
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "2E":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_NO_CREDENTIALS)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "pinauthparamTruncate":
                        displayName="unifyia"
                        username="sasmita sahu"
                        userId=user.encode()
                        
                        updated_user_entity= {
                            "id":userId, # id: byte sequence
                            "name":username,  # name 
                            "displayName": displayName
                        }
                        
                        permission = 0x04  
                        response=updateinfop2(mode,response,protocol,pin,updated_user_entity,permission)
                        if response[:2] == "33":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    elif mode == "randomupdate":
                        if response[:2] == "00":
                            print("Make Cred Done ")
                        else:
                            print("Make Cred Failed ")
                            exit(0)
                        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
                        userId=user.encode()   
                        permission=0x04   
                        for i in range(50):
                            util.ResetCardPower()
                            util.ConnectJavaCard()
                            
                            username = f"username{i}"   #  
                            displayName = f"display{i}"
                            updated_user_entity= {
                                "id": userId, # id: byte sequence
                                "name":username,  # name 
                                "displayName": displayName
                            }
                            response1=updateinfop21(mode,credential_id,protocol,pin,updated_user_entity,permission)
                            print(f"Iteration {i}: {response1}")
                            if response1[:2] == "00":
                                    print("update userinfo Done >> "+str(i+1)+" Time")
                            else:
                                print("update userinfo Failed >> "+str(i+1)+" Time")
                                exit(0)
        else:
            util.printcolor(util.RED, "**** Invalid protocol value ****")
            exit(0)
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

                    
        


def getInfoMaximumCredsCountsInteger(response: str) -> int:
    cbor_hex = extractCBORMap(response)
    decoded = cbor2.loads(bytes.fromhex(cbor_hex))
 
    if not isinstance(decoded, dict):
        raise TypeError("Top-level CBOR object is not a map")
 
    # Get last (key, value) pair
    last_key, maxPossibleRemainingResidentCredentialsCount = next(reversed(decoded.items()))
 
    if not isinstance(maxPossibleRemainingResidentCredentialsCount, int):
        raise TypeError("Last CBOR value is not an integer")
    global maxAllowedCredCount
    maxAllowedCredCount = maxPossibleRemainingResidentCredentialsCount
    return maxPossibleRemainingResidentCredentialsCount

def extractCBORMap(response):
    if len(response) > 6:
        result = response[2:]
    else:
        result = ""
    return result

def getPINtoken(mode,pin,permission):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet", "55")
    #util.APDUhex("80100000010400", "GetInfo")

    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:")
    response, status = util.run_apdu("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",expected_prefix="00") 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    apdu=createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,permission)
    return apdu

def createGetPinToken(mode,key_agreement,pinHashEnc,shared_secret,permission):
    if mode=="getpintokenmappingnotsequence":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission,
        10:"localhost"

    }
    elif mode =="makecred":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9: permission,
        10:"enterprisetest.certinfra.fidoalliance.org"
        }
    elif mode =="Anyrpid":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
        }
    
    elif mode =="nonentrprise":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9:permission

    }
    elif mode =="cmpermission":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9: permission

    }
    else:
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
    response, status = util.run_apdu(apdu,"Client PIN GetPINToken",expected_prefix="00")
    #response, status = util.APDUhex(apdu, "Client PIN  GetPINToken", checkflag=True)
    print("response>>>>>>>>",response)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.pintoken(shared_secret, enc_pin_token)
    
    util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token

def precoditionp1(pin,mode,protocol,user):
    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
    getpintokenpermissionp2.newpinset(pin)
    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
    permission = 0x01  #cm
    mode="Anyrpid"
    #pinToken=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
    pinToken=getPINtoken(mode,pin,permission)
    clientDataHash =os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    rp="localhost"
    makeCredAPDU=toggleAlwaysUv.createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
    if isinstance(makeCredAPDU, str):
        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00")
    else:
        for i, apdu in enumerate(makeCredAPDU):
            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
            
    return response

def precoditionp2(pin,mode,protocol,user):
    util.printcolor(util.YELLOW,f"  Step 2: Perform the setPIN operation using Supported Protocol ")
    getpintokenpermissionp2.setpin(pin)
    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
    util.printcolor(util.YELLOW,f"  Step 3: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) include permission Authenticator config(0x20) ")
    permission = 0x00  # cm
    mode="Anyrpid"
    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)  
    clientDataHash =os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    rp="localhost"
    makeCredAPDU=toggleAlwaysUv.createCBORmakeCred(mode,clientDataHash, rp, user,  pinAuthToken,protocol)
    if isinstance(makeCredAPDU, str):
        response, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            response, status = util.APDUhex(apdu,f" Make Cred Chaining data subcmd 0x01 make Credential:",checkflag=(i == len(makeCredAPDU) - 1))
 
    return response
    #return response


def updateinfop11(mode,credential_id,protocol,pin,updated_user_entity,permission):
    util.printcolor(util.YELLOW,f" CrdentialId:{credential_id}")

    
    pinToken=getPINtokenPubkeynewp1(mode,pin,permission)
    subCommand = 0x07 
    
    apdu=updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity)
    for apdu in apdu:
        response, status = util.APDUhex(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)",checkflag=True)
    return response

def updateinfop1(mode,response,protocol,pin,updated_user_entity,permission):
    
    if mode=="credidnotmatch":
        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
        cred_bytes = bytes.fromhex(credential_id)
        random_credential_id = os.urandom(len(cred_bytes))
        random_credential_id_hex = random_credential_id.hex()
        credential_id = random_credential_id_hex
    elif mode =="withoutregistercredid":
        credential_id=os.urandom(10)
    else:
        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
        util.printcolor(util.YELLOW,f" CrdentialId:{credential_id}")

    
    pinToken=getPINtokenPubkeynewp1(mode,pin,permission)
    subCommand = 0x07 
    
    apdu=updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity)
    if mode in ("pinUvAuthParam.missing"):
            response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="36",expected_error_name="CTAP2_ERR_SUCCESS")
    elif mode in("subCommandParams.missing","subcommand.missing","userentity.null","credidfield.null","publickeytyemissing","subcommandparamfeildnull","credidtagwrong","userentitytagwrong"):
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
    elif mode in ("invalidsubcommand"):
            response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="3E",expected_error_name="CTAP2_ERR_INVALID_SUBCOMMAND")
 
    elif mode in("unsupportedprotocol","useridlengthexceed","useridnotmatch"):
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="02",expected_error_name="CTAP2_ERR_INVALID_PARAMETER")
    elif mode in ("withoutcm.permission","rpidnotmatch","pinauthparamlengthgreter","pinauthparamlengthless","pinauthparamTruncate"):
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
    elif mode in("credidnotmatch","invalidcredId","credidtypenotpublickey","withoutregistercredid"):       
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    elif mode in("emptycredId","useridnotencoded","useridisempty","subcommandparamnotmap"):
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="11",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")




    else:
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
        #response, status = util.APDUhex(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)",checkflag=True)
    return response

def updateinfop2(mode,response,protocol,pin,updated_user_entity,permission):
    
    #credential_id="F6F381C283F27A49B02D40EDF4F02C1784E428BECD934A2BCE74025DD87BF012BA8AB99E11BD79B546898FD0990B9FC4"
    #credential_id="7d97b5c9d6c164656d474517a1bab855e5e8150283662b697a52896a4136d5a9d2a4580bb85c5471421da90240992defcab1131fc1b2fce30d38195f2c97edd683a6a95547a67288af86bdee33c5e969"
    if mode=="credidnotmatch":
        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
        cred_bytes = bytes.fromhex(credential_id)
        random_credential_id = os.urandom(len(cred_bytes))
        random_credential_id_hex = random_credential_id.hex()
        credential_id = random_credential_id_hex
    elif mode =="withoutregistercredid":
        credential_id = bytes.fromhex(os.urandom(10).hex())
    else:
        credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
        util.printcolor(util.YELLOW,f" CrdentialId:{credential_id}")
    
    
    pinToken, pubkey=getPINtokenwithPermission2(mode,pin,permission)  
    subCommand = 0x07 
    apdu=updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity)
    if mode in ("pinUvAuthParam.missing"):
            
            response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="36",expected_error_name="CTAP1_ERR_SUCCESS")
    elif mode in("subCommandParams.missing","subcommand.missing","userentity.null","credidfield.null","publickeytyemissing","subcommandparamfeildnull","credidtagwrong","userentitytagwrong"):       
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
    elif mode in ("withoutcm.permission","rpidnotmatch","pinauthparamlengthgreter","pinauthparamlengthless","pinauthparamTruncate"):
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
    elif mode in("credidnotmatch","invalidcredId","credidtypenotpublickey","withoutregistercredid"):       
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    elif mode in ("invalidsubcommand"):
            response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="3E",expected_error_name="CTAP2_ERR_INVALID_SUBCOMMAND")  
    elif mode in("useridlengthexceed","useridnotmatch","unsupportedprotocol"):       
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
    elif mode in("emptycredId","useridnotencoded","useridisempty","subcommandparamnotmap"):
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="11",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")

    else: 
        response, status = util.run_apdu(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")

        #response, status = util.APDUhex(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)",checkflag=True)
    return response     
    



def updateinfop21(mode,credential_id,protocol,pin,updated_user_entity,permission):
    util.printcolor(util.YELLOW,f" CrdentialId:{credential_id}")
    if mode=="credidnotmatch":
        cred_bytes = bytes.fromhex(credential_id)
        random_credential_id = os.urandom(len(cred_bytes))
        random_credential_id_hex = random_credential_id.hex()
        credential_id = random_credential_id_hex
     
    pinToken, pubkey=getPINtokenwithPermission2new(mode,pin,permission)  
    subCommand = 0x07 
    apdu=updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity)
    for apdu in apdu:
        response, status = util.APDUhex(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)",checkflag=True)
        
    return response


def getPINtokenwithPermission2(mode,curpin,permission):
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

    return token, pubkey


def getPINtokenwithPermission2new(mode,curpin,permission):
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


    pinSetAPDU =createGetPINtoken1(mode,pinHashEnc,key_agreement,permission,subcommand,protocol)
    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey


def createGetPINtoken1(mode,pinHashenc, key_agreement,permission,subcommand,protocol):
    rpid="localhost"
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    cbor_subcommand  = cbor2.dumps(subcommand).hex().upper() 
    cbor_protocol    = cbor2.dumps(protocol).hex().upper()

    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex
    #dataCBOR = dataCBOR + "0A"+ cbor_rpid 
        

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand
   
def createGetPINtoken(mode,pinHashenc, key_agreement,permission,subcommand,protocol):
   
    rpid="localhost"
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    cbor_subcommand  = cbor2.dumps(subcommand).hex().upper() 
    cbor_protocol    = cbor2.dumps(protocol).hex().upper() 
    if mode == "storgefull":
        print("permissionRpId >> ",permissionRpId)
        cbor_rpid  = cbor2.dumps(permissionRpId).hex().upper()
    else:
        cbor_rpid = cbor2.dumps(rpid).hex().upper()
    if mode =="rpidnotmatch":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid 
    elif mode == "storgefull":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid
    elif mode == "storgefull1":
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        
    else:
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPinUvAuthTokenUsingPinWithPermissions
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
        dataCBOR = dataCBOR + "09"+ permission_hex
        dataCBOR = dataCBOR + "0A"+ cbor_rpid 
        

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand



def permissionp1(response,protocol,pin,updated_user_entity,permission):
    credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
    util.printcolor(util.YELLOW,f" CrdentialId:{credential_id}")
    
    mode="cmpermission"
    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
    
    subCommand = 0x07 
    apdu=updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity)
    for apdu in apdu:
        response, status = util.APDUhex(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)",checkflag=True)
    if response[:2] =="00":
        print(response)
    else:
      exit(0)     
    #verify userinfo updated or not
    subCommand=0x04
    mode="cmpermission"
    pinToken,response=getpintokenpermissionp2.getPINtokenPubkeynewp1(mode,pin,permission)
    apdu=enumerateCredentials(subCommand, pinToken, rp, protocol)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)
    return response

def permissionp2(response,protocol,pin,updated_user_entity,permission):
    credential_id,publickey =enableEnterpriseAttestationctap2.authParasing(response)
    util.printcolor(util.YELLOW,f" CrdentialId:{credential_id}")
    mode="cmpermission"
    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)  
    subCommand = 0x07 
    apdu=updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity)
    for apdu in apdu:
        response, status = util.APDUhex(apdu,"CredentialMgmt(0A): updateUserInformation(0x07)",checkflag=True)
    if response[:2] =="00":
        print(response)
    else:
         exit(0)
        #verify
    subCommand=0x04
    pinToken, pubkey,response,status=getpintokenpermissionp2.getPINtokenwithPermission(mode,pin,permission)  
    apdu=enumerateCredentials(subCommand, pinToken, rp, protocol)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)
    return response

import getpintokenpermissionp2
def getPINtokenPubkeynewp1(mode,pin,permission):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    response, status = util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True) 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    apdu=createcbor1(mode,key_agreement,pinHashEnc,shared_secret,permission)
    return apdu

def createcbor1(mode,key_agreement,pinHashEnc,shared_secret,permission):

    if mode =="rpidnotmatch":
        cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 9,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc ,         # pinHashEnc
        9: permission,
        10:"example.com"

    }
    else:
        cbor_map = {
            1: 1,                  # pinProtocol = 1
            2: 9,                  # subCommand = 0x05 (getPINToken)
            3: key_agreement,      # keyAgreement (MAP)
            6: pinHashEnc ,         # pinHashEnc
            9: permission

        }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    response, status = util.APDUhex(apdu, "Client PIN  GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.pintoken(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token

import hmac
import hashlib
import cbor2
from textwrap import wrap


def updateUserInfo(mode,pinToken, subCommand, protocol, credential_id, updated_user_entity):
    
    """
    Builds CTAP2 CredentialMgmt(0x0A) → updateUserInformation(0x07) APDUs
    Always returns a LIST of APDU hex strings
    """

    # -----------------------------
    # Subcommand parameters
    # -----------------------------
    if mode =="emptycredId":

        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id":"",
                "type": "public-key"
            },
            0x03: updated_user_entity
        }
    elif mode =="withoutregistercredid":
        credential_i=os.urandom(10)

        subCommandParams = {
            0x02: {  # credentialId descriptor
                "id":credential_id,
                "type": "public-key"
            },
            0x03: updated_user_entity
        }
    elif mode == "credidfield.null":
        subCommandParams = {
                0x02: {  # credentialId descriptor
                    
                },
                0x03: updated_user_entity
            }
    elif mode =="publickeytyemissing":
        subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            
        },
        0x03: updated_user_entity}
    elif mode =="subcommandparamfeildnull":
        subCommandParams = {
        }
    elif mode =="credidtagwrong":
        subCommandParams = {
        0x00: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
        },
        0x03: updated_user_entity
        }
    elif mode =="userentitytagwrong":
        subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
        },
        0x00: updated_user_entity
        }
    elif mode =="credidtypenotpublickey":
        subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "private-key"
        },
        0x03: updated_user_entity
        }
    elif mode =="subcommandparamnotmap":
        subCommandParams = [
        {"tag": 0x02, "id": bytes.fromhex(credential_id), "type": "public-key"},
        {"tag": 0x03, "user": updated_user_entity}
        ]
    
    else:
        subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
        },
        0x03: updated_user_entity
    }


    # -----------------------------
    # pinUvAuthParam calculation
    # -----------------------------
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params

    if protocol == 1:
        pinUvAuthParam = hmac.new(
            pinToken, auth_message, hashlib.sha256
        ).digest()[:16]
    elif protocol == 2:
        pinUvAuthParam = hmac.new(
            pinToken, auth_message, hashlib.sha256
        ).digest()[:32]
    else:
        raise ValueError("Invalid pinUvAuthProtocol")
        

    # -----------------------------
    # Build CBOR map
    # -----------------------------
    if mode =="pinUvAuthParam.missing": 
        cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: protocol     # pinUvAuthProtocol
       
    }
    elif mode =="subCommandParams.missing": 
        cbor_map = {
        0x01: subCommand,
        0x03: protocol,     # pinUvAuthProtocol
        0x04: pinUvAuthParam
       
    }
    elif mode =="subcommand.missing": 
        cbor_map = {
        0x02: subCommandParams,
        0x03: protocol,     # pinUvAuthProtocol
        0x04: pinUvAuthParam
       
    }
    elif mode =="unsupportedprotocol": 
        protocol= 0
        cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: protocol,     # pinUvAuthProtocol
        0x04: pinUvAuthParam
       
    }
    elif mode =="invalid.pinauthparam":
        if protocol ==1: 
          pinUvAuthParam=os.urandom(16)
        else :
            pinUvAuthParam=os.urandom(32)

        cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: protocol,     # pinUvAuthProtocol
        0x04: pinUvAuthParam
       
        }

    elif mode =="invalidsubcommand":
        subCommand=0

        cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: protocol,     # pinUvAuthProtocol
        0x04: pinUvAuthParam
       
        }
    elif mode =="pinauthparamlengthgreter":
         if protocol ==1:
             pinUvAuthParam=os.urandom(32)
         else:
             pinUvAuthParam=os.urandom(64)
             
         cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: protocol,     # pinUvAuthProtocol
            0x04: pinUvAuthParam
        
            }
    elif mode =="pinauthparamlengthless":
         if protocol ==1:
             pinUvAuthParam=os.urandom(10)
         else:
             pinUvAuthParam=os.urandom(16)
             
         cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: protocol,     # pinUvAuthProtocol
            0x04: pinUvAuthParam
        
            }
    elif mode =="pinauthparamTruncate":
        insert_bytes = b'\x00\x00'  # extra value to add
        insert_len = len(insert_bytes)

        mid = len(pinUvAuthParam) // 2

         # Insert in the middle
        modified = (pinUvAuthParam[:mid] +insert_bytes +pinUvAuthParam[mid:])

        if protocol ==1:
                pinUvAuthParam = modified[:16]
        else:
               pinUvAuthParam = modified[:32]
             
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: protocol,     # pinUvAuthProtocol
            0x04: pinUvAuthParam
        
            }
    
        
    else:
        cbor_map = {
            0x01: subCommand,
            0x02: subCommandParams,
            0x03: protocol,      # pinUvAuthProtocol
            0x04: pinUvAuthParam
        }


    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()

    # CTAP command = 0x0A (CredentialMgmt)
    full_data = "0A" + cbor_hex
    byte_len = len(full_data) // 2

    apdus = []

    # ========================
    # CASE 1: Single APDU
    # ========================
    if byte_len <= 255:
        lc = format(byte_len, "02X")
        apdu = "80100000" + lc + full_data + "00"
        apdus.append(apdu)
        return apdus

    # ========================
    # CASE 2: Chained APDUs
    # ========================
    max_chunk_size = 255 * 2  # 510 hex chars
    chunks = wrap(full_data, max_chunk_size)

    for i, chunk in enumerate(chunks):
        cla = "90" if i < len(chunks) - 1 else "80"
        ins = "10"
        p1 = "00"
        p2 = "00"
        lc = format(len(chunk) // 2, "02X")
        apdu = cla + ins + p1 + p2 + lc + chunk + "00"
        apdus.append(apdu)

    return apdus

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
    apdu = "80100000" + format(lc, "02X") + "0A" + cbor_hex

    return apdu


