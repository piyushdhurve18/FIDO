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
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - HMAC SECRET)"
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
         "tooltest1":"""Test started: P-1:(rk =True):       
                    Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containing a valid "hmac-secret" set to true, wait for the response, 
                    and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, with extensions payload containing 'hmac-secret' field set to true""",
         "tooltest2":"""Test started: P-2:(rk =True):  
                    Send a valid CTAP2 getAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with one salt, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
                        (a) Check that response contains extensions encrypted "hmac-secret" extension response. Decrypt it and save it as salt1
                        (b) Send another GetAssertion with salt1 and salt2, and check that response still equal to result, and nonUvSalt2Hmac does not equal nonUvSalt1Hmac """, 
         "tooltest3":"""Test started: P-3:(rk =True): 
                    Send a valid CTAP2 GetAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with salt1 and salt2, wait for the response, and:
                        (a) Check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
                        (b) Check that response extensions contain "hmac-secret" extension. Decrypt extensions
                        (c) Check that decrypted hmacs contain uvSalt1Hmac, and uvSalt2Hmac
                        (d) Check that uvSalt1Hmac does not equal to nonUvSalt1Hmac, an uvSalt2Hmac does not equal to nonUvSalt2Hmac.""",
         "tooltest4":"""Test started: P-4:(rk =False): 
                    Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containing a valid "hmac-secret" set to true, 
                    wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, with extensions payload containing 'hmac-secret' field set to true.""",
          "tooltest5":"""Test started: P-5:(rk =False): 
                    Send a valid CTAP2 getAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with one salt, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
                        (a) Check that response contains extensions encrypted "hmac-secret" extension response. Decrypt it and save it as salt1
                        (b) Send another GetAssertion with salt1 and salt2, and check that response still equal to result, and nonUvSalt2Hmac does not equal nonUvSalt1Hmac.""",
         "tooltest6":"""Test started: P-6:(rk =False):
                    Send a valid CTAP2 GetAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with salt1 and salt2, wait for the response, and:
                        (a) Check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
                        (b) Check that response extensions contain "hmac-secret" extension. Decrypt extensions
                        (c) Check that decrypted hmacs contain uvSalt1Hmac, and uvSalt2Hmac
                        (d) Check that uvSalt1Hmac does not equal to nonUvSalt1Hmac, an uvSalt2Hmac does not equal to nonUvSalt2Hmac.""", 
         "tooltest7":"""Test started: F-1:(rk =True):
                    Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containing "hmac-secret" set to a random type, 
                    wait for the response, and check that Authenticator returns an error.""", 
         "tooltest8":"""Test started: F-2:(rk =True):
                    Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret" extension request with one salt that is shorter than 32 bytes, 
                    wait for the response, and check that authenticator returns an error.""", 
         "tooltest9":"""Test started: F-3:(rk =True):
                    Send a CTAP2 getAssertion(0x02) message, with "extensions" containing a "hmac-secret" extension request with two salts, 
                    with second salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error.""", 
         "tooltest10":"""Test started: F-4:(rk =False):
                    Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containing "hmac-secret" set to a random type, wait for the response, 
                    and check that Authenticator returns an error.""", 
         "tooltest11":"""Test started: F-5:(rk =False):
                    Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret" extension request with one salt that is shorter than 32 bytes, 
                    wait for the response, and check that authenticator returns an error.""", 
         "tooltest12":"""Test started: F-6:(rk =False):
                    Send a CTAP2 getAssertion(0x02) message, with "extensions" containing a "hmac-secret" extension request with two salts, 
                    with second salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error.""", 

        

"newtestcase":"""Test started: P-27 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.A PIN is configured on the authenticator.

Step 1:
Create Credential 1 using authenticatorMakeCredential (0x01)
with "hmac-secret": true,Verify CTAP1_ERR_SUCCESS
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Create Credential 2 using authenticatorMakeCredential (0x01)
with "hmac-secret": true,Verify CTAP1_ERR_SUCCESS
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).

Step 3: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".

Decrypt output → save HMAC1

Step 4:
Send authenticatorGetNextAssertion (0x08)
Verify:
1. CTAP2_SUCCESS
2. Response extensions contain "hmac-secret"
Decrypt output → save HMAC2

Expected Result:
1. HMAC1 ≠ HMAC2
2. Both correspond to different credentials""",

"newtestcasetwosalt":"""Test  started: P-28 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.
3.A PIN is configured on the authenticator.

Step 1:
Create Credential 1 using authenticatorMakeCredential (0x01)
with "hmac-secret": true,Verify CTAP1_ERR_SUCCESS
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).

Step 2:
Create Credential 2 using authenticatorMakeCredential (0x01)
with "hmac-secret": true,Verify CTAP1_ERR_SUCCESS
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).

Step 3: (Retrieve HMAC Secret Using Two Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".

Decrypt output → save HMAC1

Step 4:
Send authenticatorGetNextAssertion (0x08)
Verify:
1. CTAP2_SUCCESS
2. Response extensions contain "hmac-secret"
Decrypt output → save HMAC2

Expected Result:
1. HMAC1 ≠ HMAC2
2. Both correspond to different credentials""",



"onesaltuserverfication": """Test started: P-29

Preconditions:
1. The authenticator supports CTAP2.
2. The authenticator is reset.
3. The authenticatorGetInfo response includes "hmac-secret" in the extensions list.
4. The authenticatorGetInfo response reports the default hmac-secret value.
5. The authenticator supports discoverable credentials (rk=True) with the hmac-secret extension.
6. A PIN is configured on the authenticator.

Test Description:

Step 1: Create Credential with hmac-secret Enabled
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True and include the extension:
"hmac-secret": true.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The authenticatorMakeCredential response contains an "extensions" field.
3. The "extensions" field includes "hmac-secret": true.

Step 2: Retrieve HMAC Secret Using One Salt with User Verification
Send a valid CTAP2 authenticatorGetAssertion (0x02) request including the "hmac-secret" extension with:
1. A valid keyAgreement.
2. Properly encrypted saltEnc containing salt1 (32 bytes).
3. A valid saltAuth.
4. pinUvAuthProtocol included if required.
5. The request is performed with user verification (UV).

Ensure salt1 is a newly generated random 32-byte value.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. The returned encrypted "hmac-secret" value length is 48 bytes (32 bytes for protocol 1).
5. After decrypting using the shared secret:
   - The decrypted output length is 32 bytes.
   - The value corresponds to HMAC-SHA-256(CredRandomWithUV, salt1).

Decrypt the returned value and store it as HMAC1.

Step 3: Retrieve HMAC Secret Using the Same Salt without User Verification
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including the "hmac-secret" extension with:
1. A valid keyAgreement.
2. Properly encrypted saltEnc containing the same salt1 used previously.
3. A valid saltAuth.
4. pinUvAuthProtocol included if required.
5. The request is performed without user verification (no UV).

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. After decrypting the returned value:
   - The decrypted output length is 32 bytes.

Decrypt the returned value and store it as HMAC2.

Pass Condition:
HMAC1_withUV ≠ HMAC2_withoutUV

This verifies that the authenticator derives different HMAC values when authenticatorGetAssertion is performed with user verification compared to without user verification.
""",

"twosaltuserverfication": """Test started: P-30

Preconditions:
1. The authenticator supports CTAP2.
2. The authenticator is reset.
3. The authenticatorGetInfo response includes "hmac-secret" in the extensions list.
4. The authenticatorGetInfo response reports the default hmac-secret value.
5. The authenticator supports discoverable credentials (rk=True) with the hmac-secret extension.
6. A PIN is configured on the authenticator.

Test Description:

Step 1: Create Credential with hmac-secret Enabled
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True and include the extension:
"hmac-secret": true.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The authenticatorMakeCredential response contains an "extensions" field.
3. The "extensions" field includes "hmac-secret": true.

Step 2: Retrieve HMAC Secret Using One Salt with User Verification
Send a valid CTAP2 authenticatorGetAssertion (0x02) request including the "hmac-secret" extension with:
1. A valid keyAgreement.
2. Properly encrypted saltEnc containing salt1 (32 bytes).
3. A valid saltAuth.
4. pinUvAuthProtocol included if required.
5. The request is performed with user verification (UV).

Ensure salt1 is a newly generated random 32-byte value.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. The returned encrypted "hmac-secret" value length is 48 bytes (32 bytes for protocol 1).
5. After decrypting using the shared secret:
   - The decrypted output length is 32 bytes.
   - The value corresponds to HMAC-SHA-256(CredRandomWithUV, salt1).

Decrypt the returned value and store it as HMAC1.

Step 3: Retrieve HMAC Secret Using the Same Salt without User Verification
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including the "hmac-secret" extension with:
1. A valid keyAgreement.
2. Properly encrypted saltEnc containing the same salt1 used previously.
3. A valid saltAuth.
4. pinUvAuthProtocol included if required.
5. The request is performed without user verification (no UV).

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. After decrypting the returned value:
   - The decrypted output length is 32 bytes.

Decrypt the returned value and store it as HMAC2.

Pass Condition:
HMAC1_withUV ≠ HMAC2_withoutUV

This verifies that the authenticator derives different HMAC values when authenticatorGetAssertion is performed with user verification compared to without user verification.
""",









         "getinfocase5":"""Test started: P-7 :
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
2.The response contains hmac-secret in the extensions list.
3.The response includes the hmac-secret field, and its value matches the default .""",


"getinfocase6":"""Test started: P-8 :
Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.


Test Description:
Verify that the authenticator advertises support for the hmac-secret extension.
Steps:
Send a valid authenticatorGetInfo (0x04) request.The authenticator returns CTAP2_SUCCESS.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains hmac-secret in the extensions list.
3.The response includes the hmac-secret field, and its value matches the default .""",


"hmaccase7":"""Test started: P-9 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,
"hmaccase8":"""Test started: P-10 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,

"hmaccase9":"""Test started: P-11 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,
"hmaccase10":"""Test started: P-12 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,

"hmaccase11":"""Test started: P-13 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports  discoverable (rk=True) credentials with hmac-secret

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using Two Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).

Expected output:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. The returned "hmac-secret" encrypted value length is 80 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
 """,

"hmaccase12":"""Test started: P-14 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using Two Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).

Expected output:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. The returned "hmac-secret" encrypted value length is 80 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
 """,
"hmaccase13":"""Test started: P-15 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=False) credentials with hmac-secret


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using Two Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).

Expected output:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. The returned "hmac-secret" encrypted value length is 80 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successfull.
 """,
"hmaccase14":"""Test started: P-16 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=False) credentials with hmac-secret
6.The authenticator is configured with a PIN.


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: (Retrieve HMAC Secret Using Two Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).

Expected output:
1. The authenticator returns CTAP2_SUCCESS (0x00).
2. The response contains an "extensions" field inside authenticatorData.
3. The "extensions" field includes "hmac-secret".
4. The returned "hmac-secret" encrypted value length is 80 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successfull.
 """,
"hmaccase15":"""Test started: P-17 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret
6.The authenticator is configured with a PIN.


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response an  "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Ensure:salt1 and salt2 is a newly generated 32-byte random value.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes(for protocol 1 64). 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 


Step 3:
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.A properly encrypted saltEnc containing the same salt1 || salt2 used in Step 2 (do NOT generate new salts)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Expected Result
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The returned HMAC values for salt1 and salt2 match exactly with the values obtained in Step 2.
3.Salt verification is successful (identical salts produce identical HMAC outputs).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",


"hmaccase26":"""Test started: P-26 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret
6.The authenticator is configured with a PIN.


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response an  "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes) with uv
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Ensure:salt1 and salt2 is a newly generated 32-byte random value .


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes(for protocol 1 64). 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 


Step 3:
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.A properly encrypted saltEnc containing the same salt1 || salt2 used in Step 2 (do NOT generate new salts) but withouUv
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Expected Result
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The returned HMAC values for salt1 and salt2  not match exactly with the values obtained in Step 2.
3.Check that returned hmac secret1  equals to the hamc secret2 is different.


Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",


"hmaccase16":"""Test started: P-16 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret
6.The authenticator is configured with a PIN.


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response an  "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Ensure:salt1 and salt2 is a newly generated 32-byte random value.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes(for protocol 1 64). 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 


Step 3:
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.A properly encrypted saltEnc containing the same salt1 || salt2 used in Step 2 (do NOT generate new salts)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Expected Result
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The returned HMAC values for salt1 and salt2 match exactly with the values obtained in Step 2.
3.Salt verification is successful (identical salts produce identical HMAC outputs).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",
"hmaccase17":"""Test started: P-18 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret



Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response an  "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Ensure:salt1 and salt2 is a newly generated 32-byte random value.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes(for protocol 1 64). 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 


Step 3:
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.A properly encrypted saltEnc containing the same salt1 || salt2 used in Step 2 (do NOT generate new salts)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Expected Result
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The returned HMAC values for salt1 and salt2 match exactly with the values obtained in Step 2.
3.Salt verification is successful (identical salts produce identical HMAC outputs).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
""",
"hmaccase18":"""Test started: P-19 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret



Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response an  "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Ensure:salt1 and salt2 is a newly generated 32-byte random value.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes(for protocol 1 64). 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 


Step 3:
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.A properly encrypted saltEnc containing the same salt1 || salt2 used in Step 2 (do NOT generate new salts)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Expected Result
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The returned HMAC values for salt1 and salt2 match exactly with the values obtained in Step 2.
3.Salt verification is successful (identical salts produce identical HMAC outputs).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"hmaccase19":"""Test started: P-20 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret



Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response an  "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Ensure:salt1 and salt2 is a newly generated 32-byte random value.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes(for protocol 1 64). 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 


Step 3:
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.A properly encrypted saltEnc containing the same salt1 || salt2 used in Step 2 (do NOT generate new salts)
3.Valid saltAuth
4.pinUvAuthProtocol included if required .
Expected Result
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The returned HMAC values for salt1 and salt2 match exactly with the values obtained in Step 2.
3.Salt verification is successful (identical salts produce identical HMAC outputs).

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
""",
"hmaccase20":"""Test started: P-21 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": False. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response no  "extensions" field.


Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is successful.
 """,
"hmaccase21":"""Test started: P-22 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports  discoverable (rk=True) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": False. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response no  "extensions" field.


Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
 """,
"hmaccase22":"""Test started: P-23 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": False. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response no  "extensions" field.


Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
 """,
"hmaccase23":"""Test started: P-24 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": False. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response no  "extensions" field.


Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is Successfull.
 """,
"hmaccase24":"""Test started: P-25 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  nondiscoverable (rk=False) credentials with hmac-secret.
6.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=False.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contain an   "extensions" field.
    {"hmac-secret": True.}

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.without include the extension feild.

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response no "extensions" field inside authenticatorData.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is Successfull.
 """,
"hmaccase25":"""Test started: P-26 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator supports  discoverable (rk=True) credentials with hmac-secret.
6.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=True.Include the following in the extensions field:
"hmac-secret": True. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contain an   "extensions" field.
    {"hmac-secret": True.}

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.without include the extension feild.

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response no "extensions" field inside authenticatorData.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
 """,
"hmaccase26":"""Test started: F-7 :
F-1 Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg "hmac-secret" set to a random type, wait for the response, and check that Authenticator returns an error 
""",
"hmaccase27":"""Test started: F-8 :
F-2 Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret" extension request with one salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error
""",
"hmaccase28":"""Test started: F-9 :
F-3 Send a CTAP2 getAssertion(0x02) message, with "extensions" containg a "hmac-secret" extension request with two salts, with second salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error 
""",
"hmaccase29":"""Test started: F-10 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include the following in the extensions field:
"hmac-secret": true and option  rk is true .Verify the authenticator  response.
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true

Step 2: Retrieve HMAC Secret Using Two Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.saltEnc containing:salt1 = 32 bytes (valid random value)
3.Valid saltAuth
4.without include the protocol.

Expected Result for protocol 1 :
The authenticator returns an error CTAP2_ERR_PIN_AUTH_INVALID.

Expected Result for protocol 2 :
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.
""",
"hmaccase30":"""Test started: F-11 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk is true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using one Salts

Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing:salt1 = 32 bytes (valid random value)
	3.Valid saltAuth
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Options:
"up": false.The authenticator return an Error

Expected Result:
The authenticator returns an CTAP2_ERR_UNSUPPORTED_OPTION.""",

"hmaccase31":"""Test started: F-12 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN.

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using one Salts

Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include "extensions" containing a valid "hmac-secret" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing:
	salt1 = 32 bytes (valid random value)
	3.Invalid saltAuth
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
During processing, the authenticator performs:verify(sharedSecret, saltEnc, saltAuth) Since saltAuth is invalid, the verification step fails.

Expected Result:
1.The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",
"hmaccase32":"""Test started: F-13 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using one Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include "extensions" containing a valid "hmac-secret" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing invalid length (decrypts to length ≠ 32).
	
	3.valid saltAuth 
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected Result:
The authenticator returns the error CTAP2_ERR_PIN_AUTH_INVALID.""",
"hmaccase33":"""Test started: F-14 :

Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request and option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using one Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include "extensions" containing a valid "hmac-secret" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing:
		salt1 = 32 bytes (valid random value)
	3.Invalid saltAuth length is less. (e.g., wrong length: 16 bytes for protocol 2, 32 bytes for protocol 1).
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
During Processing:The authenticator attempts to verify saltAuth.Verification fails because saltAuth length is invalid.

Expected Result:
The authenticator returns the error CTAP1_ERR_INVALID_LENGTH.""",
"hmaccase34":"""Test started: F-15 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request and option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using one Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include "extensions" containing a valid "hmac-secret" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing:
		salt1 = 32 bytes (valid random value)
	3.Invalid saltAuth length is grater. (e.g., wrong length: 16 bytes for protocol 2, 32 bytes for protocol 1).
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
During Processing:The authenticator attempts to verify saltAuth.Verification fails because saltAuth length is invalid.

Expected Result:
The authenticator returns the CTAP1_ERR_INVALID_LENGTH.""",

"hmaccase35":"""Test started: F-16 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request and option rk=true.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using one Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include "extensions" containing a valid "hmac-secret" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc invalid length:		
	3.valid saltAuth 
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Expected Result:
The authenticator returns the CTAP1_ERR_INVALID_LENGTH.""",

"hmaccase36":"""Test started: F-17 :
"Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes ""hmac-secret"" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field:
""hmac-secret"": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an ""extensions"" field.
3.The ""extensions"" field includes:""hmac-secret"": true
Step 2: Retrieve HMAC Secret Using one Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include ""extensions"" containing a valid ""hmac-secret"" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing:
		salt1 = 32 bytes (valid random value) 
	3.Do not include saltAuth
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
missing saltAuth 

Expected Result:
The authenticator returns the error CTAP2_ERR_MISSING_PARAMETER.""",
"hmaccase37":"""Test started: F-18 :
"Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes ""hmac-secret"" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN

Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field:
""hmac-secret"": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an ""extensions"" field.
3.The ""extensions"" field includes:""hmac-secret"": true
Step 2: Retrieve HMAC Secret Using one Salts
Send another valid CTAP2 authenticatorGetAssertion (0x02) request including pinUvAuthParam.Include ""extensions"" containing a valid ""hmac-secret"" request with:
Extensions:
	1.Valid keyAgreement
	2.saltEnc containing only salt2 (32 bytes); saltenc is absent.
	3.valid saltAuth
	4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Expected Result:
The authenticator returns the  CTAP2_ERR_MISSING_PARAMETER.""",

"hmaccase38":"""Test started: F-19 :
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.


Test Description:
Step 1:(Create Credential with hmac-secret Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request option rk True.Include the following in the extensions field:
"hmac-secret": true. 
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:"hmac-secret": true
Step 2: Retrieve HMAC Secret Using Two Salts

Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1. keyAgreement absent.
2.saltEnc containing:
	salt1 = absent 
	salt2 = 32 bytes (valid random value)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).

Expected Result:
1. The authenticator returns an CTAP2_ERR_MISSING_PARAMETER.""",
"hmaccase39":"""Test started: F-20 :
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
"hmaccase40":"""Test started: F-21 :
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
    if mode in ("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12"):
        util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Precondition : CTAP2.2 authenticatorMakeCredential (0x01) using hmac-secret extension Protocol-{protocol}****")
    else:
        util.printcolor(util.YELLOW, f"**** Precondition based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with hmac-secret extension Protocol-{protocol} ****")


    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo", "00")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Authenticator","00")
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
            if mode in ("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12"):
                util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Implementation: CTAP2.2 authenticatorMakeCredential (0x01) using hmac-secret extension Protocol-{protocol} ****")
            else:
                util.printcolor(util.YELLOW, f"**** Implementation based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with hmac-secret extension For Protocol-{protocol} ****")
            if mode =="getinfocase5":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
            else:
                    if mode in("newtestcase","newtestcasetwosalt","onesaltuserverfication","twosaltuserverfication","tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","hmaccase7","hmaccase9","hmaccase11","hmaccase14","hmaccase15","hmaccase16","hmaccase18","hmaccase20","hmaccase21","hmaccase24","hmaccase25","hmaccase26","hmaccase27","hmaccase28","hmaccase29","hmaccase30","hmaccase31","hmaccase32","hmaccase33","hmaccase34","hmaccase35","hmaccase36","hmaccase37","hmaccase38","hmaccase40"):
                        if mode =="hmaccase40":
                            response=U2fprocess(mode,protocol,pin)
                            return response
                        
                        if mode in ("tooltest4","tooltest5","tooltest6","tooltest10","tooltest11","tooltest12","hmaccase9","hmaccase14","hmaccase16","hmaccase20","hmaccase24"):
                            option  = {"rk": False}
                        else:
                            option  = {"rk": True}
                        
                        if mode in("hmaccase20","hmaccase21"):
                            extension = {"hmac-secret": False}
                        elif mode in ("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6"):
                            credprotect=0x01
                            extension = {"credProtect": credprotect,"hmac-secret": True}

                        elif mode in ("hmaccase26","tooltest7","tooltest10"):
                            extension = {"hmac-secret": os.urandom(32)}

                        else:
                            extension = {"hmac-secret": True}
                        
                        subcommand=0x05
                        clientDataHash=os.urandom(32)
                        if protocol ==1:
                            pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16] 
                        else:
                            pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                        # ========================================================
                        # STEP 1 — Makecredential 
                        # ========================================================
                        username="sasmita1"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                        if mode in ("hmaccase26","tooltest7","tooltest10"):
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                            return response
                        else:
                            response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_SUCESS")
                        print("mode",mode)
                        
                        



                        print(response)
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId1: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        if mode in("tooltest1","tooltest4"):
                            return extension
                        
                        if mode in ("newtestcase","newtestcasetwosalt"):
                            util.ResetCardPower()
                            util.ConnectJavaCard() 
                            subcommand=0x05
                            clientDataHash=os.urandom(32)
                            if protocol ==1:
                                pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16] 
                            else:
                                pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                            # ========================================================
                            # STEP 1 — Makecredential 
                            # ========================================================
                            username="sasmita2"
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                            if mode in ("hmaccase26","tooltest7","tooltest10"):
                                response1, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                                return response1
                            else:
                                response1, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_SUCESS")
                        
                            print(response1)
                            credId,credentialPublicKey=authParasing(response1)
                            util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                            util.printcolor(util.YELLOW, f"credId2: {credId}")

                        # ========================================================
                        # STEP 2 — GetAssertion (One Salt) OR(TWO SALT)
                        # ========================================================
                        if mode in ("tooltest2","tooltest3","tooltest5","tooltest6") :
                            util.printcolor(util.YELLOW, "without UV")
                            pinAuthToken="null"

                        else:
                            util.printcolor(util.YELLOW, "with UV")        
                            clientDataHash, pinAuthToken=prepare_session(mode, pin, protocol)
                        subCommand=0x02
                        if mode in ("hmaccase11","tooltest3","tooltest6","twosaltuserverfication","hmaccase14","hmaccase15","hmaccase16","hmaccase18","newtestcasetwosalt"):
                            salt1 = os.urandom(32)
                            salt2 = os.urandom(32)
                            combinedSalt=salt1+salt2
                        elif mode in ("hmaccase27","tooltest8","tooltest11"):
                            salt1 = os.urandom(16)
                            combinedSalt=salt1
                        elif mode in ("hmaccase28","tooltest9","tooltest12"):
                            salt1 = os.urandom(32)
                            salt2 = os.urandom(16)
                            combinedSalt=salt1+salt2

                        else:
                            salt1 = os.urandom(32)
                            combinedSalt=salt1
                        if protocol ==1:
                            key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
                            if mode =="hmaccase32":
                                saltEnc=os.urandom(32)
                            elif mode =="hmaccase35":
                                saltEnc=os.urandom(10)
                            else:   
                                saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinedSalt)
                            #salt auth
                            if mode =="hmaccase31":
                                saltAuth=os.urandom(16)
                            elif mode =="hmaccase33":
                                saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:10]
                            elif mode =="hmaccase34":
                                saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:32]

                            else:
                                saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]    
                        else:
                            key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                            if mode =="hmaccase32":
                            
                                saltEnc=os.urandom(48)
                            elif mode =="hmaccase35":
                                saltEnc=os.urandom(10)
                            else:
                                saltEnc = aes256_cbc_encrypt(shareSecretKey , combinedSalt)
                            #saltauth
                            if mode =="hmaccase31":
                                saltAuth=os.urandom(32)
                            
                            elif mode =="hmaccase33":
                                saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
                            elif mode =="hmaccase34":
                                saltAuth =os.urandom(48)
                            else:

                                saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
                        if mode =="hmaccase29":
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0x03:saltAuth
                            }
                        elif mode =="hmaccase36":
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x03:saltAuth,
                            0x04:protocol
                            }
                        elif mode =="hmaccase37":
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x03:saltAuth,
                            0x04:protocol
                            }
                        elif mode =="hmaccase38":
                            hmac_secret_ext = {
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0x04:protocol
                            }
                        else:
                            hmac_secret_ext = {
                                0x01: key_agreement,
                                0x02:saltEnc,
                                0x03:saltAuth,
                                0x04:protocol}

                        

                        extensions = {"hmac-secret": hmac_secret_ext}
                        apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)
                        
                        
                        
                        if protocol ==1:
                            if mode in ("hmaccase27","hmaccase33","hmaccase34","hmaccase35","tooltest8","tooltest11"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH" )
                                return response
                            elif mode in ("hmaccase28","hmaccase31","tooltest9","tooltest12"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID" )
                                return response
                            elif mode =="hmaccase30":
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="2B",expected_error_name="CTAP2_ERR_UNSUPPORTED_OPTION" )
                                return response
                            elif mode in ("hmaccase36","hmaccase37","hmaccase38"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER" )
                                return response
                            
                            else:
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS" )
                        else:
                            if mode in ("hmaccase27","hmaccase28","hmaccase29","hmaccase31","tooltest8","tooltest9","tooltest11","tooltest12"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID" )
                                return response
                            elif mode =="hmaccase30":
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="2B",expected_error_name="CTAP2_ERR_UNSUPPORTED_OPTION" )
                                return response
                            elif mode in ("hmaccase33","hmaccase34","hmaccase35"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH" )
                                return response
                            elif mode in ("hmaccase36","hmaccase37","hmaccase38"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER" )
                                return response

                            else:
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS" )
                                
                                #response, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                                
                        extension=getextension(response)
                        
                        if mode in ("hmaccase24","hmaccase25"):
                            return u2fauthenticate(mode,rp, clientDataHash, credId)
                            
                        encrypted_output = extension["hmac-secret"]
                        if protocol ==1:
                            decrypted = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
                            if mode in ("twosaltuserverfication","tooltest3","tooltest6","hmaccase11","hmaccase14","hmaccase15","hmaccase16","hmaccase18","newtestcasetwosalt"):
                                assert len(encrypted_output) == 64
                                assert len(decrypted) == 64
                            else:
                                assert len(encrypted_output) == 32
                                assert len(decrypted) == 32
                        else:
                            decrypted = aes256_cbc_decrypt(shareSecretKey, encrypted_output)
                            if mode in ("twosaltuserverfication","tooltest3","tooltest6","hmaccase11","hmaccase14","hmaccase15","hmaccase16","hmaccase18","newtestcasetwosalt"):
                                assert len(encrypted_output) == 80
                                assert len(decrypted) == 64
                            else:
                                assert len(encrypted_output) == 48
                                assert len(decrypted) == 32
                        util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
                        util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted)}, "f"UvSalt1Hmac = {decrypted.hex()}")
                        

                        if mode in ("newtestcase","newtestcasetwosalt"):
                            response,status=util.run_apdu("80100000010800", "authenticatorGetNextAssertion (0x08)", "00")
                            extension=getextension(response)
                            UvSalt1Hmac=decrypted
                            response=verificationforsalt(mode,protocol,extension,shareSecretKey,UvSalt1Hmac)
                            return response
                            
                        
                        if mode in ("tooltest2","tooltest3","tooltest5","tooltest6","onesaltuserverfication","twosaltuserverfication"):
                            response=getasserationprocess(mode,decrypted,combinedSalt,pin,protocol,credId)
                            return response
                        if mode in ("hmaccase15","hmaccase16","hmaccase18"):
                            clientDataHash, pinAuthToken=prepare_session(mode, pin, protocol)
                            saltverification(mode,protocol,combinedSalt,credId,clientDataHash, pinAuthToken)
                        apdu=credentialpresetornot(credId,rp, clientDataHash,protocol,pin)
                        response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                        decode=parse_get_creds_metadata(response)
                        u2fauthenticate(mode,rp, clientDataHash, credId)
        else:
            util.printcolor(util.YELLOW, f"**** Withoutpin authenticatorMakeCredential (0x01) Extension Credblob CTAP2.2 For Protocol, {protocol}")
            if mode =="getinfocase6":
                response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                getinforesponse(response)

            else:
                if mode in("hmaccase8","hmaccase10","hmaccase12","hmaccase13","hmaccase17","hmaccase19","hmaccase22","hmaccase23","hmaccase39"):
                        if mode=="hmaccase39":
                            
                            response=U2fprocess(mode,protocol,pin)
                            return response
                        if mode in("hmaccase10","hmaccase13","hmaccase17","hmaccase23"):
                            option  = {"rk": False}
                        else:
                            option  = {"rk": True}
                        if mode in("hmaccase22","hmaccase23"):
                            extension = {"hmac-secret": False}
                        else:
                            extension = {"hmac-secret": True}
                        # ========================================================
                        # STEP 1 — Makecredential 
                        # ========================================================
                        pinAuthToken="null"
                        clientDataHash=os.urandom(32)
                        username="bobsmith"
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP2_SUCESS")
                        print(response)
                        credId,credentialPublicKey=authParasing(response)
                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                        util.printcolor(util.YELLOW, f"Extensions: {extensions}")
                        # ========================================================
                        # STEP 2 — GetAssertion (One Salt) OR(TWO SALT)
                        # ========================================================
            
                        
                        subCommand=0x02
                        if mode in("hmaccase12","hmaccase13","hmaccase17","hmaccase19"):
                            salt1 = os.urandom(32)
                            salt2 = os.urandom(32)
                            combinedSalt=salt1+salt2
                        else:
                            salt1 = os.urandom(32)
                            combinedSalt=salt1
                        if protocol ==1:
                            key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
                            saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinedSalt)
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
                        else:
                            key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                            saltEnc = aes256_cbc_encrypt(shareSecretKey , combinedSalt)
                            saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]

                        hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0x04:protocol}

                        
                        extensions = {"hmac-secret": hmac_secret_ext}
                        apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)
                        response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS" )
                        extension=getextension(response)
                        encrypted_output = extension["hmac-secret"]
                        

                        if protocol ==1:
                            decrypted = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
                            if mode in ("hmaccase12","hmaccase13","hmaccase17","hmaccase19"):
                                assert len(encrypted_output) == 64
                                assert len(decrypted) == 64
                            else:
                                assert len(encrypted_output) == 32
                                assert len(decrypted) == 32
                        else:
                            decrypted = aes256_cbc_decrypt(shareSecretKey, encrypted_output)
                            if mode in ("hmaccase12","hmaccase13","hmaccase17","hmaccase19"):
                                assert len(encrypted_output) == 80
                                assert len(decrypted) == 64
                            else:
                                assert len(encrypted_output) == 48
                                assert len(decrypted) == 32
                        util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
                        util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted)}, "f"UvSalt1Hmac = {decrypted.hex()}")
                        if mode in ("hmaccase17","hmaccase19"):
                            saltverification(mode,protocol,combinedSalt,credId,clientDataHash, pinAuthToken)
                            
                        u2fauthenticate(mode,rp, clientDataHash, credId)
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


def verificationforsalt(mode,protocol,extension,shareSecretKey,UvSalt1Hmac):
    encrypted_output2 = extension["hmac-secret"]
    if protocol ==1:
        decrypted2 = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output2)
    else:
        decrypted2 = aes256_cbc_decrypt(shareSecretKey, encrypted_output2)
    util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output2)}")
    util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted2)}, "f"UvSalt2Hmac = {decrypted2.hex()}")
    UvSalt2Hmac=decrypted2
    
    if UvSalt1Hmac != UvSalt2Hmac:
        util.printcolor(util.GREEN,"PASS: HMAC1 ≠ HMAC2 – Different credentials produced different HMAC")
    else:
        util.printcolor(util.RED,"FAIL: HMAC1 == HMAC2 – Authenticator returned identical HMAC")

    return extension
def getasserationprocess(mode,previousSalt1Hmac,salt1,pin,protocol,credId):
    if mode in ("tooltest2","tooltest5","onesaltuserverfication","twosaltuserverfication") :
        util.printcolor(util.YELLOW, "without UV")
        pinAuthToken="null"
        clientDataHash=os.urandom(32)

    else:
        util.printcolor(util.YELLOW, "with UV")        
        clientDataHash, pinAuthToken=prepare_session(mode, pin, protocol)
    subCommand=0x02
    if mode in ("tooltest3","tooltest6","onesaltuserverfication","twosaltuserverfication"):
        combinedSalt=salt1
    else:

        salt2 = os.urandom(32)
        combinedSalt=salt1+salt2
    if protocol ==1:
        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinedSalt)
        saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16] 
    else:
        key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
        saltEnc = aes256_cbc_encrypt(shareSecretKey , combinedSalt)
        saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
    hmac_secret_ext = {
                        0x01: key_agreement,
                        0x02:saltEnc,
                        0x03:saltAuth,
                        0x04:protocol}
    extensions = {"hmac-secret": hmac_secret_ext}
    apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS" )
    extension=getextension(response)
    encrypted_output = extension["hmac-secret"]
    if protocol ==1:
        decrypted = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
        if mode in ("tooltest2","tooltest3","tooltest5","tooltest6","twosaltuserverfication"):
            assert len(encrypted_output) == 64
            assert len(decrypted) == 64
        else:
            assert len(encrypted_output) == 32
            assert len(decrypted) == 32
    else:
        decrypted = aes256_cbc_decrypt(shareSecretKey, encrypted_output)
        if mode in ("tooltest2","tooltest3","tooltest5","tooltest6","twosaltuserverfication"):
            assert len(encrypted_output) == 80
            assert len(decrypted) == 64
        else:
            assert len(encrypted_output) == 48
            assert len(decrypted) == 32
    
    if mode in ("onesaltuserverfication","twosaltuserverfication"):
        HMAC2_withoutUV = decrypted
        HMAC1_withUV = previousSalt1Hmac
        util.printcolor(util.BLUE, f"GetAssertion HMAC with UV     : {HMAC1_withUV.hex()}")
        util.printcolor(util.BLUE, f"GetAssertion HMAC without UV  : {HMAC2_withoutUV.hex()}")

        if HMAC1_withUV != HMAC2_withoutUV:
            util.printcolor(
                util.GREEN,
                "PASS: authenticatorGetAssertion returned different HMAC values with UV and without UV as expected."
            )
            return True
        else:
            util.printcolor(
                util.RED,
                "FAIL: authenticatorGetAssertion returned identical HMAC values for requests with and without UV."
            )
            exit(0)
            


    util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
    util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted)}, "f"UvSaltHmac = {decrypted.hex()}")
    salt1Hmac = decrypted[:32]
    salt2Hmac = decrypted[32:64]

    util.printcolor(util.GREEN,
                    f"salt1Hmac = {salt1Hmac.hex()}")
    util.printcolor(util.GREEN,
                    f"salt2Hmac = {salt2Hmac.hex()}")
    # -----------------------------
    # Salt validation (non-UV)
    # -----------------------------
    if mode in ("tooltest2","tooltest5"):

        assert salt1Hmac == previousSalt1Hmac, \
            "FAIL: response does not match previous result"

        util.printcolor(util.GREEN,
                        "PASS: response still equal to previous result")

        assert salt2Hmac != previousSalt1Hmac, \
            "FAIL: nonUvSalt2Hmac should not equal nonUvSalt1Hmac"

        util.printcolor(util.GREEN,
                        "PASS: nonUvSalt2Hmac != nonUvSalt1Hmac")

        
    
    # ------------------------------------------------
    # Salt validation (UV case)
    # ------------------------------------------------
    elif mode in ("tooltest3","tooltest6"):

        uvSalt1Hmac = salt1Hmac
        uvSalt2Hmac = salt2Hmac

        # previous result from non-UV test
        assert len(previousSalt1Hmac) == 64, \
            "FAIL: previousSalt1Hmac must contain salt1+salt2 (64 bytes)"

        nonUvSalt1Hmac = previousSalt1Hmac[:32]
        nonUvSalt2Hmac = previousSalt1Hmac[32:64]

        util.printcolor(util.GREEN, f"uvSalt1Hmac = {uvSalt1Hmac.hex()}")
        util.printcolor(util.GREEN, f"uvSalt2Hmac = {uvSalt2Hmac.hex()}")

        util.printcolor(util.GREEN, f"nonUvSalt1Hmac = {nonUvSalt1Hmac.hex()}")
        util.printcolor(util.GREEN, f"nonUvSalt2Hmac = {nonUvSalt2Hmac.hex()}")

        # P-3 validation
        assert uvSalt1Hmac != nonUvSalt1Hmac, \
            "FAIL: uvSalt1Hmac should not equal nonUvSalt1Hmac"

        assert uvSalt2Hmac != nonUvSalt2Hmac, \
            "FAIL: uvSalt2Hmac should not equal nonUvSalt2Hmac"

        util.printcolor(util.GREEN, "PASS: uvSalt1Hmac != nonUvSalt1Hmac")
        util.printcolor(util.GREEN, "PASS: uvSalt2Hmac != nonUvSalt2Hmac")



    return response
    
    

    




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
    if mode =="hmaccase40":
        response=authenticationwithpin(mode,challenge, rpid,  credId,protocol,pin)
    else:
        response=authentication(mode,challenge, rpid,  credId,protocol)
    return response


def authenticationwithpin(mode,challenge, rpid,  credId,protocol,pin):
    pinAuthToken="null"
    salt1 = os.urandom(32)
    combinedSalt=salt1
    subCommand=0x02
    if protocol ==1:
        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinedSalt)
        saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
    else:
        key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
        saltEnc = aes256_cbc_encrypt(shareSecretKey , combinedSalt)
        saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]

    hmac_secret_ext = {
                        0x01: key_agreement,
                        0x02:saltEnc,
                        0x03:saltAuth,
                        0x04:protocol}

                       
    extension = {"hmac-secret": hmac_secret_ext}
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam---->", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")            
    
    subcommand=0x05
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand,protocol)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)         
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:32]
    mode ="none"
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
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
    return response


def authentication(mode,challenge, rpid,  credId,protocol):
    pinAuthToken="null"
    salt1 = os.urandom(32)
    combinedSalt=salt1
    subCommand=0x02
    if protocol ==1:
        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinedSalt)
        saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
    else:
        key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
        saltEnc = aes256_cbc_encrypt(shareSecretKey , combinedSalt)
        saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]

    hmac_secret_ext = {
                        0x01: key_agreement,
                        0x02:saltEnc,
                        0x03:saltAuth,
                        0x04:protocol}

                       
    extension = {"hmac-secret": hmac_secret_ext}
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")            
    
    util.printcolor(util.YELLOW, f"credId: {credId}")
    if protocol==1:
            pinAuthToken=os.urandom(16)
    else:
            pinAuthToken=os.urandom(32)
    mode ="none"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
         
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredId"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02) without credentialId and without pinAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")
             
    util.printcolor(util.YELLOW, f"credId: {credId}")
    mode="withoutcredandpinauth"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  without credentialId and with pinAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
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


def saltverification(mode,protocol,combinedSalt,credId,clientDataHash, pinAuthToken):
    # ========================================================
    # STEP 2 — GetAssertion (One Salt) OR(TWO SALT)
    # ========================================================
        
    subCommand=0x02               
    if protocol ==1:
        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinedSalt)
        saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
    else:
        key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
        saltEnc = aes256_cbc_encrypt(shareSecretKey , combinedSalt)
        saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]

    hmac_secret_ext = {
                        0x01: key_agreement,
                        0x02:saltEnc,
                        0x03:saltAuth,
                        0x04:protocol}

                       
    extensions = {"hmac-secret": hmac_secret_ext}
    apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion 0x02 using same salt",expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS" )
    extension=getextension(response)
    encrypted_output = extension["hmac-secret"]

    if protocol ==1:
        decrypted = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
        assert len(encrypted_output) == 64
        assert len(decrypted) == 64
        
    else:
        decrypted = aes256_cbc_decrypt(shareSecretKey, encrypted_output)                
        assert len(encrypted_output) == 80
        assert len(decrypted) == 64
                        
    util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
    util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted)}, "f"UvSalt1Hmac = {decrypted.hex()}")
       
                    

def aes256_cbc_decrypt_p1(shared_secret: bytes, encrypted: bytes) -> bytes:
    """
    CTAP2 Protocol 1 hmac-secret decrypt
    - AES-256-CBC
    - IV = 16 zero bytes (NOT included in encrypted)
    - Key = full 32-byte sharedSecret
    """

    assert len(shared_secret) == 32, "sharedSecret must be 32 bytes"
    assert len(encrypted) % 16 == 0, "Encrypted must be multiple of 16"

    iv = b"\x00" * 16  # ZERO IV (important)

    cipher = Cipher(
        algorithms.AES(shared_secret),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes256_cbc_decrypt(shared_secret, encrypted):
    """
    Decrypt CTAP2 hmac-secret output.

    encrypted = iv (16 bytes) || ciphertext
    AES key = last 32 bytes of shared_secret
    No padding is used (plaintext is multiple of 16)
    """

    if len(shared_secret) < 32:
        raise ValueError("sharedSecret must be at least 32 bytes")

    if len(encrypted) < 16:
        raise ValueError("Encrypted data too short")

    # ---- AES key (last 32 bytes) ----
    aes_key = shared_secret[-32:]

    # ---- Extract IV and ciphertext ----
    iv = encrypted[:16]
    ciphertext = encrypted[16:]

    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext not multiple of AES block size")

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    ).decryptor()

    plaintext = cipher.update(ciphertext) + cipher.finalize()

    return plaintext
                    
    

def getextension(response, expect_credblob=False, expect_hmac=False):
    """
    expect_credblob:
        True  -> credBlob must be returned
        False -> credBlob must NOT be returned

    expect_hmac:
        True  -> hmac-secret must be returned
        False -> hmac-secret must NOT be returned
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

        return

    # -------------------------------------------------
    # Case 2: Extensions map exists but empty
    # -------------------------------------------------
    if isinstance(extensions, dict) and len(extensions) == 0:
        util.printcolor(util.YELLOW, "Extensions map present but empty")

        if expect_credblob:
            util.printcolor(util.RED, "Expected credBlob but extensions empty!")

        if expect_hmac:
            util.printcolor(util.RED, "Expected hmac-secret but extensions empty!")

        return

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
        #util.printcolor(util.YELLOW, "credBlob: NOT PRESENT")
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
    else:
        util.printcolor(util.YELLOW, "hmac-secret: NOT PRESENT")
        if expect_hmac:
            util.printcolor(util.RED, "Expected hmac-secret but not returned!")
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

def print_extensions_hex(extensions):
    print("  Extensions:")
    for key, value in extensions.items():
        if isinstance(value, bytes):
            print(f"    {key}: {value.hex()}")
        else:
            print(f"    {key}: {value}")
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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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



def hmac_sha25611(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def aes256_cbc_encrypt1(shared_secret, data):
    """
    AES-256-CBC for CTAP2 PIN/UV Protocol 1
    Supports 1 salt (32B) or 2 salts (64B)
    """

    assert len(shared_secret) == 32, "sharedSecret must be 32 bytes"
    assert len(data) in (32, 64), "hmac-secret requires 32 or 64 bytes"

    iv = b"\x00" * 16  # Protocol 1 requires zero IV

    cipher = Cipher(
        algorithms.AES(shared_secret),
        modes.CBC(iv)
    ).encryptor()

    return cipher.update(data) + cipher.finalize()

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
    if pinAuthToken =="null":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "09"+ cbor_protocol 

    elif mode =="withoutExtension":
        dataCBOR = "A7"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        
        dataCBOR = dataCBOR + "07" + cbor_option
        dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
        dataCBOR = dataCBOR + "09"+ cbor_protocol
    elif mode =="performresetcommand":
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
def createCBORmakeAssertion(mode,cryptohash, rp,  credId,extensions,pinAuthToken,protocol):
    allow_list = [{
         "id": bytes.fromhex(credId),
        "type": "public-key"
       
    }]


    
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_extensions     = cbor2.dumps(extensions).hex().upper()      # 0x04: extensions
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    cbor_protocol       = cbor2.dumps(protocol).hex().upper()        # 0x07: pinProtocol = 2
    

    if pinAuthToken =="null":
        
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "07" + cbor_protocol
    elif mode in ("hmaccase24","hmaccase25"):
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol

    elif mode =="credidnull":
        option= {"up":False}
        cbor_option       = cbor2.dumps(option).hex().upper() 
        dataCBOR = "A4"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + cbor_protocol
    elif mode =="hmaccase30":
        option= {"up":False}
        cbor_option       = cbor2.dumps(option).hex().upper() 
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option
        dataCBOR += "07" + cbor_protocol


    elif mode =="credid":
        dataCBOR = "A4"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        
        dataCBOR += "07" + cbor_protocol
    elif mode =="withoutcredId":
        dataCBOR = "A4"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_extensions 
       
        dataCBOR += "07" + cbor_protocol
    elif mode =="withoutcredandpinauth":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol
    elif mode in ("newtestcase","newtestcasetwosalt"):
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        #dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol

    

    

    else:
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "06" + cbor_pinAuthToken
        dataCBOR += "07" + cbor_protocol

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    
    # Final payload = 01 prefix + dataCBOR
    full_data = "02" + dataCBOR
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
    if mode in ("hmaccase9","hmaccase10","hmaccase13","hmaccase14","hmaccase16","hmaccase17","hmaccase20","hmaccase23","hmaccase24"):
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