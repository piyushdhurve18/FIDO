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
COMMAND_NAME = "AUTHENTICATOR MC(EXTENSION - HMAC SECRET MC)"
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

        "tooltest1":"""Test started: P-1:(rk =False):
        Test started: P-1 :For authenticator with makeCredUvNotRqd:true, 
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message without UV, with salt1 and salt2 in "hmac-secret-mc".
                        Send a valid CTAP2 GetAssertion(0x02) message with UV, with salt1 and salt2 in "hmac-secret".
                        Check that hmac secrets from non-UV request are different from UV request.""",
         "tooltest2":"""Test started: P-2(rk =False):
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with "hmac-secret-mc" with salt1.
                        Send a valid CTAP2 GetAssertion(0x02) message, with extensions that contain a valid "hmac-secret" extension request with salt1.
                        Check that returned hmac secret equals to the hamc secret from MakeCredential.""",
        "tooltest3":"""Test started: P-3(rk =False):
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with "hmac-secret-mc" with salt1 and salt2.
                        Send a valid CTAP2 GetAssertion(0x02) message, with extensions that contain a valid "hmac-secret" extension request with salt1 and salt2.
                        Check that returned hmac secrets are equal to the hamc secrets from MakeCredential.""",
        "tooltest4":"""Test started: P-4 (rk =True):              
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with "hmac-secret-mc" with salt1.
                        Send a valid CTAP2 GetAssertion(0x02) message, with extensions that contain a valid "hmac-secret" extension request with salt1.                        
                        Check that returned hmac secret equals to the hamc secret from MakeCredential.""",
        "tooltest5":"""Test started: P-5 (rk =True):  
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with "hmac-secret-mc" with salt1 and salt2.
                        Send a valid CTAP2 GetAssertion(0x02) message, with extensions that contain a valid "hmac-secret" extension request with salt1 and salt2.                        
                        Check that returned hmac secrets are equal to the hamc secrets from MakeCredential.""",
         "tooltest6":"""Test started: F-1(rk =True and clientpin set and without pinauthparam):
                        For authenticator with makeCredUvNotRqd:true,                         
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message without UV, with salt1 and salt2 in "hmac-secret-mc".
                        Authenticator return CTAP2_ERR_PUAT_REQUIRED.""",
         "tooltest7":"""Test started: F-2 (rk=false):               
                        Send a CTAP2 authenticatorMakeCredential(0x01) message, without necessary "hmac-secret" in extensions                        
                        Check that Authenticator returns CTAP2_ERR_MISSING_PARAMETER(0x14) error code.""",
         "tooltest8":"""Test started: F-3 (rk=false):                                      
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containing "hmac-secret-mc" set to a random types,
                        wait for the response, and check that Authenticator returns an error.""",
         "tooltest9":"""Test started: F-4 (rk=false):
                        Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret-mc" extension request with one salt that is shorter than 32 bytes,
                        wait for the response, and check that authenticator returns an error.""",
         "tooltest10":"""Test started: F-5 (rk=false):             
                        Send a CTAP2 getAssertion(0x02) message, with "extensions" containing a "hmac-secret-mc" extension request with two salts, with second salt that is shorter than 32 bytes, 
                        wait for the response, and check that authenticator returns an error.""",
         "tooltest11":"""Test started: F-6 (rk=True):
                        Send a CTAP2 authenticatorMakeCredential(0x01) message, without necessary "hmac-secret" in extensions
                        Check that Authenticator returns CTAP2_ERR_MISSING_PARAMETER(0x14) error code.""",
         "tooltest12":"""Test started: F-7 (rk=True):
                        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containing "hmac-secret-mc" set to a random types, 
                        wait for the response, and check that Authenticator returns an error.""",
         "tooltest13":"""Test started: F-8 (rk=True):
                        Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret-mc" extension request with one salt that is shorter than 32 bytes, 
                        wait for the response, and check that authenticator returns an error.""",
         "tooltest14":"""Test started: F-9 (rk=True):
                        Send a CTAP2 getAssertion(0x02) message, with "extensions" containing a "hmac-secret-mc" extension request with two salts, with second salt that is shorter than 32 bytes, 
                        wait for the response, and check that authenticator returns an error.""",
                



        "getinfo":"""Test started: P-6:
        Preconditions:
1.The authenticator supports CTAP2.
2.The authenticator is reset.

Test Description:
Verify that the authenticator advertises support for the hmac-secret and hmac-secret-mc extension.
Steps:
Send a valid authenticatorGetInfo (0x04) request.The authenticator returns CTAP2_SUCCESS.
Expected Result:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains  hmac-secret and hmac-secret-mc in the extensions list.
3.The response includes the hmac-secret-mc and and hmac-secret field, and its value matches the default .""",

"hmac_secret_mccase2":"""Test started: P-7:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret and hmac-secret-mc extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The extensions field contains:
{
  "hmac-secret": true,
  "hmac-secret-mc": "<encrypted_value>"
}

4.The extension output corresponds to the encrypted HMAC output derived from salt1.
5.The extension output structure matches the hmac-secret getAssertion output format.
6.The decrypted extension output is 48 bytes.
7.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret-mc" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.



Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.

4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication error.""",


"hmac_secret_mccase3":"""Test started: P-8:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret-mc" and hmac-secret in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret-mc and hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true)credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The extensions field contains:
{
  "hmac-secret": true,
  "hmac-secret-mc": "<encrypted_value>"
}
4.The returned "hmac-secret-mc" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret-mc" encrypted value length is 64 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt1 matches the result obtained in Step 2. 
10.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).

Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret-mc" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt1 matches the result obtained in Step 2. 
10.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
    """,
"hmac_secret_mccase4":"""Test started: P-9:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret-mc" and hmac-secret in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and and hmac-secret extension.
7.The authenticator supports both nondiscoverable (rk=False) credentials with hmac-secret-mc and hmac-secret.

Test Description:
Step 1:(Create Credential with  hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The extensions field contains:
{
  "hmac-secret": true,
  "hmac-secret-mc": "<encrypted_value>"
}

4.The extension output corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted extension output is 48 bytes.
6.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret-mc Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

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
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP1_ERR_SUCCESS (0x01).   
  """,  

"hmac_secret_mccase5":"""Test started: P-10:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret-mc " and hmac-secret in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret-mc  and and hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and and hmac-secret extension.
7.The authenticator supports both nondiscoverable (rk=False)credentials with hmac-secret-mc and and hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The extensions field contains:
{   "hmac-secret": true,
    "hmac-secret-mc": "<encrypted_value>"
    }
3.The returned "hmac-secret-mc" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret-mc" encrypted value length is 64 bytes. 
4.The decrypted extension output is 48 bytes.
5.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Ensure:User presence(up is true) and PIN verification are completed if required.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3.The extensions field contains:
4. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes.  
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt1 matches the result obtained in Step 2. 
10.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is CTAP1_ERR_SUCCESS (0x01).
""", 

"hmac_secret_mccase6":"""Test started: P-11:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret-mc" and hmac-secret in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret-mc and hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret-mc and hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
2.The extensions field contains:
{   "hmac-secret": true,
    "hmac-secret-mc": "<encrypted_value>"
    }

4.The decrypted extension output is 48 bytes.
5.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte using step 1 salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.
7.The decrypted output1 from Step 2 matches the output1 obtained in Step 1 (same salt verification).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.

""", 
"hmac_secret_mccase7":"""Test started: P-12:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret-mc"and hmac-secret in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret-mc  and hmac-secret value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both nondiscoverable (rk=False)credentials with hmac-secret-mc and hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The extensions field contains:
{   "hmac-secret": true,
    "hmac-secret-mc": "<encrypted_value>"
    }
3.The returned "hmac-secret-mc" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret-mc" encrypted value length is 64 bytes. 
4.The decrypted extension output is 48 bytes.
5.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 ( 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Ensure:User presence(up is true) and PIN verification are completed if required.


Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes.  
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 48 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is CTAP1_ERR_SUCCESS (0x01).
""", 
"hmac_secret_mccase8":"""Test started: P-13:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes and hmac-secret and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default and hmac-secret and hmac-secret-mc value.
5.The authenticator supports the hmac-secret and hmac-secret-mc extension.
6.The authenticator supports both discoverable (rk=true) credentials with hmac-secret.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The extensions field contains:
{   "hmac-secret": true,
    "hmac-secret-mc": "<encrypted_value>"
    }
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes for protocol 2 and protocol 1 is 32 byte.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) 
Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted extension output is 48 bytes for protocol 2 and protocol 1 is 32 byte.
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is an error.

""",

"hmac_secret_mccase9":"""Test started: P-14:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and  hmac-secret-mc  in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc  value.
5.The authenticator supports the hmac-secret and hmac-secret-mc extension.
6.The authenticator supports both discoverable (rk=true)credentials with hmac-secret and hmac-secret-mc .

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The extensions field contains:
{   "hmac-secret": true,
    "hmac-secret-mc": "<encrypted_value>"}
3.The returned "hmac-secret-mc" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret-mc" encrypted value length is 64 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt1 matches the result obtained in Step 2. 
10.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).

Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (omit only when protocol version = 1).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
3. The "extensions" field includes "hmac-secret". 
4. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes. 
5. After decrypting the returned value using the shared secret: 
6. The decrypted output length is 64 bytes. 
7. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
8. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
9. The HMAC result for salt1 matches the result obtained in Step 2. 
10.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is an error.
    """,
"hmac_secret_mccase10":"""Test started: P-15:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret-mc" and hmac-secret in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret-mc and hmac-secret value.
5.The authenticator supports the hmac-secret-mc and hmac-secret extension.
6.The authenticator supports both nondiscoverable (rk=False) credentials withhmac-secret-mc and hmac-secret.

Test Description:
Step 1:(Create Credential with  hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
3.credprotect=0x01,
4.credblob=32byte,

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
    {1."credBlob": false,
     2."credProtect": 1,
     3.{
            "hmac-secret": true,
            "hmac-secret-mc": "<encrypted_value>"
            }
3.The extension output corresponds to the encrypted HMAC output derived from salt1.
4.The extension output structure matches the hmac-secret getAssertion output format.
5.The decrypted extension output is 48 bytes.
6.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
"extensions" → "hmac-secret" with:
    1.Valid keyAgreement
    2.Properly encrypted saltEnc (32-byte salt1)
    3.Valid saltAuth
    4.pinUvAuthProtocol included if required (optional)
2.credBlob = True
Ensure:User presence(up is true) 

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
    ."credBlob": <empty bytes>
    ."hmac-secret": "<encrypted_value>"

3.The returned value corresponds to the encrypted HMAC output derived from salt1.
4.The decrypted output length is 48 bytes. 
5.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication is CTAP1_ERR_SUCCESS (0x01).   

""",
"hmac_secret_mccase11":"""Test started: P-16:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator supports the hmac-secret-mc and hmac-secret extension.
6.The authenticator supports both nondiscoverable (rk=False)credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
3.credprotect=0x02,
4.credblob=20 byte,

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
    {1."credBlob": false,
     2."credProtect": 2,
     3.{
        "hmac-secret": true,
        "hmac-secret-mc": "<encrypted_value>"
        }
3.The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes. 
4.The decrypted extension output is 48 bytes.
5.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).
5.credBlob = True

Ensure:User presence(up is true)

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
    ."credBlob": <empty bytes>
    ."hmac-secret": "<encrypted_value>"
3. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes.  
4. After decrypting the returned value using the shared secret: 
5. The decrypted output length is 64 bytes. 
6. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
7. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
8. The HMAC result for salt1 matches the result obtained in Step 2. 
9.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is CTAP1_ERR_SUCCESS (0x01).
""",

"hmac_secret_mccase12":"""Test started: P-17:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret and hmac-secret-mc extension.
7.The authenticator supports both nondiscoverable (rk=False) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
3.credprotect=0x03,
4.credblob=10byte,

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
    {1."credBlob": False,
     2."credProtect": 3,
     3.{
        "hmac-secret": true,
        "hmac-secret-mc": "<encrypted_value>"
        }
3.The extension output corresponds to the encrypted HMAC output derived from salt1.
4.The extension output structure matches the hmac-secret getAssertion output format.
5.The decrypted extension output is 48 bytes.
6.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.
Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).
5.credBlob = True
Ensure:User presence(up is true) and pin varification.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
    ."credBlob": <empty bytes>
    ."hmac-secret": "<encrypted_value>"
3. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes.  
4. After decrypting the returned value using the shared secret: 
5. The decrypted output length is 64 bytes. 
6. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
7. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
8. The HMAC result for salt1 matches the result obtained in Step 2. 
9.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is an failed.
""",

"hmac_secret_mccase13":"""Test started: P-18:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret  and hmac-secret-mc extension.
7.The authenticator supports both nondiscoverable (rk=False) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
3.credprotect=0x02,
4.credblob=20byte,

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
    {1."credBlob": False,
     2."credProtect": 2,
     3.{
        "hmac-secret": true,
        "hmac-secret-mc": "<encrypted_value>"
        }
3.The extension output corresponds to the encrypted HMAC output derived from salt1.
4.The extension output structure matches the hmac-secret getAssertion output format.
5.The decrypted extension output is 48 bytes.
6.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.
Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).
5.credBlob = True
Ensure:User presence(up is true) and pin varification.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
    ."credBlob": <empty bytes>
    ."hmac-secret": "<encrypted_value>"
3. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes.  
4. After decrypting the returned value using the shared secret: 
5. The decrypted output length is 64 bytes. 
6. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
7. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
8. The HMAC result for salt1 matches the result obtained in Step 2. 
9.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is an CTAP1_ERR_SUCCESS (0x01).
""",

"hmac_secret_mccase14":"""Test started: P-19:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret and hmac-secret-mc extension.
7.The authenticator supports both nondiscoverable (rk=False) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
3.credprotect=0x01,
4.credblob=32byte,

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
    {1."credBlob": False,
     2."credProtect": 1,
     3.{
        "hmac-secret": true,
        "hmac-secret-mc": "<encrypted_value>"
        }
3.The extension output corresponds to the encrypted HMAC output derived from salt1.
4.The decrypted extension output is 48 bytes.
5.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.
Step 2:( Retrieve HMAC Secret Using Two Salts)
Send another valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc containing salt1 || salt2 (each 32 bytes)
3.Valid saltAuth
4.pinUvAuthProtocol included if required (optional).
5.credBlob = True
Ensure:User presence(up is true) and pin varification.

Expected Result:
1. The authenticator returns CTAP2_SUCCESS (0x00). 
2. The response contains an "extensions" field inside authenticatorData. 
    ."credBlob": <empty bytes>
    ."hmac-secret": "<encrypted_value>"
3. The returned "hmac-secret" encrypted value length is 80 bytes for protocol 2 and protocol1 "hmac-secret" encrypted value length is 64 bytes.  
4. After decrypting the returned value using the shared secret: 
5. The decrypted output length is 64 bytes. 
6. The first 32 bytes correspond to HMAC-SHA-256(CredRandom, salt1). 
7. The next 32 bytes correspond to HMAC-SHA-256(CredRandom, salt2). 
8. The HMAC result for salt1 matches the result obtained in Step 2. 
9.The HMAC result for salt2 (UvSalt2Hmac) does not equal the HMAC result for salt1 (UvSalt1Hmac).
Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication  is an CTAP1_ERR_SUCCESS (0x01).
""",
"hmac_secret_mccase15":"""Test started: P-20:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=false) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"hmac-secret": true,credprotct=02,credblob=20byte, without sending the hmac-secret-mc.

Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{    1."credBlob": False,
     2."credProtect": 2,
     3."hmac-secret": true,
    }

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.Valid saltAuth
4.pinUvAuthProtocol included if required(optional).
5.credblob=true
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP2_SUCCESS (0x00).
2.The response contains an "extensions" field inside authenticatorData.
3.The "extensions" field includes "hmac-secret".
    ."credBlob": <empty bytes>
    ."hmac-secret": "<encrypted_value>"
4.The returned value corresponds to the encrypted HMAC output derived from salt1.
5.The decrypted output length is 48 bytes. 
6.After decrypting the extension output using the shared secret, exactly 32 bytes (output1) are obtained.

Step 3:
Send getCredsMetadata (0x01).
Verify whether an additional credential is present or not.
Step 4:
Send a valid U2F authentication request using the previously recorded credentialId and verify that authentication CTAP_ERR_SUCCESS
.""",




"hmac_secret_mccase16":"""Test started: F-10:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret and hmac-secret-mc extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": false
2."hmac-secret-mc" with valid input:
3.Valid keyAgreement
4.Properly encrypted saltEnc (32-byte salt1)
5.Valid saltAuth.
6.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns CTAP2_ERR_MISSING_PARAMETER .""",
"hmac_secret_mccase17":"""Test started: F-11:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc less( salt1 is not 32 byte)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns  CTAP1_ERR_INVALID_LENGTH.""",

"hmac_secret_mccase18":"""Test started: F-12:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc greater tahn 32 byte( salt1 is not 32 byte)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns  CTAP1_ERR_INVALID_LENGTH.""",
"hmac_secret_mccase19":"""Test started: F-13:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.An invalid saltAuth value (verification intentionally fails)
	.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",
"hmac_secret_mccase20":"""Test started: F-14:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc  and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.An invalid length saltAuth value (protocol1 less than 16 and protocol 2 less than 32)
	.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns  CTAP1_ERR_INVALID_LENGTH.""",
"hmac_secret_mccase21":"""Test started: F-15:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.An invalid length saltAuth value (protocol1 grater than 16 and protocol 2 grater than 32)
	.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns  CTAP1_ERR_INVALID_LENGTH.""",

"hmac_secret_mccase22":"""Test started: F-16:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.inValid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.valid saltAuth 
	.pinUvAuthProtocol included if required(optional)
Expected Result:
The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",

"hmac_secret_mccase23":"""Test started: F-17:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc  and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.valid saltAuth 
	.invalid pinUvAuthProtocol 
Expected Result:
The authenticator returns  CTAP1_ERR_INVALID_PARAMETER.""",

"hmac_secret_mccase24":"""Test started: F-18:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc  value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.absent  keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.valid saltAuth 
	.valid pinUvAuthProtocol 
Expected Result:
The authenticator returns  CTAP2_ERR_MISSING_PARAMETER.""",
"hmac_secret_mccase25":"""Test started: F-19:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and hmac-secret-mc in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.valid keyAgreement
	.saltEnc absent
	.valid saltAuth 
	.valid pinUvAuthProtocol 
Expected Result:
The authenticator returns  CTAP2_ERR_MISSING_PARAMETER.""",
"hmac_secret_mccase26":"""Test started: F-20:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret  and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.valid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.saltAuth omitted (not included) 
	.valid pinUvAuthProtocol 
Expected Result:
The authenticator returns  CTAP2_ERR_MISSING_PARAMETER.""",
"hmac_secret_mccase27":"""Test started: F-21:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret  and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc  and hmac-secret extension.


Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option up=false.Include the following in the extensions field: 
1."hmac-secret": True
2."hmac-secret-mc" with valid input:
	.valid keyAgreement
	.Properly encrypted saltEnc ( salt1 is 32 byte)
	.vaild saltAuth omitted 
	.valid pinUvAuthProtocol 
and option up=false
Expected Result:
The authenticator returns  CTAP2_ERR_INVALID_OPTION.""",

"hmac_secret_mccase28":"""Test started: F-22:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret",and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
"hmac-secret" set to a random typ.
Expected Result:
The authenticator returns  CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",
"hmac_secret_mccase29":"""Test started: F-23:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc  and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The extensions field contains:
    {   "hmac-secret": true,
        "hmac-secret-mc": "<encrypted_value>"
    }
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.valid keyAgreement
2.Properly encrypted saltEnc (32-byte salt1)
3.saltAuth(randomly saltauth)
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"hmac_secret_mccase30":"""Test started: F-24:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.saltEnc (not 32-byte salt1 less than 32 byte)
3.Valid saltAuth
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",

"hmac_secret_mccase31":"""Test started: F-25:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret"  and "hmac-secret-mc "in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret  and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.saltEnc ( not 32-byte salt1 is greater than 32 byte)
3.Valid saltAuth 
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",
"hmac_secret_mccase32":"""Test started: F-26:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret"  and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret  extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc ( 32-byte salt1)
3.inValid saltAuth
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.""",

"hmac_secret_mccase33":"""Test started: F-27:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc  and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc ( 32-byte salt1)
3.inValid saltAuth length(protocol less than 16 byte and protocol 2 is less than 32 byte)
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",

"hmac_secret_mccase34":"""Test started: F-28:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret-mc extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc ( 32-byte salt1)
3.inValid saltAuth length(protocol grater than 16 byte and protocol 2 is grater than 32 byte)
4.pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP1_ERR_INVALID_LENGTH.""",
"hmac_secret_mccase35":"""Test started: F-29:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc ( 32-byte salt1)
3.Valid saltAuth 
4.invalid pinUvAuthProtocol included if required(optional).
Ensure:User presence(up is true) and PIN verification are completed if required.

Expected output:
1.The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",
"hmac_secret_mccase36":"""Test started: F-30:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and :hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.Valid keyAgreement
2.Properly encrypted saltEnc ( 32-byte salt1)
3.Valid saltAuth 
4.valid pinUvAuthProtocol included if required(optional).
Ensure:(up is false) 

Expected output:
1.The authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION.""",
"hmac_secret_mccase37":"""Test started: F-31:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.keyAgreement absent.
2.Properly encrypted saltEnc ( 32-byte salt1)
3.Valid saltAuth 
4.valid pinUvAuthProtocol included if required(optional).
Ensure:User presence(up =true) 

Expected output:
1.The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",
"hmac_secret_mccase38":"""Test started: F-32:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc  and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.valid keyAgreement .
2.saltEnc absent.
3.Valid saltAuth 
4.valid pinUvAuthProtocol included if required(optional).
Ensure:User presence(up =true) 

Expected output:
1.The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",
"hmac_secret_mccase39":"""Test started: F-33:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret" and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and hmac-secret-mc value.
5.The authenticator is configured with a PIN
6.The authenticator supports the hmac-secret-mc and hmac-secret extension.
7.The authenticator supports both discoverable (rk=true) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=true.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
Expected Result:
1.The authenticator returns CTAP1_ERR_SUCCESS (0x00).
2.The authenticatorMakeCredential response contains an "extensions" field.
3.The "extensions" field includes:
{   "hmac-secret": true
    "hmac-secret-mc": "<encrypted_value>"
}
4.The authenticator processes hmac-secret-mc as defined for hmac-secret getAssertion behavior.
5.The extension output corresponds to the encrypted HMAC output derived from salt1.
6.The extension output structure matches the hmac-secret getAssertion output format.
7.The decrypted extension output is 48 bytes.
8.After decrypting using the shared secret, exactly 32 bytes (output1) are obtained.

Step 2: (Retrieve HMAC Secret Using One Salt)
Send a valid CTAP2 authenticatorGetAssertion (0x02) request.Include "extensions" containing a valid "hmac-secret" request with:
1.valid keyAgreement .
2.Properly encrypted saltEnc (32-byte salt1).
3.saltAuth absent.
4.valid pinUvAuthProtocol included if required(optional).
Ensure:User presence(up =true) 

Expected output:
1.The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",





"hmac_secret_mccase40":"""Test started: F-34:
Preconditions:
1.The authenticator supports CTAP2
2.The authenticator is reset
3.The authenticatorGetInfo response includes "hmac-secret",and "hmac-secret-mc" in the extensions list..
4.The authenticatorGetInfo response reports the default hmac-secret and and hmac-secret-mc value.
5.The authenticator supports the hmac-secret and hmac-secret-mc and hmac-secret-mc extension.
6.The authenticator supports both nondiscoverable (rk=False) credentials with hmac-secret and hmac-secret-mc.

Test Description:
Step 1:(Create Credential with hmac-secret and hmac-secret-mc Enabled)
Send a valid CTAP2 authenticatorMakeCredential (0x01) request with option rk=false.Include the following in the extensions field: 
1."hmac-secret": true
2."hmac-secret-mc" with valid input:
	.Valid keyAgreement
	.Properly encrypted saltEnc (32-byte salt1)
	.Valid saltAuth.
	.pinUvAuthProtocol included if required(optional)
3.credprotect=0x03,
4.credblob=10byte,

Expected Result:
1.The authenticator returns CTAP2_ERR_PUAT_REQUIRED.
""",

"u2fregistationwithauthentication":"""Test started: F-35:

Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator supports U2F (CTAP1) protocol
3.The authenticator is reset. (Dont have PIN set)
4.The authenticator supports the hmac-secret-mc extension.


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
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS.
""",

"u2fregistation":"""Test started: F-36:

Preconditions:
1.The authenticator supports the authenticatorMakeCredential (0x01).
2.The authenticator supports U2F (CTAP1) protocol
3.The authenticator is reset. (Dont have PIN set)
4.The authenticator supports the hmac-secret-mc extension.
5.The authenticator is configured with a PIN


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
Verify that the authenticator returns error code CTAP2_ERR_NO_CREDENTIALS.""",


    }

    if mode not in descriptions:
                    raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])
    if mode in ("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14"):
        util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Precondition : CTAP2.2 authenticatorMakeCredential (0x01) using hmac-secret-mc extension Protocol-{protocol}   ****")
    else:
        util.printcolor(util.YELLOW, f"**** Precondition based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with hmac-secret-mc extension Protocol-{protocol} ****")
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
            response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
            PinIsSet = "yes"
        elif protocol ==2:
            clentpinsetp2(pin, protocol, subcommand)
            response,staus=util.run_apdu("80100000010400", "GetInfo", "00")
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
                if mode in("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14"):
                    util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Implementation: CTAP2.2 authenticatorMakeCredential (0x01) using hmac-secret-mc extension Protocol-{protocol} ****")
                else:
                    util.printcolor(util.YELLOW, f"**** Implementation based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with hmac-secret-mc extension For Protocol-{protocol} ****")
                if mode =="getinfo":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                else:
                    if mode in ("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14","hmac_secret_mccase2","hmac_secret_mccase3","hmac_secret_mccase4","hmac_secret_mccase5","hmac_secret_mccase6","hmac_secret_mccase7","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15","hmac_secret_mccase16","hmac_secret_mccase17","hmac_secret_mccase18","hmac_secret_mccase19","hmac_secret_mccase20","hmac_secret_mccase21","hmac_secret_mccase22","hmac_secret_mccase23","hmac_secret_mccase24","hmac_secret_mccase25","hmac_secret_mccase26","hmac_secret_mccase27","hmac_secret_mccase28","hmac_secret_mccase29","hmac_secret_mccase30","hmac_secret_mccase31","hmac_secret_mccase32","hmac_secret_mccase33","hmac_secret_mccase34","hmac_secret_mccase35","hmac_secret_mccase36","hmac_secret_mccase37","hmac_secret_mccase38","hmac_secret_mccase39","u2fregistation"):
                        
                        if mode =="u2fregistation":
                            rpid, challenge, credential_id=u2fregistation(mode,protocol)

                            extension=extensionprepare(protocol)
                            response=authenticationwithpin(mode,rpid, challenge, credential_id,protocol,extension,pin)
                            return response

                        if mode in("tooltest1","tooltest2","tooltest3","tooltest7","tooltest8","tooltest9","tooltest10","hmac_secret_mccase4","hmac_secret_mccase5","hmac_secret_mccase7","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15"):
                            option  = {"rk": False}
                        elif mode =="hmac_secret_mccase27":
                            option  = {
                                    "up": False}
                        else:
                            option  = {"rk": True}
                        subCommand=0x02
                        if mode =="hmac_secret_mccase22":
                            key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                        else:
                            key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)

                        if mode in("tooltest1","tooltest3","tooltest5","tooltest6","hmac_secret_mccase3","hmac_secret_mccase5","hmac_secret_mccase7"):
                            salt1 = os.urandom(32)
                            salt2 = os.urandom(32)
                            combinesaltdata=salt1+salt2 
                        elif mode in ("hmac_secret_mccase17","tooltest9","tooltest13"):
                            salt1 = os.urandom(16)
                            combinesaltdata=salt1
                        elif mode =="hmac_secret_mccase18":
                            salt1 = os.urandom(96)
                            combinesaltdata=salt1
                        elif mode in ("tooltest10","tooltest14"):
                            salt1 = os.urandom(32)
                            salt2 = os.urandom(16)
                            combinesaltdata=salt1+salt2


                        else:
                            salt1 = os.urandom(32)
                            combinesaltdata=salt1 
                        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinesaltdata)
                        if mode =="hmac_secret_mccase19":
                            saltAuth = hmac_sha25611(shareSecretKey, salt1 )[:16]
                        elif mode =="hmac_secret_mccase20":
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:10]
                        elif mode =="hmac_secret_mccase21":
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:32]


                        else:   
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
                        if mode =="hmac_secret_mccase12":
                            credblob=os.urandom(10)
                            credprotect=0x03
                            extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x02:saltEnc,
                                                0x03:saltAuth,
                                                0x04:protocol},
                                        "credBlob": credblob,
                                        "credProtect": credprotect}
                        elif mode =="hmac_secret_mccase13":
                            credblob=os.urandom(20)
                            credprotect=0x02
                            extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x02:saltEnc,
                                                0x03:saltAuth,
                                                0x04:protocol},
                                        "credBlob": credblob,
                                        "credProtect": credprotect}
                        elif mode =="hmac_secret_mccase14":
                            credblob=os.urandom(32)
                            credprotect=0x01
                            extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x02:saltEnc,
                                                0x03:saltAuth,
                                                0x04:protocol},
                                        "credBlob": credblob,
                                        "credProtect": credprotect}
                        elif mode =="hmac_secret_mccase15":
                            credblob=os.urandom(32)
                            credprotect=0x02
                            extension = {"hmac-secret": True,
                                        "credBlob": credblob,
                                        "credProtect": credprotect}
                        elif mode =="hmac_secret_mccase16":
                            extension = {"hmac-secret": False,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                        elif mode =="hmac_secret_mccase23":
                            protocols=0
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocols}}
                        elif mode =="hmac_secret_mccase24":
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                        elif mode =="hmac_secret_mccase25":
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                        elif mode in ("tooltest7","tooltest11"):
                            extension ={"hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                        elif mode in ("tooltest8","tooltest12") :
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: os.urandom(32),
                                            0x02:os.urandom(32),
                                            0x04:os.urandom(4)}}

                        elif mode =="hmac_secret_mccase26":
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x04:protocol}}
                        elif mode =="hmac_secret_mccase28":
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": os.urandom(32)}
                        

                        else:
                            extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                        clientDataHash1=os.urandom(32)
                        if mode in("tooltest1","tooltest6"):
                            util.printcolor(util.YELLOW, "without UV")
                            pinAuthToken="null"

                        else:
                            util.printcolor(util.YELLOW, "with UV")
                            subcommand=0x05
                            pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
                            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash1)[:16]
                        makeCredAPDU=createCBORmakeCred(mode,clientDataHash1, rp, username,  pinAuthToken,protocol,extension,option)
                        if mode in("tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14","hmac_secret_mccase16","hmac_secret_mccase17","hmac_secret_mccase18","hmac_secret_mccase19","hmac_secret_mccase20","hmac_secret_mccase21","hmac_secret_mccase22","hmac_secret_mccase23","hmac_secret_mccase24","hmac_secret_mccase25","hmac_secret_mccase26","hmac_secret_mccase27","hmac_secret_mccase28"):
                            if mode =="hmac_secret_mccase16":
                                if isinstance(makeCredAPDU, str):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                                else:   
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                                
                            elif mode in("hmac_secret_mccase17","hmac_secret_mccase20","hmac_secret_mccase18","hmac_secret_mccase21","tooltest9","tooltest13"):   
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
                            elif mode in ("hmac_secret_mccase19","hmac_secret_mccase22","tooltest10","tooltest14"):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                            elif mode =="hmac_secret_mccase23":
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
                            elif mode in ("hmac_secret_mccase24","hmac_secret_mccase25","hmac_secret_mccase26","tooltest7","tooltest11"):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                            elif mode in ("hmac_secret_mccase27"):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                            elif mode in ("hmac_secret_mccase28","tooltest8","tooltest12"):
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                            elif mode =="tooltest6":
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                        


                            return response    

                        
                        else:

                            if isinstance(makeCredAPDU, str):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                            else:   
                                response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                        print(response)

                        credId, credentialPublicKey = authParasing(response)

                        util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                        util.printcolor(util.YELLOW, f"credId: {credId}")

                        cose_key, extensions = parse_credential_pubkey_and_extensions(credentialPublicKey)

                        extensions_hex = {
                            k: v.hex() if isinstance(v, bytes) else v
                            for k, v in extensions.items()
                        }

                        util.printcolor(util.YELLOW, f"Extensions : {extensions_hex}")
                        if mode =="hmac_secret_mccase15":
                            util.printcolor(util.YELLOW, "without hmac-secret-mc")
                        else:

                        # ✅ Correct variable
                            encrypted_output = extensions["hmac-secret-mc"]

                            # convert hex → bytes
                            if isinstance(encrypted_output, str):
                                encrypted_output = bytes.fromhex(encrypted_output)

                            util.printcolor(util.YELLOW, f"Encrypted length = {len(encrypted_output)}")

                            decrypted_mc = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
                            #withoutUvSalt1Hmac = decrypted

                            util.printcolor(util.GREEN, f"Decrypted MC HMAC = {decrypted_mc.hex()}")
                        # ========================================================
                        # STEP 2 — GetAssertion (One Salt)
                        # ========================================================
                        clientDataHash, pinAuthToken=prepare_session(mode, pin, protocol)
                        subCommand=0x02
                        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
                        if mode in("tooltest1","hmac_secret_mccase3","hmac_secret_mccase5","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14"):
                            salt1 = os.urandom(32)
                            salt2 = os.urandom(32)
                            combinesaltdata=salt1+salt2 
                        elif mode in ("hmac_secret_mccase6","tooltest2","tooltest4"):
                            combinesaltdata=salt1#(verification same salt)
                        elif mode in("tooltest3","tooltest5"):
                            combinesaltdata=salt1+salt2
                        elif mode =="hmac_secret_mccase30":
                            salt1 = os.urandom(16)
                            combinesaltdata=salt1
                        elif mode =="hmac_secret_mccase31":
                            salt1 = os.urandom(48)
                            combinesaltdata=salt1

                        else:
                            salt1 = os.urandom(32)
                            combinesaltdata=salt1

                        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinesaltdata)
                        if mode =="hmac_secret_mccase32":
                            saltAuth = hmac_sha25611(shareSecretKey, salt1)[:16]
                        elif mode =="hmac_secret_mccase33":
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:10]
                        elif mode =="hmac_secret_mccase34":
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:32]

                        else:
                            saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
                        if mode =="hmac_secret_mccase29":
                            saltEnc=os.urandom(16)
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0X04:protocol}
                        elif mode =="hmac_secret_mccase35":
                            protocols=0
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0X04:protocols}

                        elif mode =="hmac_secret_mccase37":
                            hmac_secret_ext = {
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0X04:protocol}
                        elif mode =="hmac_secret_mccase38":
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x03:saltAuth,
                            0X04:protocol}
                        elif mode =="hmac_secret_mccase39":
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0X04:protocol}
                        else:
                            hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0X04:protocol}
                        if mode in("hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15"):
                            extensions = {"hmac-secret": hmac_secret_ext,
                                "credBlob": True
                                }
                        else:
                        
                            extensions = {"hmac-secret": hmac_secret_ext}

                        
                        apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)

                        if mode in ("hmac_secret_mccase29","hmac_secret_mccase30","hmac_secret_mccase31","hmac_secret_mccase32","hmac_secret_mccase33","hmac_secret_mccase34","hmac_secret_mccase35","hmac_secret_mccase36","hmac_secret_mccase37","hmac_secret_mccase38","hmac_secret_mccase39"):
                            if mode in ("hmac_secret_mccase31","hmac_secret_mccase32"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                            elif mode in("hmac_secret_mccase30","hmac_secret_mccase33","hmac_secret_mccase29","hmac_secret_mccase34"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
                            elif mode =="hmac_secret_mccase35":
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
                            elif mode =="hmac_secret_mccase36":
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2B",expected_error_name="CTAP2_ERR_UNSUPPORTED_OPTION")
                            elif mode in ("hmac_secret_mccase37","hmac_secret_mccase38","hmac_secret_mccase39"):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                        
                                
                                
                            
                            return response
                        else:
                            if isinstance(apdu, str):
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                            else:
                                response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                        print(response)
                        extension=getextension(response)
                        encrypted_output = extension["hmac-secret"]
                        
                        decrypted = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
                        if mode in ("tooltest1","tooltest3","tooltest5","hmac_secret_mccase3","hmac_secret_mccase5","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14"):
                            assert len(encrypted_output) == 64
                            assert len(decrypted) == 64
                        else:
                            assert len(encrypted_output) == 32
                            assert len(decrypted) == 32
                        util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
                        UvSalt1Hmac = decrypted
                        util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted)}, "f"UvSalt1Hmac = {UvSalt1Hmac.hex()}")
                        if mode in("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5"):
                            util.printcolor(util.YELLOW, f"MC SaltHmac = {decrypted_mc.hex()}")
                            util.printcolor(util.YELLOW, f"GA SaltHmac = {UvSalt1Hmac.hex()}")
                            if mode in ("tooltest1"):
                                # P-1: values must be different
                                withoutUvSalt1Hmac_mc=decrypted_mc
                                if withoutUvSalt1Hmac_mc == UvSalt1Hmac:
                                    util.printcolor(util.RED, "FAIL: HMAC secrets from non-UV and UV requests are equal")
                                    exit(0)

                                util.printcolor(util.GREEN,
                                    "PASS: HMAC secrets from non-UV request are different from UV request")

                            elif mode in("tooltest2","tooltest4"):
                                # P-2: values must be equal
                                Salt1Hmac_mc=decrypted_mc
                                if  Salt1Hmac_mc!= UvSalt1Hmac:
                                    util.printcolor(util.RED,
                                        "FAIL: HMAC secret from GetAssertion does not match MakeCredential")
                                    exit(0)

                                util.printcolor(util.GREEN,
                                    "PASS: HMAC secret from GetAssertion equals the HMAC secret from MakeCredential")
                            elif mode in ("tooltest3","tooltest5"):
                                # P-3: verify both salt1 and salt2 HMAC values

                                if len(decrypted_mc) != 64:
                                    util.printcolor(util.RED,
                                        f"FAIL: MakeCredential HMAC length expected 64 but got {len(decrypted_mc)}")
                                    exit(0)

                                if len(UvSalt1Hmac) != 64:
                                    util.printcolor(util.RED,
                                        f"FAIL: GetAssertion HMAC length expected 64 but got {len(UvSalt1Hmac)}")
                                    exit(0)

                                # Split MakeCredential HMAC
                                Salt1Hmac_mc = decrypted_mc[:32]
                                Salt2Hmac_mc = decrypted_mc[32:]

                                # Split GetAssertion HMAC
                                Salt1Hmac_ga = UvSalt1Hmac[:32]
                                Salt2Hmac_ga = UvSalt1Hmac[32:]

                                util.printcolor(util.YELLOW, f"MC Salt1Hmac = {Salt1Hmac_mc.hex()}")
                                util.printcolor(util.YELLOW, f"MC Salt2Hmac = {Salt2Hmac_mc.hex()}")

                                util.printcolor(util.YELLOW, f"GA Salt1Hmac = {Salt1Hmac_ga.hex()}")
                                util.printcolor(util.YELLOW, f"GA Salt2Hmac = {Salt2Hmac_ga.hex()}")

                                if Salt1Hmac_mc != Salt1Hmac_ga:
                                    util.printcolor(util.RED,
                                        "FAIL: salt1 HMAC from GetAssertion does not match MakeCredential")
                                    exit(0)

                                if Salt2Hmac_mc != Salt2Hmac_ga:
                                    util.printcolor(util.RED,
                                        "FAIL: salt2 HMAC from GetAssertion does not match MakeCredential")
                                    exit(0)

                                util.printcolor(util.GREEN,
                                    "PASS: salt1 and salt2 HMAC values match those from MakeCredential")

                        else:

                            apdu=credentialpresetornot(credId,rp, clientDataHash,protocol,pin)
                            response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                            decode=parse_get_creds_metadata(response)
                            u2fauthenticate(mode,rp, clientDataHash, credId)
                        


                        
                    
                        

                                
            else:

                if mode in("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14"):
                    util.printcolor(util.YELLOW, f"**** FIDO Conformance Test Implementation : CTAP2.2 authenticatorMakeCredential (0x01) using hmac-secret-mc extension Protocol-{protocol} ****")
                else:
                    util.printcolor(util.YELLOW, f"**** Implementation based on CTAP2.2 standard: authenticatorMakeCredential (0x01) with hmac-secret-mc extension For Protocol-{protocol} ****")
                if mode =="getinfo":
                    response,status=util.run_apdu("80100000010400", "GetInfo", "00")
                    getinforesponse(response)
                else:
                        if mode in ("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5","tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14","hmac_secret_mccase2","hmac_secret_mccase3","hmac_secret_mccase4","hmac_secret_mccase5","hmac_secret_mccase6","hmac_secret_mccase7","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15","hmac_secret_mccase16","hmac_secret_mccase17","hmac_secret_mccase18","hmac_secret_mccase19","hmac_secret_mccase20","hmac_secret_mccase21","hmac_secret_mccase22","hmac_secret_mccase23","hmac_secret_mccase24","hmac_secret_mccase25","hmac_secret_mccase26","hmac_secret_mccase27","hmac_secret_mccase28","hmac_secret_mccase29","hmac_secret_mccase30","hmac_secret_mccase31","hmac_secret_mccase32","hmac_secret_mccase33","hmac_secret_mccase34","hmac_secret_mccase35","hmac_secret_mccase36","hmac_secret_mccase37","hmac_secret_mccase38","hmac_secret_mccase39","u2fregistation"):
                            if mode =="u2fregistation":
                                rpid, challenge, credential_id=u2fregistation(mode,protocol)

                                extension=extensionprepare(protocol)
                                response=authenticationwithpin(mode,rpid, challenge, credential_id,protocol,extension,pin)
                                return response
                            if mode in("tooltest1","tooltest2","tooltest3","tooltest7","tooltest8","tooltest9","tooltest10","hmac_secret_mccase4","hmac_secret_mccase5","hmac_secret_mccase7","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15"):
                                option  = {"rk": False}
                            elif mode =="hmac_secret_mccase27":
                                option  = {"up": False}

                            else:
                                option  = {"rk": True}
                            subCommand=0x02
                            key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                            if mode in("tooltest1","tooltest3","tooltest5","tooltest6","hmac_secret_mccase3","hmac_secret_mccase5","hmac_secret_mccase7"):
                                salt1 = os.urandom(32)
                                salt2 = os.urandom(32)
                                combinesaltdata=salt1+salt2 
                            elif mode in ("hmac_secret_mccase17","tooltest9","tooltest13"):
                                salt1 = os.urandom(16)
                                combinesaltdata=salt1
                            elif mode =="hmac_secret_mccase18":
                                salt1 = os.urandom(48)
                                combinesaltdata=salt1
                            elif mode in ("tooltest10","tooltest14"):
                                salt1 = os.urandom(32)
                                salt2 = os.urandom(16)
                                combinesaltdata=salt1+salt2 

                            
                            else:
                                salt1 = os.urandom(32)
                                combinesaltdata=salt1

                            
                            saltEnc = aes256_cbc_encrypt(shareSecretKey , combinesaltdata)
                            if mode in("hmac_secret_mccase19","hmac_secret_mccase20","hmac_secret_mccase21"):
                                if mode =="hmac_secret_mccase19":
                                    saltAuth = hmac_sha256(shareSecretKey, salt1)[:32]
                                elif mode =="hmac_secret_mccase20":
                                    saltAuth =hmac_sha256(shareSecretKey, saltEnc)[:10]
                                elif mode =="hmac_secret_mccase21":
                                    saltAuth =os.urandom(40)
                                    
                            else:
                                saltAuth =hmac_sha256(shareSecretKey, saltEnc)[:32]

                                
                            

                            if mode =="hmac_secret_mccase12":
                                credblob=os.urandom(10)
                                credprotect=0x03
                                extension = {"hmac-secret": True,
                                                "hmac-secret-mc": {
                                                    0x01: key_agreement,
                                                    0x02:saltEnc,
                                                    0x03:saltAuth,
                                                    0x04:protocol},
                                            "credBlob": credblob,
                                            "credProtect": credprotect}
                            elif mode =="hmac_secret_mccase13":
                                credblob=os.urandom(20)
                                credprotect=0x02
                                extension = {"hmac-secret": True,
                                                "hmac-secret-mc": {
                                                    0x01: key_agreement,
                                                    0x02:saltEnc,
                                                    0x03:saltAuth,
                                                    0x04:protocol},
                                            "credBlob": credblob,
                                            "credProtect": credprotect}
                            elif mode =="hmac_secret_mccase14":
                                credblob=os.urandom(32)
                                credprotect=0x01
                                extension = {"hmac-secret": True,
                                                "hmac-secret-mc": {
                                                    0x01: key_agreement,
                                                    0x02:saltEnc,
                                                    0x03:saltAuth,
                                                    0x04:protocol},
                                            "credBlob": credblob,
                                            "credProtect": credprotect}
                            elif mode =="hmac_secret_mccase15":
                                credblob=os.urandom(32)
                                credprotect=0x02
                                extension = {"hmac-secret": True,
                                            "credBlob": credblob,
                                            "credProtect": credprotect}
                            elif mode =="hmac_secret_mccase16":
                                extension = {"hmac-secret": False,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                            elif mode =="hmac_secret_mccase22":
                                saltAuth =os.urandom(32)
                                extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}  
                            elif mode =="hmac_secret_mccase23":
                                protocols=0
                                extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x02:saltEnc,
                                                0x03:saltAuth,
                                                0x04:protocols}}
                            elif mode =="hmac_secret_mccase24":
                                extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                            elif mode =="hmac_secret_mccase25":
                                extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x03:saltAuth,
                                                0x04:protocol}}
                            elif mode =="hmac_secret_mccase26":
                                extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x02:saltEnc,
                                                0x04:protocol}}
                            elif mode =="hmac_secret_mccase28":
                                extension = {"hmac-secret": True,
                                            "hmac-secret-mc": os.urandom(32)}
                            elif mode in ("tooltest7","tooltest11"):
                                extension ={"hmac-secret-mc": {
                                                0x01: key_agreement,
                                                0x03:saltAuth,
                                                0x04:protocol}}
                            elif mode in ("tooltest8","tooltest12"):
                                extension = {"hmac-secret": True,
                                            "hmac-secret-mc": {
                                            0x01: os.urandom(32),
                                            0x02:os.urandom(16),
                                            0x04:os.urandom(4)}}
                            else:
                                
                                extension = {"hmac-secret": True,
                                        "hmac-secret-mc": {
                                            0x01: key_agreement,
                                            0x02:saltEnc,
                                            0x03:saltAuth,
                                            0x04:protocol}}
                            clientDataHash1=os.urandom(32)
                            if mode in("tooltest1","tooltest6"):
                                util.printcolor(util.YELLOW, "without UV")
                                pinAuthToken="null"

                            else:
                                util.printcolor(util.YELLOW, "with UV")
                                subcommand=0x05
                                pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
                                
                                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash1)
                            makeCredAPDU=createCBORmakeCred(mode,clientDataHash1, rp, username,  pinAuthToken,protocol,extension,option)
                            if mode in("tooltest6","tooltest7","tooltest8","tooltest9","tooltest10","tooltest11","tooltest12","tooltest13","tooltest14","hmac_secret_mccase16","hmac_secret_mccase17","hmac_secret_mccase18","hmac_secret_mccase19","hmac_secret_mccase20","hmac_secret_mccase21","hmac_secret_mccase22","hmac_secret_mccase23","hmac_secret_mccase24","hmac_secret_mccase25","hmac_secret_mccase26","hmac_secret_mccase27","hmac_secret_mccase28"):
                                if mode =="hmac_secret_mccase16":
                                    if isinstance(makeCredAPDU, str):
                                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                                    else:   
                                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                                elif mode in("hmac_secret_mccase20","hmac_secret_mccase21"):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
                                elif mode in("hmac_secret_mccase19","hmac_secret_mccase17","hmac_secret_mccase18","hmac_secret_mccase22","tooltest9","tooltest10","tooltest13","tooltest14"):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                                elif mode =="hmac_secret_mccase23":
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
                                elif mode in ("hmac_secret_mccase24","hmac_secret_mccase25","hmac_secret_mccase26","tooltest7","tooltest11"):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                                elif mode =="hmac_secret_mccase27":
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="2C",expected_error_name="CTAP2_ERR_INVALID_OPTION")
                                elif mode in ("hmac_secret_mccase28","tooltest8","tooltest12"):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="11",expected_error_name="CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
                                elif mode =="tooltest6":
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                            



                                return response
                            else:
                                if isinstance(makeCredAPDU, str):
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                                else:   
                                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                            print(response)
                            credId,credentialPublicKey=authParasing(response)
                            util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                            util.printcolor(util.YELLOW, f"credId: {credId}")
                            cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                            extensions_hex = {
                                k: v.hex() if isinstance(v, bytes) else v
                                for k, v in extensions.items()
                            }
                            util.printcolor(util.YELLOW, f"Extensions : {extensions_hex}")
                            if mode =="hmac_secret_mccase15":
                                util.printcolor(util.YELLOW, "without hmac-secret-mc")
                            else:
                                # ✅ Correct variable
                                encrypted_output = extensions["hmac-secret-mc"]

                                # convert hex → bytes
                                if isinstance(encrypted_output, str):
                                    encrypted_output = bytes.fromhex(encrypted_output)

                                util.printcolor(util.YELLOW, f"Encrypted length = {len(encrypted_output)}")
                                decrypted_mc = aes256_cbc_decrypt(shareSecretKey, encrypted_output)
                                
                                #withoutUvSalt1Hmac = decrypted

                                util.printcolor(util.GREEN, f"Decrypted MC HMAC = { decrypted_mc.hex()}")
                            
                            # ========================================================
                            # STEP 2 — GetAssertion (One Salt and two salt)
                            # ========================================================
                            clientDataHash, pinAuthToken=prepare_session(mode, pin, protocol)
                            subCommand=0x02
                            key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                            if mode in("tooltest1","hmac_secret_mccase3","hmac_secret_mccase5","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14"):
                                salt1 = os.urandom(32)
                                salt2 = os.urandom(32)
                                combinesaltdata=salt1+salt2 
                            elif mode in ("hmac_secret_mccase6","tooltest2","tooltest4"):
                                combinesaltdata=salt1#(verification same salt)
                            elif mode in("tooltest3","tooltest5"):
                                combinesaltdata=salt1+salt2
                            elif mode =="hmac_secret_mccase30":
                                salt1 = os.urandom(16)
                                combinesaltdata=salt1
                            elif mode =="hmac_secret_mccase31":
                                salt1 = os.urandom(48)
                                combinesaltdata=salt1
                            else:
                                salt1 = os.urandom(32)
                                combinesaltdata=salt1
                            saltEnc = aes256_cbc_encrypt(shareSecretKey , combinesaltdata)

                            if mode =="hmac_secret_mccase32":
                                saltAuth = hmac_sha256(shareSecretKey, salt1)[:32]
                            elif mode =="hmac_secret_mccase33":
                                saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:16]
                            elif mode =="hmac_secret_mccase34":
                                saltAuth = os.urandom(38)
                            else:
                                saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
                            if mode =="hmac_secret_mccase29":
                                saltAuth=os.urandom(32)
                                hmac_secret_ext = {
                                    0x01: key_agreement,
                                    0x02:saltEnc,
                                    0x03:saltAuth,
                                    0X04 :protocol}
                            elif mode =="hmac_secret_mccase35":
                                protocols=0
                                hmac_secret_ext = {
                                    0x01: key_agreement,
                                    0x02:saltEnc,
                                    0x03:saltAuth,
                                    0X04 :protocols}
                            elif mode =="hmac_secret_mccase37":
                                hmac_secret_ext = {
                                    0x02:saltEnc,
                                    0x03:saltAuth,
                                    0X04 :protocol}
                            elif mode =="hmac_secret_mccase38":
                                hmac_secret_ext = {
                                0x01: key_agreement,
                                0x03:saltAuth,
                                0X04:protocol}
                            elif mode =="hmac_secret_mccase39":
                                hmac_secret_ext = {
                                0x01: key_agreement,
                                0x02:saltEnc,
                                0X04:protocol}
                            else:
                                hmac_secret_ext = {
                                0x01: key_agreement,
                                0x02:saltEnc,
                                0x03:saltAuth,
                                0X04 :protocol}
                            if mode in("hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15"):
                                extensions = {"hmac-secret": hmac_secret_ext,
                                    "credBlob": True
                                    }
                            else:
                                extensions = {"hmac-secret": hmac_secret_ext}

                            
                            apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)
                            if mode in ("hmac_secret_mccase29","hmac_secret_mccase30","hmac_secret_mccase31","hmac_secret_mccase32","hmac_secret_mccase33","hmac_secret_mccase34","hmac_secret_mccase35","hmac_secret_mccase36","hmac_secret_mccase37","hmac_secret_mccase38","hmac_secret_mccase39"):
                                if mode in("hmac_secret_mccase29","hmac_secret_mccase30","hmac_secret_mccase31","hmac_secret_mccase32","hmac_secret_mccase32"):
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="33",expected_error_name="CTAP2_ERR_PIN_AUTH_INVALID")
                                elif mode in("hmac_secret_mccase33","hmac_secret_mccase34"):
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="03",expected_error_name="CTAP1_ERR_INVALID_LENGTH")
                                elif mode =="hmac_secret_mccase35":
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="02",expected_error_name="CTAP1_ERR_INVALID_PARAMETER")
                                elif mode =="hmac_secret_mccase36":
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="2B",expected_error_name="CTAP2_ERR_UNSUPPORTED_OPTION")
                                elif mode in ("hmac_secret_mccase37","hmac_secret_mccase38","hmac_secret_mccase39"):
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="14",expected_error_name="CTAP2_ERR_MISSING_PARAMETER")
                        

                                return response
                            else:
                                if isinstance(apdu, str):
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                                else:
                                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                            print(response)
                            extension=getextension(response)
                            encrypted_output = extension["hmac-secret"]
                            decrypted = aes256_cbc_decrypt(shareSecretKey, encrypted_output)
                            if mode in("tooltest1","tooltest3","tooltest5","hmac_secret_mccase3","hmac_secret_mccase5","hmac_secret_mccase12","hmac_secret_mccase13","hmac_secret_mccase14"):
                                assert len(encrypted_output) == 80
                                assert len(decrypted) == 64
                            else:

                                assert len(encrypted_output) == 48
                                assert len(decrypted) == 32
                            util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
                            UvSalt1Hmac = decrypted
                            util.printcolor(
                                util.GREEN,
                                f"PASS: One-salt decrypted length = {len(decrypted)}, "
                                f"UvSalt1Hmac = {UvSalt1Hmac.hex()}")
                            if mode in("tooltest1","tooltest2","tooltest3","tooltest4","tooltest5"):
                                util.printcolor(util.YELLOW, f"MC SaltHmac = {decrypted_mc.hex()}")
                                util.printcolor(util.YELLOW, f"GA SaltHmac = {UvSalt1Hmac.hex()}")
                                if mode in ("tooltest1"):
                                    # P-1: values must be different
                                    withoutUvSalt1Hmac = decrypted_mc
                                    if withoutUvSalt1Hmac == UvSalt1Hmac:
                                        util.printcolor(util.RED, "FAIL: HMAC secrets from non-UV and UV requests are equal")
                                        exit(0)

                                    util.printcolor(util.GREEN,"PASS: HMAC secrets from non-UV request are different from UV request")

                                elif mode in ( "tooltest2","tooltest4"):
                                    # P-2: values must be equal
                                    Salt1Hmac_mc = decrypted_mc
                                    if Salt1Hmac_mc != UvSalt1Hmac:
                                        util.printcolor(util.RED,
                                            "FAIL: HMAC secret from GetAssertion does not match MakeCredential")
                                        exit(0)

                                    util.printcolor(util.GREEN,"PASS: HMAC secret from GetAssertion equals the HMAC secret from MakeCredential")
                                elif mode in("tooltest3","tooltest5"):
                                    # P-3: verify both salt1 and salt2 HMAC values

                                    if len(decrypted_mc) != 64:
                                        util.printcolor(util.RED,
                                            f"FAIL: MakeCredential HMAC length expected 64 but got {len(decrypted_mc)}")
                                        exit(0)

                                    if len(UvSalt1Hmac) != 64:
                                        util.printcolor(util.RED,
                                            f"FAIL: GetAssertion HMAC length expected 64 but got {len(UvSalt1Hmac)}")
                                        exit(0)

                                    # Split MakeCredential HMAC
                                    Salt1Hmac_mc = decrypted_mc[:32]
                                    Salt2Hmac_mc = decrypted_mc[32:]

                                    # Split GetAssertion HMAC
                                    Salt1Hmac_ga = UvSalt1Hmac[:32]
                                    Salt2Hmac_ga = UvSalt1Hmac[32:]

                                    util.printcolor(util.YELLOW, f"MC Salt1Hmac = {Salt1Hmac_mc.hex()}")
                                    util.printcolor(util.YELLOW, f"MC Salt2Hmac = {Salt2Hmac_mc.hex()}")

                                    util.printcolor(util.YELLOW, f"GA Salt1Hmac = {Salt1Hmac_ga.hex()}")
                                    util.printcolor(util.YELLOW, f"GA Salt2Hmac = {Salt2Hmac_ga.hex()}")

                                    if Salt1Hmac_mc != Salt1Hmac_ga:
                                        util.printcolor(util.RED,
                                            "FAIL: salt1 HMAC from GetAssertion does not match MakeCredential")
                                        exit(0)

                                    if Salt2Hmac_mc != Salt2Hmac_ga:
                                        util.printcolor(util.RED,
                                            "FAIL: salt2 HMAC from GetAssertion does not match MakeCredential")
                                        exit(0)

                                    util.printcolor(util.GREEN,
                                        "PASS: salt1 and salt2 HMAC values match those from MakeCredential")
                            
                            else:
                                apdu=credentialpresetornot(credId,rp, clientDataHash,protocol,pin)
                                response, status = util.run_apdu(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)",expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
                                decode=parse_get_creds_metadata(response)
                                u2fauthenticate(mode,rp, clientDataHash, credId)
        else:
            util.printcolor(util.YELLOW, f"****  WithoutClientpin Extension Credblob CTAP2.2 For Protocol- {protocol}")
            if mode in("hmac_secret_mccase8","hmac_secret_mccase9","hmac_secret_mccase10","hmac_secret_mccase11","hmac_secret_mccase40","u2fregistationwithauthentication"):
                if mode =="u2fregistationwithauthentication":
                    rpid, challenge, credential_id=u2fregistation(mode,protocol) 
                    extension=extensionprepare(protocol)
                    response=authentication(mode,rpid, challenge, credential_id,protocol,extension)
                    return response


                if mode in ("hmac_secret_mccase10","hmac_secret_mccase11","hmac_secret_mccase40"):
                    option  = {"rk": False}
                else:
                    option  = {"rk": True}
                subCommand=0x02
                if protocol ==1:
                    key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
                    if mode in("hmac_secret_mccase9","hmac_secret_mccase11"):
                        salt1 = os.urandom(32)
                        salt2 = os.urandom(32)
                        combinesaltdata=salt1+salt2
                    else:

                        salt1 = os.urandom(32)
                        combinesaltdata=salt1
                    saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinesaltdata)
                    saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
                else:
                    key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                    if mode in("hmac_secret_mccase9","hmac_secret_mccase11"):
                        salt1 = os.urandom(32)
                        salt2 = os.urandom(32)
                        combinesaltdata=salt1+salt2
                    else:

                        salt1 = os.urandom(32)
                        combinesaltdata=salt1
                    saltEnc = aes256_cbc_encrypt(shareSecretKey , combinesaltdata)
                    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
                if mode =="hmac_secret_mccase10":
                    credblob=os.urandom(32)
                    credprotect=0x01
                    extension = {"hmac-secret": True,
                                    "hmac-secret-mc": {
                                        0x01: key_agreement,
                                        0x02:saltEnc,
                                        0x03:saltAuth,
                                        0x04:protocol},
                                "credBlob": credblob,
                                "credProtect": credprotect}
                elif mode =="hmac_secret_mccase11":
                    credblob=os.urandom(20)
                    credprotect=0x02
                    extension = {"hmac-secret": True,
                                    "hmac-secret-mc": {
                                        0x01: key_agreement,
                                        0x02:saltEnc,
                                        0x03:saltAuth,
                                        0x04:protocol},
                                "credBlob": credblob,
                                "credProtect": credprotect}
                elif mode =="hmac_secret_mccase40":
                    credblob=os.urandom(10)
                    credprotect=0x03
                    extension = {"hmac-secret": True,
                                    "hmac-secret-mc": {
                                        0x01: key_agreement,
                                        0x02:saltEnc,
                                        0x03:saltAuth,
                                        0x04:protocol},
                                "credBlob": credblob,
                                "credProtect": credprotect}
                                        
                else:

                    extension = {"hmac-secret": True,
                                    "hmac-secret-mc": {
                                        0x01: key_agreement,
                                        0x02:saltEnc,
                                        0x03:saltAuth,
                                        0x04:protocol}}
                pinAuthToken="null"
                clientDataHash=os.urandom(32)

                makeCredAPDU=createCBORmakeCred(mode,clientDataHash, rp, username,  pinAuthToken,protocol,extension,option)
                if mode =="hmac_secret_mccase40":
                    response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="36",expected_error_name="CTAP2_ERR_PUAT_REQUIRED")
                    return response
                else:

                    if isinstance(makeCredAPDU, str):
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                    else:   
                        response, status = util.run_apdu(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                print(response)
                credId,credentialPublicKey=authParasing(response)
                util.printcolor(util.YELLOW, f"credentialPublicKey: {credentialPublicKey}")
                util.printcolor(util.YELLOW, f"credId: {credId}")
                cose_key, extensions=parse_credential_pubkey_and_extensions(credentialPublicKey)
                extensions_hex = {k: v.hex() if isinstance(v, bytes) else v
                                for k, v in extensions.items()
                            }
                util.printcolor(util.YELLOW, f"Extensions : {extensions_hex}")
                # ========================================================
                # STEP 2 — GetAssertion (One Salt and two salt)
                # ========================================================
                subCommand=0x02
                if protocol ==1:
                    key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
                    if mode in("hmac_secret_mccase9","hmac_secret_mccase11","hmac_secret_mccase12"):
                        salt1 = os.urandom(32)
                        salt2 = os.urandom(32)
                        combinesaltdata=salt1+salt2
                    else:

                        salt1 = os.urandom(32)
                        combinesaltdata=salt1
                    saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinesaltdata)
                    saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
                else:
                    key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
                    if mode in("hmac_secret_mccase9","hmac_secret_mccase11","hmac_secret_mccase12"):
                        salt1 = os.urandom(32)
                        salt2 = os.urandom(32)
                        combinesaltdata=salt1+salt2
                    else:

                        salt1 = os.urandom(32)
                        combinesaltdata=salt1
                    saltEnc = aes256_cbc_encrypt(shareSecretKey , combinesaltdata)
                    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
            
                hmac_secret_ext = {
                                0x01: key_agreement,
                                0x02:saltEnc,
                                0x03:saltAuth,
                                0x04:protocol}
                if mode in("hmac_secret_mccase10","hmac_secret_mccase11","hmac_secret_mccase12"):
                    extensions = {"hmac-secret": hmac_secret_ext,
                                "credBlob": True
                                }
                else:
                    extensions = {"hmac-secret": hmac_secret_ext}        
                apdu = createCBORmakeAssertion(mode,clientDataHash, rp,  credId,extensions,pinAuthToken,protocol)
                if isinstance(apdu, str):
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02",expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS" )
                else:
                    response, status = util.run_apdu(apdu, "GetAssertion 0x02", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
                print(response)
                extension=getextension(response)
                encrypted_output = extension["hmac-secret"]
                if protocol ==1:
                    decrypted = aes256_cbc_decrypt_p1(shareSecretKey, encrypted_output)
                    if mode in ("hmac_secret_mccase9","hmac_secret_mccase11","hmac_secret_mccase12"):
                        assert len(encrypted_output) == 64
                        assert len(decrypted) == 64
                    else:
                        assert len(encrypted_output) == 32
                        assert len(decrypted) == 32
                else:
                    decrypted = aes256_cbc_decrypt(shareSecretKey, encrypted_output)
                    if mode in ("hmac_secret_mccase9","hmac_secret_mccase11","hmac_secret_mccase12"):
                        assert len(encrypted_output) == 80
                        assert len(decrypted) == 64
                    else:
                        assert len(encrypted_output) == 48
                        assert len(decrypted) == 32
                util.printcolor(util.GREEN, f"PASS: One-salt encrypted output length ={len(encrypted_output)}")
                util.printcolor(util.GREEN,f"PASS: One-salt decrypted length = {len(decrypted)}, "f"UvSalt1Hmac = {decrypted.hex()}")
                u2fauthenticate(mode,rp, clientDataHash, credId)
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

def extensionprepare(protocol):
    salt1 = os.urandom(32)
    combinesaltdata=salt1
    subCommand=0x02
    if protocol ==1:
        key_agreement, shareSecretKey =getKeyAgreementp1(protocol,subCommand)
        saltEnc = aes256_cbc_encryptp11(shareSecretKey, combinesaltdata)
        saltAuth = hmac_sha25611(shareSecretKey, saltEnc)[:16]
    else:
        key_agreement, shareSecretKey =getKeyAgreement(protocol,subCommand)
        saltEnc = aes256_cbc_encrypt(shareSecretKey , combinesaltdata)
        saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
        
    hmac_secret_ext = {
                            0x01: key_agreement,
                            0x02:saltEnc,
                            0x03:saltAuth,
                            0x04:protocol}
        
    extension = {"hmac-secret": hmac_secret_ext}  
    return extension       
def authentication(mode,rpid, challenge, credential_id,protocol,extension):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    credId= credential_id.hex()
    util.printcolor(util.YELLOW, f"credId: {credId}")
    pinAuthToken="null"
    
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP1_ERR_SUCCESS")
    util.printcolor(util.YELLOW, f"credId: {credId}")
    if protocol==1:
        pinAuthToken=os.urandom(16)
    else:
        pinAuthToken=os.urandom(32)
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID with pinUvAuthParam", expected_prefix="35",expected_error_name="CTAP2_ERR_PIN_NOT_SET")
    mode ="credidnull"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request without credentialID without pinUvAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")

    return response

def authenticationwithpin(mode,rpid, challenge, credential_id,protocol,extension,pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    credId= credential_id.hex()
    util.printcolor(util.YELLOW, f"credId: {credId}")
    subcommand=0x05
    
    pinAuthToken="null"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID without pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP_ERR_SUCCESS")
    util.printcolor(util.YELLOW, f"credId: {credId}")
    if protocol ==1:
        pinToken=getPINtokenp1(mode,pin,subcommand,protocol)
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:16]
    else:
        pinToken=getPINtokenp2(mode,pin,subcommand,protocol)
        pinAuthToken = util.hmac_sha256(pinToken, challenge)[:32]
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request with previously recorded credentialID with pinUvAuthParam", expected_prefix="00",expected_error_name="CTAP2_ERR_SUCCESS")
    mode ="credidnull"
    apdu=createCBORmakeAssertion(mode,challenge, rpid,  credId,extension,pinAuthToken,protocol)
    response, status = util.run_apdu(apdu, "GetAssertion (0x02)  request without credentialID without pinUvAuthParam", expected_prefix="2E",expected_error_name="CTAP2_ERR_NO_CREDENTIALS")

    return response

def u2fregistation(mode,protocol):
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
    response, status = util.run_apduu2f(
    apdu,"U2F AUTHENTICATE ",expected_prefix="01",  expected_error_name="CTAP1_ERR_SUCCESS")
    return rpid, challenge, credential_id
    
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


def u2fauthenticate(mode,rp, clientDataHash, credId):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                    #clientDataHash1=os.urandom(32)
    apdu = u2f_authenticate_apdu(rp, clientDataHash, credId)
    print("U2F AUTHENTICATE APDU:", apdu)
                    # 4. Send AUTHENTICATE APDU
    if mode in ("hmac_secret_mccase4","hmac_secret_mccase5","hmac_secret_mccase7","hmac_secret_mccase10","hmac_secret_mccase11","hmac_secret_mccase13","hmac_secret_mccase14","hmac_secret_mccase15"):
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
    if pinAuthToken=="null":
        dataCBOR = "A6"
        dataCBOR = dataCBOR + "01"+ cbor_hash
        dataCBOR = dataCBOR + "02"+ cbor_rp
        dataCBOR = dataCBOR + "03"+ cbor_user
        dataCBOR = dataCBOR + "04"+ credParam
        dataCBOR = dataCBOR + "06"+ cbor_extension
        dataCBOR = dataCBOR + "07" + cbor_option
        #dataCBOR = dataCBOR + "09"+ cbor_protocol 
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
    if pinAuthToken=="null":
        dataCBOR = "A6"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "03" + cbor_allowlist
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
        dataCBOR += "07" + cbor_protocol
    elif mode =="credidnull":
        dataCBOR = "A5"
        dataCBOR += "01" + cbor_rp
        dataCBOR += "02" + cbor_hash
        dataCBOR += "04" + cbor_extensions 
        dataCBOR += "05" + cbor_option 
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
    if byte_len <= 256:
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

def hmac_sha25611(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

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