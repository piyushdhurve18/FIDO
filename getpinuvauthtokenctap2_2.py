
import util
import cbor2
import binascii
import Setpinp22
import os
import credentialManagement
import credBlob
import struct
#import getpintokenCTAP2_2

RP_domain          = "localhost"
user="bobsmith"

def getPinUvAuthTokenP2_2(mode,pin,pinset):
    util.printcolor(util.YELLOW, "**** pinUvAuthToken  protocol 2.2****")
    util.ResetCardPower()
    util.ConnectJavaCard()

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
         "cmPermission": """Test started: P-1 : 
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required parameters.
Include the Credential Management permission (0x04) in the permissions field.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the cm permission.""",     
       
        "acfgPermission": """Test started: P-2 : 
Preconditions:
1.The authenticator supports Authenticator Configuration (authnrCfg) functionality.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Authenticator Configuration permission (0x20) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the authnrCfg permission.""",


        "mcPermission": """Test started: P-3 : 
Preconditions:

1.The authenticator supports the MakeCredential capability.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:

Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the MakeCredential permission (0x01) in the permissions field.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the mc permission.""",

        "gaPermission": """Test started: P-4 : 
Preconditions:
1.The authenticator supports the GetAssertion capability.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the GetAssertion permission (0x02) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the ga permission.""",

       "lbwpermission": """Test started: p-6 : 
Preconditions:
The authenticator supports Large Blob Write functionality.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Large Blob Write permission (0x10) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the lbw permission.""",
        
        "bepermission": """Test started:  : F-1
Preconditions:
1.The authenticator does not support the Bio Enrollment capability.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Bio Enrollment permission (0x08) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the be permission, even though Bio Enrollment is not supported.""",
        
        "getpinToken": """Test started: F-2 : 
Preconditions:
1.The authenticator has a PIN already configured.
2.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request without specifying any permissions, using a valid pinHashEnc and all other required command parameters.
Expected Result:
The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

        "permission.zero": """Test started: F-3 : 
Preconditions:
1.The authenticator has a PIN already configured.
2.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with the permissions field set to zero (0x00), using a valid pinHashEnc and all other required command parameters.

Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

        "verifycmper": """Test started: P-7 : 
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Credential Management permission (0x04) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the cm permission.

Step 3 (Verification):
Use the returned pinUvAuthToken to perform a Credential Management command (0x0A).

Expected Result:
The authenticator returns CTAP2_OK, confirming that the token is valid and usable for Credential Management operations.""",
        
        "verifyacfgper": """Test started: P-7 : 
Preconditions:
1.The authenticator supports Authenticator Configuration.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Authenticator Configuration permission (0x20) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the acfg permission.

Step 3 (Verification):
Optionally, use the returned pinUvAuthToken to perform an Authenticator Configuration operation to verify the token’s validity.

Expected Result:
The authenticator returns CTAP2_OK, confirming the token is valid and can be used for Authenticator Configuration operations. """,       
        "verifymcper": """Test started: P-8 : 
Preconditions:
1.The authenticator supports the MakeCredential capability.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the MakeCredential permission (0x01) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the mc permission.

Step 3 (Verification):
Use the returned pinUvAuthToken to perform a MakeCredential command (0x01).

Expected Result:
The authenticator returns CTAP2_OK, confirming that the token is valid and can be used for MakeCredential operations.""",


"verifygaper": """Test started: P-9 : 
Preconditions:
1.The authenticator supports the GetAssertion capability.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the GetAssertion permission (0x02) in the request.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the ga permission.

Step 3 (Verification):
Use the returned pinUvAuthToken to perform a GetAssertion command (0x02).

Expected Result:
The authenticator returns CTAP2_OK, confirming that the token is valid and can be used for GetAssertion operations.""",

        "withoutpingetpintoken": """Test started: P-10 : 
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator does not have a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Credential Management permission (0x04) in the request.

Expected Result:
Since no PIN is configured on the authenticator, it shall return CTAP2_ERR_PIN_NOT_SET.""",
         
         "InvalidPIN": """Test started: F-4 :
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using all valid command parameters.
Include a permission such as Credential Management (0x04), but provide an incorrect PIN.

Expected Result:
The authenticator shall return CTAP2_ERR_PIN_INVALID.""",



"Invalidkey_agreement": """Test started: F-5 :
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Step 1: Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid PIN hash (pinHashEnc) but with an invalid key_agreement. Ensure all other command parameters are correctly and validly specified. Include a permission such as Credential Management (0x04).
Expected Result: The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",



"Invalidpermission": """Test started: F-6 :
Precondition:
1.The authenticator supports Credential Management = true.
2.The authenticator must  have a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc, the key_agreement, and all other required command parameters.
Specify a permission such as Credential Management (0x04), but replace it with 0x00.

Expected Result:
The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",

        "piuvauthmissing": """Test started: F-8 :
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc, the key_agreement, and all other required command parameters. Include a permission such as Credential Management (0x04), but omit the pinUvAuth parameter.

Expected Result:The authenticator shall return CTAP2_ERR_MISSING_PARAMETER.""",

"keyAgreementmissing": """Test started: F-9 :
Precondition:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Step:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct pinHashEnc, along with the key_agreement and valid command parameters.
Including a permission such as Credential Management (0x04),but keyAgreement parameter  is omitted.

Expected Result:the authenticator SHALL return CTAP2_ERR_MISSING_PARAMETER.""",



"subcommandInvalid": """Test started: F-9 :
Precondition:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Step:
Send an AuthenticatorClientPIN request using a subCommand value other than getPinUvAuthTokenUsingPinWithPermissions (for example, 0x06), while keeping all other parameters (pinHashEnc, keyAgreement, and permissions) correctly specified.
Including a permission such as Credential Management (0x04).
Expected Result:The authenticator retuen CTAP1_ERR_INVALID_PARAMETER.""",


"pinauthblocked": """Test started: F-10 :
Precondition:
1.The authenticator supports Credential Management = true.
2.The authenticator must  have a PIN configured.
3.PIN/UV Protocol 2 is being used.

Test Step:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using an incorrect PIN (for example, the actual PIN is "123456" but "654321" is provided), while including a permission such as Credential Management (0x04).
The authenticator should return CTAP2_ERR_PIN_INVALID for each incorrect attempt, and after multiple consecutive failures (e.g., three attempts),
Expected Result:The authenticator  return CTAP2_ERR_PIN_AUTH_BLOCKED.""",

"pinauthblocked.pin": """Test started: F-11 :
Precondition:
1.The authenticator must already have a PIN configured.                                      
2.The PIN is in a PIN_AUTH_BLOCKED state. .
3.The authenticator supports Credential Management.
4.PIN/UV Protocol 2 is being used.

Test Steps:
With the PIN in a PIN_AUTH_BLOCKED state and without performing a power-cycle reset.
send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct PIN and including a permission such as Credential Management (0x04).

Expected Result:The authenticator shall return CTAP2_ERR_PIN_AUTH_BLOCKED..""",


"pinretry": """Test started: F-12 :
Precondition:
1.The authenticator must already have a PIN configured.                                      
2.The PIN is in a PIN_AUTH_BLOCKED state. .
3.The authenticator supports Credential Management.
4.PIN/UV Protocol 2 is being used.

Test Step:
With the PIN in a PIN_AUTH_BLOCKED state and without performing a power-cycle reset,
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using any PIN value—correct (e.g., 123456) or incorrect—and include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall not decrement the PIN retry counter..""",



"withpowercycle": """Test started: P-11 :
Precondition:
1.The authenticator must already have a PIN configured.                                      
2.The PIN is in a PIN_AUTH_BLOCKED state.
3.The authenticator supports Credential Management.
4.PIN/UV Protocol 2 is being used

Test Step:
After performing a power-cycle reset, send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the correct PIN, the proper pinHashEnc, and all other valid command parameters.
Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP2_OK.""",

"pinblocked": """Test started: P-13 :
Preconditions:
1.The authenticator has a PIN already configured.
2.The PIN retry counter is 0.
3.The authenticator supports Credential Management.
4.PIN/UV Protocol 2 is being used.

Test Steps:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request after the PIN has been blocked due to multiple incorrect attempts, with all required command parameters supplied correctly. Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP2_ERR_PIN_BLOCKED.""",


"pinreset": """Test started: P-14 :
Preconditions:
1.The authenticator supports Credential Management.
2.PIN/UV Protocol 2 is being used.
3.The PIN was previously blocked.

Test Steps:
Step 1: Perform a power-cycle reset of the authenticator and set a new PIN using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the newly set PIN, the proper pinHashEnc, and all other valid command parameters. Include a permission such as Credential Management (0x04).
Expected Result: The authenticator shall return CTAP2_OK.""",


"Invalidkey_sharesecret": """Test started: F-14 :
Preconditions:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Steps:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using an invalid shared secret, ensuring that all other command parameters are correctly and validly specified. Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",



"platformCOSKEY.notmap": """Test started: F-14 :
Precondition:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Step:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request with with platformCOSKEY not being a map (e.g., an array or string). 
Including a permission such as Credential Management (0x04)The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",




"pinHashEnc.notbyte": """Test started: F-15 :
Precondition:
1.The authenticator supports Credential Management.
2.The authenticator has a PIN already configured.
3.PIN/UV Protocol 2 is being used.

Test Step:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request where the platformCOSKEY is provided, but pinHashEnc is not of type bytes (e.g., provided as an integer or string).
Include a permission such as Credential Management (0x04).

Expected Result:
The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",

"forcepinset": """Test started: F-16 :
Precondition:
1.The authenticator supports Authenticator config.
2.The authenticator must  have a PIN configured.
3. PIN/UV Protocol 2 is being used.

Test Steps:

Step 1: Set the forcePINChange field to True.
Expected Result: The authenticator returns CTAP2_OK, but indicates that a PIN change is required.

Step 2: With the forcePINChange field set to true and the user not having changed their PIN, send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the old PIN and all other required parameters correctly. Include a permission such as Credential Management (0x04).
Expected Result: The authenticator shall return CTAP2_ERR_PIN_INVALID.""",

"changepin": """Test started: F-17 :
Precondition:
1.The authenticator supports Authenticator config=true
2.The authenticator must  have a PIN configured.
3. forcePINChange  field is set True.
Test Step:
If forcePINChange is set to true and the user has already changed their PIN, then sending a getPinUvAuthTokenUsingPinWithPermissions (0x09) request—using the currect PIN and all required parameters, 
including a permission such as Authenticator config (0x20). The authenticator returning CTAP2_OK.""",


"changewrongpin": """Test started: F-18 :
Precondition:
1.The authenticator supports Authenticator config.
2.The authenticator must  have a PIN configured.
3. PIN/UV Protocol 2 is being used.
Test Step:
Step 1: Set the forcePINChange field to True.
Expected Result: The authenticator returns CTAP2_OK, indicating that a PIN change is required.

Step 2: After the user has changed their PIN, send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the current PIN and all other required parameters. Include a permission such as Authenticator Configuration (0x20).
Expected Result: The authenticator shall return CTAP2_OK.""",

"forcechangepin.false": """Test started: F-18 :
Precondition:
1.The authenticator supports Authenticator config.
2.The authenticator must  have a PIN configured.
3. PIN/UV Protocol 2 is being used.
Test Step:
Step 1: Set the forcePINChange field to False.
Expected Result: The authenticator returns CTAP2_OK, indicating that a PIN change is not required.

Step 2: Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using the current PIN and all other required parameters. Include a permission such as Authenticator Configuration (0x20).
Expected Result: The authenticator shall return CTAP2_OK."""

    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    util.printcolor(util.YELLOW, descriptions[mode])
   
    if str(pinset).lower() == "yes": 
        if mode == "getpinToken":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission=4
            getPINtokenwithPermission1(mode,pin,permission) #without providing the permisssion

        elif mode == "cmPermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission(mode,pin,permission)
        elif mode =="acfgPermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x20  # Authenticator Configuration permission
            getPINtokenwithPermission(mode,pin,permission)
        elif mode == "mcPermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x01  # MakeCredential permission
            getPINtokenwithPermission(mode,pin,permission)
        elif mode == "gaPermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x02  # GetAssertion permission
            getPINtokenwithPermission(mode,pin,permission)

        elif mode == "lbwpermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x10  # Large Blob Write permission
            getPINtokenwithPermission(mode,pin,permission)

        elif mode == "bepermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x08  # Bio Enrollment permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "permission.zero":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x00  # zer value  permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "verifycmper":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)
            #pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
            subCommand = 0x01  # getCredsMetadata
            pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
            apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
            util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)

        elif mode == "verifyacfgper":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x20  # Authenticator Configuration permission
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission) #varify the piToken
            subCommand = 0x01
            apdu=enableEnterpriseAttestation(pinToken,subCommand)
            util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
        elif mode == "verifymcper":
            clientDataHash=os.urandom(32)
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x01  # MakeCredential permission
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
            makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pubkey, pinAuthToken);
            if isinstance(makeCredAPDU, str):
                result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
            else:
                for i, apdu in enumerate(makeCredAPDU):
                    result, status = util.APDUhex(apdu,f"Rest of Data:",checkflag=(i == len(makeCredAPDU) - 1)
            )

            return result
        
        elif mode == "verifygaper":
            clientDataHash=os.urandom(32)
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x01  # MakeCredential permission
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
            makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pubkey, pinAuthToken);
            result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
            credId=authParasing(result)
            permission = 0x02  # GetAssertion permission
            pinToken, pubkey = getPINtokenwithPermission(mode,pin,permission)  #varify the piToken
            pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
            apdu = createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
            result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
        elif mode == "InvalidPIN":
            pin="654321" #wrong pin
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "InvalidpinHashEnc":
            
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "Invalidkey_agreement":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)

        elif mode == "Invalidpermission":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x00  # invalid value of permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "piuvauthmissing":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "keyAgreementmissing":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "subcommandInvalid":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "pinauthblocked":
            pin="654321"
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "pinauthblocked.pin":
            wrongpin="654321"
            util.printcolor(util.YELLOW,f"  PIN IS: {wrongpin}")
            permission = 0x04  # CredentialManagement permission
            mode="pinauthblocked"
            getPINtokenwithPermission2(mode,wrongpin,permission)#pinauthblocked
            mode="pinauthblocked.pin"
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "pinretry":
            wrongpin="654321"
            util.printcolor(util.YELLOW,f"  PIN IS: {wrongpin}")
            permission = 0x04  # CredentialManagement permission
            mode="pinauthblocked"
            getPINtokenwithPermission2(mode,wrongpin,permission)#pinauthblocked
            mode="pinauthblocked.pin"
            getPINtokenwithPermission2(mode,pin,permission)
            util.APDUhex("801000000606A20102020100", "Client PIN GetRetries", checkflag=True)

        elif mode == "withpowercycle":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "pinblocked":
            wrongpin="654321"
            util.printcolor(util.YELLOW,f"  PIN IS: {wrongpin}")
            permission = 0x04  # CredentialManagement permission
            mode="pinauthblocked"
            getPINtokenwithPermission2(mode,wrongpin,permission)#pinauthblocked
            mode="pinblocked"
            getPINtokenwithPermission2(mode,wrongpin,permission)#pinblock
            util.APDUhex("801000000606A20102020100", "Client PIN GetRetries", checkflag=True)
        elif mode == "Invalidkey_sharesecret":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        
        elif mode == "platformCOSKEY.notmap":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)

        elif mode == "pinHashEnc.notbyte":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "forcepinset":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x20  # authenticator config
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)
            subCommand = 0x03
            apdu=newMinPinLength(pinToken,subCommand)
            response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
            util.APDUhex("80100000010400", "Get Info")
            getPINtokenwithPermission2(mode,pin,permission)
        elif mode == "changepin":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x20  # authenticator config
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)
            subCommand = 0x03
            apdu=newMinPinLength(pinToken,subCommand)
            response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
            newpin="654321"
            changePin(pin,newpin)
            util.APDUhex("80100000010400", "Get Info")
            getPINtokenwithPermission(mode,newpin,permission)

        elif mode == "changewrongpin":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x20  # authenticator config
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)
            subCommand = 0x03
            apdu=getpintokenCTAP2_2.newMinPinLength(pinToken,subCommand)
            response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
            newpin="654321"
            getpintokenCTAP2_2.changePin(pin,pin)
            util.APDUhex("80100000010400", "Get Info")
            getPINtokenwithPermission2(mode,newpin,permission)

        elif mode == "forcechangepin.false":
            util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
            permission = 0x20  # authenticator config
            pinToken, pubkey=getPINtokenwithPermission(mode,pin,permission)
            subCommand = 0x03
            apdu=getpintokenCTAP2_2.newMinPinLength1(pinToken,subCommand)
            response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
            getPINtokenwithPermission(mode,pin,permission)


        




            
        
       
        





    else:
        if mode == "withoutpingetpintoken":
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            util.APDUhex("80108000010700", "Reset Card PIN")
            util.printcolor(util.YELLOW,f"  PIN NOT SET")
            permission = 0x04  # CredentialManagement permission
            getPINtokenwithPermission2(mode,pin,permission)

            
        

           
            












def getPINtokenwithPermission(mode,curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey

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
 
    if mode == "Invalidkey_agreement" : 
        key_agreement, shareSecretKey = util.wrongkeyagreement(decoded_data[1])
        pin_hash    = util.sha256(curpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "InvalidPIN":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "bepermission":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "permission.zero":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "InvalidpinHashEnc":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "withoutpingetpintoken":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "Invalidpermission":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "piuvauthmissing":
         pinSetAPDU =createGetPINtokenmissingparam(key_agreement,permission)
    elif mode == "keyAgreementmissing":
        pinSetAPDU =createGetPINtokenmissingkeyagrrement(pinHashEnc,permission)
    elif mode == "subcommandInvalid":
        pinSetAPDU =createGetPINtokenInvalidsub(pinHashEnc,key_agreement,permission)
    elif mode == "pinauthblocked":
        for _ in range(3):
            pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
            util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)
    elif mode == "pinauthblocked.pin":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "withpowercycle":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "pinblocked":
        
        for _ in range(5):
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.APDUhex("00a4040008a0000006472f0001","Select applet")
            cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
            cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
            decoded_data  = cbor2.loads(cbor_bytes)
            pubkey        = cardPublickey[6:]
            #util.printcolor(util.ORANGE,f"{pubkey}")
            key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
            pin_hash    = util.sha256(curpin.encode())[:16]
            pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
            pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
            util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)
    elif mode == "Invalidkey_sharesecret" : 
        key_agreement, shareSecretKey = util.wrongkeysharesecret(decoded_data[1])
        pin_hash    = util.sha256(curpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)

    elif mode == "platformCOSKEY.notmap":
        key_agreement, shareSecretKey = util.key_agreementnotmap(decoded_data[1])
        pin_hash    = util.sha256(curpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)

    elif mode == "pinHashEnc.notbyte":
        pinSetAPDU =createGetPINtokennotbyte(pinHashEnc,key_agreement,permission)
    elif mode == "forcepinset":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    elif mode == "changewrongpin":
        pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)


    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)



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
    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);
    


def createGetPINtoken(pinHashenc, key_agreement,permission):
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand



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

def getCredsMetadata_APDU(subCommand, pinUvAuthParam):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 2,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    #util.printcolor(util.BLUE, cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)
    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu
def enableEnterpriseAttestation(pinToken, subCommand):
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # enableEnterpriseAttestation
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu


def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

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
        },
        {
            "alg": -257,  # RS256
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
    dataCBOR = "A7"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

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
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


def restPin(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    util.APDUhex("80108000010700", "Reset Card PIN")
    util.APDUhex("80100000010400", "GetInfo")
    setpin(pin)


def setpin(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
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
 
        APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
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

    apdu = "80108000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    return apdu