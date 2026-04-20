import util
import cbor2
import binascii
import Setpinp22
import os
import credentialManagement
import Setpinp1 
import getasserationrequest
import DocumentCreation

RP_domain          = "localhost"
user="bobsmith"
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "GET PIN TOKEN"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def authenticatorGetPinTokenP2_2(mode,pin,pinset):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL

    PROTOCOL = 2
    util.printcolor(util.YELLOW, "****ClientPin protocol 2.2****")
    util.ResetCardPower()
    util.ConnectJavaCard()

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
         "validgetpintoken": """Test started: P-1 : 
Precondition:
1.The authenticator must be in a reset state.
2.The authenticator must have a PIN configured.
3.Verify whether Client PIN is supported by using the GetInfo command.
4.Protocol version 2 must be used.

Test Step:
Send  a pinUvAuthToken using the getPinToken (0x05) subcommand with a correct pinHashEnc and valid command parameters. 
Expected Result:The authenticator should return CTAP2_OK along with a valid encrypted pinUvAuthToken. CTAP2_OK.""",

        "verifypintoken": """Test started: P-2 :
Precondition:
1.The authenticator must be in a reset state.
2.The authenticator must have a PIN configured.
3.Verify whether Client PIN is supported by using the GetInfo command.
4.Protocol version 2 must be used.

Test Case:
Step 1 — Request pinUvAuthToken
Request a pinUvAuthToken using the getPinToken (0x05) subcommand with a correct pinHashEnc and all other required parameters.
Expected Result :The authenticator returns CTAP2_OK. 
Step 2 — Verify that the authenticator returns pinUvAuthToken 
Use the returned pinUvAuthToken in an authenticatorMakeCredential (0x01) with all other parameter are valid.
Expected Result :The authenticatorMakeCredential command succeeds (returns CTAP2_OK ). """,  
       
       
       "withoutsetpin": """Test started: F-1 :
Precondition:
1.The authenticator must be in a reset state.
2.Authenticator does not have a PIN configured.
3.Verify whether Client PIN is supported by using the GetInfo command.
4.Protocol version 2 must be used.
Test case:
Send a getPinToken (0x05) request with valid command parameters, including a correctly formatted pinHashEnc.
Since no PIN is configured on the authenticator, it should return CTAP2_ERR_PIN_NOT_SET.""",

"missing.pinUvAuthProtocols": """Test started: P-2 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
Send a getPinToken (0x05) request while omitting pinUvAuthProtocol.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",
"missing.subcommand": """Test started: P-2 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
Send a getPinToken (0x05) request while omitting subcommand(0x05).
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",


"missing.pinHashenc": """Test started: P-2 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
Send a getPinToken (0x05) request while omitting pinHashenc.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"missing.keyAgreement": """Test started: P-2 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
Send a getPinToken (0x05) request while omitting keyAgreement.
Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",
"invalid.pinUvAuthProtocol": """Test started: F-6 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
 Send a getPinToken (0x05) request Invalid pinUvAuthProtocol  parameter .
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER. """,

"invalid.subcommand": """Test started: F-2 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
 Send a getPinToken (0x05) request Invalid  subcommand parameter .
Expected Result:The authenticator returns CTAP2_ERR_INVALID_SUBCOMMAND. """,

"invalid.pinHashEnc": """Test started: F-3 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
 Send a getPinToken (0x05) request Invalid  pinHashEnc parameter .
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER. """,

"invalid.keyAgreement": """Test started: F-9 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Case:
 Send a getPinToken (0x05) request Invalid keyAgreement parameter .
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER. """,

"permission": """Test started: F-10 :
Precondition:
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.Protocol version 2 must be used.

Test Step:
Send an authenticatorClientPIN request using the getPinToken (0x05) subcommand, and include the credential management (cm, 0x04) permission in the request parameters.
Since the cm (0x04) permission is not permitted with the getPinToken (0x05) subcommand.
Expected Result:The authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",

"wrongpin": """Test started: F-11 :
Precondition: 
1.The authenticator must be in a reset state.
2.Verify whether Client PIN is supported by using the GetInfo command.
3.The authenticator  have a PIN configured.
4.supported Protocol version  must be used.

Test Step:
Send an authenticatorClientPIN request using the getPinToken(0x05) subcommand.
Providing an incorrect PIN while supplying all other parameters correctly (e.g., a properly formatted pinHashEnc and valid command fields).
Under these conditions.
Expected Result: The authenticator is expected to return CTAP2_ERR_PIN_INVALID.""",

 "wrongpin.repeatedly": """Test started: F-12 :
Precondition:  
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
Send an authenticatorClientPIN request using the getPinToken (0x05) subcommand, providing an incorrect PIN while supplying all other parameters correctly (e.g., a properly formatted pinHashEnc and valid command fields).
If the user repeatedly provides an invalid PIN for multiple consecutive attempts.
Expected Result:The authenticator return CTAP2_ERR_PIN_AUTH_BLOCKED.""",




"pinblocked": """Test started: F-13 :
Precondition:  
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
Attempt to change the PIN by issuing an authenticatorClientPIN request with the getpintoken (0x06) subcommand, supplying an incorrect PIN (e.g., 654321). 
Repeat this operation until the authenticator’s pinRetries counter is exhausted and the PIN becomes blocked.
Once the PIN is blocked, send an authenticatorClientPIN request using the getPinToken (0x05) subcommand with the correct PIN.
Under these conditions.
Expected Result:The authenticator shall return CTAP2_ERR_PIN_BLOCKED.""",

"invalid.share secret": """Test started: F-14 :
Precondition:  
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand while providing an invalid share secret .
with  a correct pinHashEnc parameters.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PIN.""",

"invalid.pinHashEnclength": """Test started: F-15 :
Precondition:  
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand while providing an invalid  pinHashEnclength(must be 32 byte but giving less or more).
with  a correct pinHashEnc parameters.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",




"pinauthblocked": """Test started: F-16 :
Precondition:  
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.

Test Step:
Step1:
Send a clientPIN request using the getPinToken (0x05) subcommand with an incorrect PIN (e.g., "654321").
Repeat:
Send the request multiple times (e.g., 3 consecutive attempts).
Expected Result:
For each incorrect PIN attempt before the limit is reached, the authenticator returns:
CTAP2_ERR_PIN_INVALID
Once the maximum allowed retries are exceeded, the authenticator returns:
CTAP2_ERR_PIN_AUTH_BLOCKED
Step 2: send retry counter command check retry count remaining suppose XX
Step 3: Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN 8 times.
Step 4: send retry counter command check retry count remaining same as step XX.""",

"withoutpowercyclereset": """Test started: F-17:
Precondition:
1.The authenticator must already have a PIN configured.
2.pin auth is blocked .
3.Protocol version 2 must be used.

Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an correct PIN , perform a without power cycle reset on the authenticator and then send a request with the correct PIN.
The authenticator shall return CTAP2_ERR_PIN_AUTH_BLOCKED.""",

"pinauth.blocked": """Test started: F-18 :
Precondition: 
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
1.Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN (for example, the current PIN is "123456", but "654321" is used).After multiple incorrect PIN attempts, the authenticator should return CTAP2_ERR_PIN_AUTH_BLOCKED.
2.Once the PINAUTH is blocked, perform a power cycle reset on the authenticator and then send a request with the correct PIN.
The authenticator should now return a valid pinUvAuthToken.
3.Check Retry counter should be reset to 8.""",


"pinHashEnc.notbyte": """Test started: F-26 :
Precondition:
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
Send CTAP2 authenticatorClientPIN getPinToken (0x05) message with correct platformCOSKEY but pinHashEnc is not bytes (e.g., integer or string). Wait for the response.
The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"platformCOSKEY.notmap": """Test started: F-19 :
Precondition:
1.Authenticator dont  have a PIN configured.
2.Protocol version 2 must be used.
Test Step:
Send CTAP2 authenticatorClientPIN getPinToken (0x05) message with platformCOSKEY not being a map (e.g., an array or string). 
Wait for the response.
Expected Output: The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",



 "forcepinchange": """Test started: F-20 :
1.Authenticator  have a PIN .
2.Protocol version 2 must be used.

Test Step:
Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters. 
After forcePINChange is set to true, but without performing a PIN change, if the client attempts to use the old PIN to request getPinToken (0x05).
Expected Output:The authenticator shall not allow PIN-token retrieval and shall return CTAP2_ERR_PIN_INVALID.""",


"forcepinchange.false": """Test started: P-6 :
Precondition:
Precondition:
1.The authenticator must already have a PIN configured, 
2.The forcePINChange field in the authenticatorGetInfo response must be false or absent.
3.Protocol version 2 must be used.
Test Step:
Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters.
Since forcePINChange is false or not present, no PIN change is required, and the authenticator shall process the request normally and return a valid pinUvAuthToken.""",







"changingpin": """Test started: P-7 :
Precondition:
1.The authenticator must already have a PIN configured, 
2.The forcePINChange field in the authenticatorGetInfo response must beTrue.
3.Protocol version 2 must be used.
Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters. 
and forcePINChange is true, a PIN change is required. After successfully changing the existing PIN, send the getPinToken (0x05) request again. 
Expected Output:The authenticator shall respond with CTAP2_OK and return a valid pinUvAuthToken.""",



"forcePINChange.token": """Test started: F-21 :
Precondition:
1.The authenticator must already have a PIN configured, 
2.The forcePINChange field in the authenticatorGetInfo response must beTrue.
3.Protocol version 2 must be used.
Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters And forcePINChange is true, a PIN change is required.
After successfully changing the PIN, send a getPinToken (0x05) request using an incorrect PIN. 
Expected Output:The authenticator shall reject the request and return CTAP2_ERR_PIN_INVALID..""",


"pinBlocked.Blocked": """Test started: F-22 :
Precondition:
1.The authenticator must already have a PIN configured, 
2.Protocol version 2 must be used.

Step 1: Trigger PIN Authentication Block
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN.
Repeat this for 3 incorrect PIN attempts.
Expected Result:The authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED.


Step 2: Power Cycle and Re-Attempt Incorrect PIN Entry
Perform a power cycle reset on the authenticator.
Again, send getPinToken (0x05) with an incorrect PIN for 3 incorrect attempts.
Expected Result:The authenticator again returns CTAP2_ERR_PIN_AUTH_BLOCKED.

Step 3: Verify Retry Counter
Check the PIN retry counter using getPINRetries.
Expected Result:The retry counter should be reset to 2.

Step 4: Trigger Permanent PIN Block
Perform a power cycle reset on the authenticator.
Send getPinToken (0x05) with an incorrect PIN for 2 incorrect attempts.
Expected Result:The authenticator returns CTAP2_ERR_PIN_BLOCKED (0x32).

Step 5: Confirm Blocked State Even with Correct PIN
Perform a power cycle reset again.
Send getPinToken (0x05) with a correct PIN.
Expected Result:The authenticator still returns CTAP2_ERR_PIN_BLOCKED (0x32), confirming permanent PIN lock..""",


"forcechangepinwrong": """Test started: F-23 :
Precondition:
1.The authenticator must already have a PIN configured, 
2.The forcePINChange field in the authenticatorGetInfo response must beTrue.
3.Protocol version 2 must be used.

Step1:Start by sending a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand, providing all command parameters correctly. Because forcePINChange is true, the authenticator requires the PIN to be changed before any pinUvAuthToken can be issued. Therefore, when attempting to request the pinUvAuthToken without performing a PIN change,
Expected Output: The authenticator should return CTAP2_ERR_PIN_INVALID.

Step2:Proceed to perform a successful Change PIN operation by supplying the correct current PIN and a valid new PIN with all parameters correctly formed.
Expected Output: The authenticator should accept the new PIN and return CTAP2_OK.

Step3: check forcePINChange should clear in Getinfo

Step4:A fter the PIN has been successfully updated, send another getPinToken (0x05) request using a correct pinHashEnc and all valid parameters. Now that the PIN change requirement has been fulfilled.
Expected Output:the authenticator should return CTAP2_OK along with a valid encrypted pinUvAuthToken.""",


"Allpermission": """Test started: F-24 :
Precondition:
1.The authenticator must already have a PIN configured, 
2.Protocol version 2 must be used.

Test Step:
Request a pinUvAuthToken using the getPinToken (0x05) subcommand with a correct pinHashEnc and valid command parameters. Verify that the authenticator returns CTAP2_OK, then use the returned pinUvAuthToken for following commands

Case 1: authenticatorMakeCredential command.
Expexted OUTPUT :The Authenticatior should return CTAP2_OK

Case 2: authenticatorGetAssertion command.
Expexted OUTPUT :The Authenticatior should return CTAP2_OK

Case 3: authenticatorConfig command.
Expexted OUTPUT :The Authenticatior should return should failed
 
Case 4: authenticatorCredentialManagement command.
Expexted OUTPUT :The Authenticatior should return should failed""",



"sharesecretprotol1": """Test started: F-25 :
Precondition:
1.The authenticator must already have a PIN configured, 
2.Protocol version 2 must be used.

Test Step:
Generate the shared secret using PIN protocol 1, completing the keyAgreement and shared-secret establishment successfully.
Then attempt to request a pinUvAuthToken using the getPinToken (0x05) subcommand but incorrectly specify PIN protocol 2, while all other command parameters are valid. Because the shared secret was established under protocol 1 but the request is made under protocol 1.
Expected Result:The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",









       "pinUvAuthProtocol": """Test started: F-3 :
Precondition:Authenticator must have a PIN configured.
Send a getPinToken (0x05) request using an unsupported pinUvAuthProtocol value (for example, 3, when the authenticator only supports protocols 1 and 2).
Authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",
                 
     
        

        "invalid. key-agreement": """Test started: F-8 :
Precondition: The authenticator must already have a PIN configured.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand while providing an invalid platform key-agreement key.
with  a correct pinHashEnc parameters. The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

       

        "cmpermission": """Test started: F-10 :
Precondition: The authenticator must already have a PIN configured.
Test Step:
Send an authenticatorClientPIN request using the getPinToken (0x05) subcommand without specifying any permissions,.
resulting in the authenticator applying its default permission set for credential-management operations. 
If the authenticator is equipped with a display, it shall request user consent for these default permissions. 
If the user does not grant consent—or if the authenticator does not receive the required explicit approval—then the authenticator shall return:CTAP2_ERR_OPERATION_DENIED.""",


        "subcommand.invalid":"""Test started: F-11 :
Precondition: The authenticator must already have a PIN configured.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand while providing an  invalid getPinToken subcommand value (for example, 0x0A). with  a correct pinHashEnc parameters.
The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",


        "pinauthblocked1": """Test started: F-12 :
Precondition: The authenticator must already have a PIN configured.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN (for example, the current PIN is "123456", but "654321" is used). 
The authenticator should return CTAP2_ERR_PIN_INVALID for each wrong attempt, and after repeated incorrect attempts (e.g., three times), it should return CTAP2_ERR_PIN_AUTH_BLOCKED.""",


        "without power cycle reset1": """Test started: F-13:
Precondition:The authenticator must already have a PIN configured.
pin auth is blocked 

Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an correct PIN , perform a without power cycle reset on the authenticator and then send a request with the correct PIN.
The authenticator shall return CTAP2_ERR_PIN_AUTH_BLOCKED.""",


        "pinisblocked1": """Test started: F-14 :
Precondition: The authenticator must already have a PIN configured.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN (for example, the current PIN is "123456", but "654321" is used).
After sending multiple incorrect PIN attempts, the authenticator should return CTAP2_ERR_PIN_AUTH_BLOCKED. Once the PIN is blocked(retries count=0), even sending the correct PIN should continue to return CTAP2_ERR_PIN_AUTH_BLOCKED until a power cycle reset is performed.send an authenticatorClientPIN request using the getPinToken (0x05) subcommand with the correct PIN.
Under these conditions, The authenticator shall return CTAP2_ERR_PIN_BLOCKED.""",



    "retrieszero": """Test started: F-15 :
Precondition:The authenticator must already have a PIN configured.
pin retries count=0

Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an correct PIN , perform  the authenticator and then send a request with the correct PIN.
The authenticator shall return CTAP2_ERR_PIN_BLOCKED..""",


        "missing.pinHashEnc": """Test started: F-16 :
Precondition:The authenticator must already have a PIN configured.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand  message with correct platformCOSKEY but missing the  pinHashEnc field , wait for the response.
The authenticator  return CTAP2_ERR_MISSING_PARAMETER...""",


        "missing.keyagrrement": """Test started: F-17 :
Precondition:The authenticator must already have a PIN configured.
Test Step:
Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with the correct PIN and all other valid parameterswith correct pinHashEnc but omit platformCOSKEY, wait for the response.
The authenticator shall return CTAP2_ERR_MISSING_PARAMETER.. The authenticator shall return CTAP2_ERR_MISSING_PARAMETER. return CTAP2_ERR_MISSING_PARAMETER...""",









        "pinHashEnc.notbyte1": """Test started: F-19 :



Precondition:The authenticator must already have a PIN configured.
Test Step:
Send CTAP2 authenticatorClientPIN getPinToken (0x05) message with correct platformCOSKEY but pinHashEnc is not bytes (e.g., integer or string). Wait for the response.
The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


        "platformCOSKEY.notmap1": """Test started: F-19 :
Precondition:The authenticator must already have a PIN configured.
Test Step:
Send CTAP2 authenticatorClientPIN getPinToken (0x05) message with platformCOSKEY not being a map (e.g., an array or string). 
Wait for the response. The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE..""",

        "forcepinchange1": """Test started: F-20 :
Precondition:The authenticator must already have a PIN configured.

Test Step:
Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters. 
After forcePINChange is set to true, but without performing a PIN change, if the client attempts to use the old PIN to request getPinToken (0x05).
The authenticator shall not allow PIN-token retrieval and shall return CTAP2_ERR_PIN_INVALID.""",



        "forcepinchange.false1": """Test started: P-6 :
Precondition:
The authenticator must already have a PIN configured, and the forcePINChange field in the authenticatorGetInfo response must be false or absent.

Test Step:
Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters.
Since forcePINChange is false or not present, no PIN change is required, and the authenticator shall process the request normally and return a valid pinUvAuthToken..""",


        



           
    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    util.printcolor(util.YELLOW, descriptions[mode])
    SCENARIO = util.extract_scenario(descriptions[mode])
    try:
        scenarioCount += 1
        if str(pinset).lower() == "yes":  
        
            if mode=="validgetpintoken":
                    response=setpin(pin)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    response,pinToken, pubkey=creatGetPinToken(pin)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode=="verifypintoken":
                    response=setpin(pin)
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    clientDataHash = os.urandom(32);
                    
                    response,pinToken, pubkey= creatGetPinToken(pin)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)

                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    response=makecred(clientDataHash,RP_domain,user,pubkey,pinAuthToken)
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
            elif mode == "mandatoryparameter":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                createpinToken(pin)
            elif mode == "mandatoryparameter":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                createpinToken(pin)
            
            elif mode == "missing.pinUvAuthProtocols":
                response=setpin(pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "missing.subcommand":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "missing.pinHashenc":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "missing.keyAgreement":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalid.pinUvAuthProtocol":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalid.subcommand":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "3E":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "invalid.pinHashEnc":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalid.keyAgreement":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "permission":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "wrongpin":
                response=setpin(pin)
                pin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "wrongpin.repeatedly":
                response=setpin(pin)
                pin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                for i in range(3):
                    pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
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

            elif mode == "pinblocked":
                pin="123456"
                response=setpin(pin)
                
                wrongpin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                
                for i in range(8):
                    
                    if i in (2,4,6):
                        util.ResetCardPower()
                        util.ConnectJavaCard()
                        util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                    pinHashEnc, key_agreement,response,status=pintoken(wrongpin,mode)
                    if i==7:
                        if response[:2] == "32":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_BLOCKED)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)
                    else:
                        if response[:2] == "31":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                        else:
                            util.printcolor(util.RED, "  ❌ Test Case Failed")
                            exit(0)

                    Setpinp1.pinGetRetries()
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "32":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_BLOCKED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "invalid.share secret":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "31":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "invalid.pinHashEnclength":
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauthblocked":
                response=setpin(pin)
                pin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                for i in range(3):
                    print("i-->",i)
                    pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                util.printcolor(util.YELLOW,f"  Step 2: send retry counter command check retry count remaining suppose 5")
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

                Setpinp1.pinGetRetries()
                util.printcolor(util.YELLOW,f" Step 3: Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN 8 times.")
                util.printcolor(util.YELLOW,f" Step 4: send retry counter command check retry count remaining same as 5.")
                for i in range(8):
                    pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                    if response[:2] == "34":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                Setpinp1.pinGetRetries()
            elif mode == "withoutpowercyclereset":
                pin="123456"
                response=setpin(pin)
                
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                wrongpin="654321"
                
                for i in range(3):
                    pinHashEnc, key_agreement,response,status=pintoken(wrongpin,mode)
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
            
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "34":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauth.blocked":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                wrongpin="654321"
                for i in range(3):
                    pinHashEnc, key_agreement,response,status=pintoken(wrongpin,mode)
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
                
                util.printcolor(util.YELLOW,f"  Step 2: PIN AUTH IS BLOCKED STATE WITH POWER CYCLE RESET PROVIDING CORRECT PIN:{pin}")
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS,CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

                util.printcolor(util.YELLOW,f" Step 4: send retry counter command check retry count remaining same as 8.")
                Setpinp1.pinGetRetries()
            elif mode == "pinHashEnc.notbyte":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "platformCOSKEY.notmap":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "11":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "forcepinchange":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "31":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "forcepinchange.false":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS,CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "changingpin":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS,CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinBlocked.Blocked":
                pin="123456"
                response=setpin(pin)
                wrongpin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f" Step 1:Repeat this for 3 incorrect PIN attempts {pin}")
                for i in range(3):
                    pinHashEnc, key_agreement,response,status=pintoken(wrongpin,mode)
                    Setpinp1.pinGetRetries()
                
                util.printcolor(util.YELLOW,f" Step 2:Power Cycle and Re-Attempt Incorrect PIN Entry{pin}")
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                
                for i in range(3):
                    pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                    Setpinp1.pinGetRetries()
                pintoken(pin,mode)
                util.printcolor(util.YELLOW,f" Step 3:Verify Retry Counter is 2 or Not")
                Setpinp1.pinGetRetries()
                util.printcolor(util.YELLOW,f"Step 4: Power Cycle incorrect PIN for 2 incorrect attempts{pin}")
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                for i in range(2):
                    pintoken(pin,mode)
                    Setpinp1.pinGetRetries()
                pin="123456"
                util.printcolor(util.YELLOW,f"Step 5: Providing Correct PIN {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "forcechangepinwrong":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS, CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode=="Allpermission":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                clientDataHash = os.urandom(32);    
                response,pinToken, pubkey = creatGetPinToken(pin)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                response=makecred(clientDataHash,RP_domain,user,pubkey,pinAuthToken)
                credId =getasserationrequest.authParasing(response)
                getasserationrequest.makeAssertion(pin, clientDataHash, RP_domain, credId);
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "02":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "sharesecretprotol1":
                pin="123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=pintokenusingP1(pin,mode)
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            
            


                
            

            




            elif mode == "pinUvAuthProtocol":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            
            
            
            
                
            elif mode == "invalid. key-agreement":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                
                pintoken(pin,mode)
            
            
            elif mode == "cmpermission":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)

            elif mode == "subcommand.invalid":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            elif mode == "pinauthblocked1":
                pin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
                pintoken(pin,mode)
                pintoken(pin,mode)
            elif mode == "without power cycle reset":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
                
            elif mode == "pinisblocked":
                pin="654321"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                util.ResetCardPower()
                util.ConnectJavaCard()
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                util.ResetCardPower()
                util.ConnectJavaCard()
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                pintoken(pin,mode)
                util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
            elif mode == "retrieszero":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            elif mode == "missing.pinHashEnc":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            elif mode == "missing.keyagrrement":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            elif mode == "pinHashEnc.notbyte1":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            elif mode == "platformCOSKEY.notmap1":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pintoken(pin,mode)
            
            
            
            elif mode == "forcePINChange.token":
                pin="123456"
                response=setpin(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                pinHashEnc, key_agreement,response,status=pintoken(pin,mode)
                if response[:2] == "31":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)


                



        else:
            util.run_apdu("00A4040008A0000006472F0001", "Select applet")
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.run_apdu("00A4040008A0000006472F0001", "Select applet")
            util.run_apdu("80108000010700", "Reset Card PIN","00")
            if mode=="withoutsetpin":
                response=creatGetPinTokenexiting(pin)
                if response[:2] == "35":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
            
        

def setpin(pin):
    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo","00")
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.run_apdu("00A4040008A0000006472F0001", "Select applet")
    util.run_apdu("80108000010700", "Reset Card PIN","00")
    util.run_apdu("80100000010400", "GetInfo","00") 
    response=Setpinp22.setpin(pin)   
    return response    
    

def makecred(clientDataHash, rp,user,pubkey, pinAuthToken):
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken)
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
            apdu,
            f"Rest of Data:",
            checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result


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
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 1

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
    

























def creatGetPinToken(curpin):
    #util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    response,pinToken, pubkey = getPINtokenPubkey(curpin)
    return response,pinToken, pubkey

def creatGetPinTokenexiting(curpin):
    #util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    response=getPINtokenPubkeyexisting(curpin)
    return response
   

def createpinToken(mode,curpin):
    #util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    getPINtokenpubkey(mode,curpin)
   
def pintokenusingP1(pin,mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.printcolor(util.YELLOW,f"  Providing protocol 1 share secret:")
    cardPublickey, status = util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    util.printcolor(util.YELLOW,f"  Providing protocol 1 share secret: {shareSecretKey.hex()}")
    pin_hash    = util.sha256(pin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    protocol=2
    subcommand=5
    pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)
    return response
    




def pintoken(pin,mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(pin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    print("pinHashEnc",pinHashEnc.hex())
    protocol=2
    subcommand=5
    if mode=="pinUvAuthProtocol":
        pinSetAPDU = GetPINtokeninvalidprotocol(pinHashEnc,key_agreement)
    

    # elif mode=="permission":
    #     permission = 0x04  # Credential Management
    #     pinSetAPDU = GetPINtokenwithPer(pinHashEnc,key_agreement,permission)
    elif mode=="invalid. key-agreement":
        key_agreement1, shareSecretKey1 = util.wrongkeyagreement(decoded_data[1])
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey1[32:],pin_hash)
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement1)
        key_agreement=key_agreement1
    elif mode=="invalid.share secret1":
        key_agreement1, shareSecretKey1 = util.wrongkeysharesecret(decoded_data[1])
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey1[32:],pin_hash)
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement1)
        key_agreement=key_agreement1
    elif mode=="cmpermission":
        permission = 0x04  # Credential Management
        pinSetAPDU = GetPINtokenwithPer(pinHashEnc,key_agreement,permission)
    elif mode=="subcommand.invalid":
        pinSetAPDU = GetPINtokeninvalidsubcommand(pinHashEnc, key_agreement)

    # elif mode=="missing.pinHashEnc":
    #     pinSetAPDU = GetPINtokenmissingpinhash(pinHashEnc, key_agreement)
    elif mode=="missing.pinUvAuthProtocols":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="missing.subcommand":   
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="missing.pinHashenc":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="missing.keyAgreement":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)

    elif mode=="invalid.pinUvAuthProtocol":
        protocol=3
        util.printcolor(util.YELLOW,f"  Invalid pinUvAuthProtocol: {protocol}")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="invalid.subcommand":
        subcommand=0
        util.printcolor(util.YELLOW,f"  Invalid Subcommand: {subcommand}")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="invalid.pinHashEnc":
        pinHashEnc = os.urandom(64)
        util.printcolor(util.YELLOW,f"  Invalid pinHashEnc:{pinHashEnc.hex()}")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="invalid.keyAgreement":
        key_agreement, shareSecretKey = util.wrongkeyagreement(decoded_data[1])
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        formatted = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in key_agreement.items()}
        util.printcolor(util.YELLOW,f"  Invalid keyAgreements: {formatted}")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)

    elif mode=="permission":
        permission = 0x04  # Credential Management
        #pinSetAPDU = GetPINtokenwithPer(pinHashEnc,key_agreement,permission)delet
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="wrongpin":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode == "wrongpin.repeatedly":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode == "pinblocked":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode == "invalid.share secret":
        key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
        shareSecretKey=os.urandom(64) #size 64 is madetory
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        util.printcolor(util.YELLOW,f"  Invalid Sharesecret: {shareSecretKey.hex()}")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
        
    elif mode == "invalid.pinHashEnclength":
        key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinHashEnc=os.urandom(10)#invalid Length
        util.printcolor(util.YELLOW,f"  invalid pinHashEnclength: {pinHashEnc.hex()}")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode == "pinauthblocked":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
      
    elif mode == "pinHashEnc.notbyte":
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode == "platformCOSKEY.notmap":
        key_agreement, shareSecretKey = util.key_agreementnotmap(decoded_data[1])
        util.printcolor(util.YELLOW, f"  platformcosekey is not map: {key_agreement}")
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="forcepinchange":
        permission = 0x20  # authenticator config
        pinToken, pubkey =getPINtokenPubkey11per(pin, permission)
        subCommand = 0x03
        util.printcolor(util.YELLOW, f"  ForceChange is TRUE")
        apdu=newMinPinLength(pinToken,subCommand)
        util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        util.APDUhex("80100000010400", "Get Info")
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)
    elif mode=="forcepinchange.false":
        permission = 0x20  # authenticator config
        pinToken, pubkey =getPINtokenPubkey11per(pin, permission)
        subCommand = 0x03
        apdu=newMinPinLength1(pinToken,subCommand)
        response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        util.APDUhex("80100000010400", "Get Info")
        pinSetAPDU = GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement)
    elif mode=="changingpin":
        pin="123456"
        permission = 0x20  # authenticator config
        pinToken, pubkey =getPINtokenPubkey11per(pin, permission)
        subCommand = 0x03
        apdu=newMinPinLength(pinToken,subCommand)
        response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        newpin="654321"
        changePin(pin,newpin)
        key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

        pin_hash    = util.sha256(newpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)
    elif mode=="forcePINChange.token":
        permission = 0x20  # authenticator config
        pinToken, pubkey =getPINtokenPubkey11per(pin, permission)
        subCommand = 0x03
        apdu=newMinPinLength(pinToken,subCommand)
        response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        #util.APDUhex("80100000010400", "Get Info")
        newpin="654321"
        changePin(pin,newpin)
        key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)
    elif mode=="forcechangepinwrong":
        permission = 0x20  # authenticator config
        pinToken, pubkey =getPINtokenPubkey11per(pin, permission)
        subCommand = 0x03
        util.printcolor(util.YELLOW, f"  ForceChange is TRUE")
        apdu=newMinPinLength(pinToken,subCommand)
        util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        util.APDUhex("80100000010400", "Get Info")
        util.printcolor(util.YELLOW,f"  without performing a PIN change {pin}")
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)
        
        newpin="654321"
        util.printcolor(util.YELLOW,f"  Performoring The Change PIN operation {newpin}")
        changePin(pin,newpin)
        util.printcolor(util.YELLOW,f"  Performoring The Getinfo")
        util.APDUhex("80100000010400", "Get Info")
        key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
        pin_hash    = util.sha256(newpin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)
    elif mode=="Allpermission":
        permission = 0x04  # Credential Management
        pinSetAPDU = GetPINtokenwithPer(pinHashEnc,key_agreement,permission)
        util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);
        permission = 0x20  # Credential Management
        pinSetAPDU = GetPINtokenwithPer(pinHashEnc,key_agreement,permission)
        

      
    



        
    
    
    

    
    
    







    elif mode=="missing.keyagrrement":
        pinSetAPDU = GetPINtokenmissingkey(pinHashEnc, key_agreement)
    elif mode=="pinHashEnc.notbyte1":
        pinSetAPDU = GetPINtokenpinHashnotbyte(pinHashEnc, key_agreement)
    elif mode=="platformCOSKEY.notmap1":
        key_agreement, shareSecretKey = util.key_agreementnotmap(decoded_data[1])
        pin_hash    = util.sha256(pin.encode())[:16]
        pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
        pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)

    

    
    
    

    


        
    else:
         pinSetAPDU = createGetPINtoken(pinHashEnc, key_agreement)

    response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);
    return pinHashEnc, key_agreement,response,status


def changePin(old_pin, new_pin):
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

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
    pinAuth = hmac_value[:16]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

def getPINtokenPubkey11per(curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =createGetPINtoken1(pinHashEnc,key_agreement,permission)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey
def createGetPINtoken1(pinHashenc, key_agreement,permission):
    
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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand

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

def getPINtokenPubkey11(curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =credentialManagement.createGetPINtoken(pinHashEnc,key_agreement,permission)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey


def getPINtokenPubkey(curpin):
    
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)
    

    #if (hexstring[0:2] != "00"):
        #util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        #os._exit(0)
    #print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return hexstring,token, pubkey


def getPINtokenPubkeyexisting(curpin):
    
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)
    return hexstring

    

def newMinPinLength(pinToken, subCommand):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to minimumpinlength 6 )
        0x03: True   # forcePINChange = true means change pin change requried
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


def newMinPinLength1(pinToken, subCommand):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to minimumpinlength 6 )
        0x03: False   # forcePINChange = false means change pin change not requried
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

def getPINtokenpubkey(mode,curpin):
    
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    subcommand=5
    protocol=2

    if mode=="missing.pinUvAuthProtocol":
        pinSetAPDU = createGetPINToken(mode,subcommand,protocol,pinHashEnc,key_agreement)
    

        util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    


def createGetPINtoken(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand


def GetPINtokeninvalidprotocol(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "03" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand




def GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashenc, key_agreement):
    
    cbor_subcommand   = cbor2.dumps(subcommand).hex().upper()
    cbor_protocol   = cbor2.dumps(protocol).hex().upper()
    cbor_platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    if mode == "missing.pinUvAuthProtocols":
        util.printcolor(util.YELLOW,f" Missing pinUvAuthProtocols ")
        dataCBOR = "A3"
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    elif mode=="missing.subcommand":
        util.printcolor(util.YELLOW,f" Missing SubCommand ")
        dataCBOR = "A3"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
    elif mode=="missing.pinHashenc":
        util.printcolor(util.YELLOW,f" Missing pinHashenc ")
        dataCBOR = "A3"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY
    elif mode=="missing.keyAgreement":
        util.printcolor(util.YELLOW,f" Missing keyAgreement ")
        dataCBOR = "A3"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
    elif mode=="permission":
        permission = 0x04
        permission_hex   = cbor2.dumps(permission).hex().upper()
        util.printcolor(util.YELLOW, "Trying to get the PIN token without giving CM permission")
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
        dataCBOR = dataCBOR + "09"+ permission_hex
    elif mode=="pinHashEnc.notbyte":
        # pinHashEnc = bytes.fromhex(pinHashenc)
        # cbor_pinHashenc = cbor2.dumps(pinHashEnc).hex().upper()
        
        #cbor_pinHashenc  = cbor2.dumps(pinHashEnc_str).hex().upper()
        util.printcolor(util.YELLOW, "pinHashenc is not byte")
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ cbor_protocol               # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand             # getPINtoken
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY         #keyAgreeement
        dataCBOR = dataCBOR + "06"+  "0102"                 #(cbor_pinHashenc is not byte)
       

        
        

    else:
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc
    length = (len(dataCBOR) >> 1) +1 

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
    return APDUcommand



def GetPINtokeninvalidsubcommand(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "A0" # subcommand wrong
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def GetPINtokenmissingpinhash(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A3"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "05" 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    #dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def GetPINtokenmissingkey(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A3"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "05" 
    
    #dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def GetPINtokenpinHashnotbyte(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "05" 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06" +"01" #(cbor_pinHashenc is not byte)
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def platformCOSKEYnotmap(pinHashenc, key_agreement):
    print("hiiiiiiiiiiiiiiiiiiiii")
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "05" 
    
    dataCBOR = dataCBOR + platformCOSKEY 
    dataCBOR = dataCBOR + "06" +cbor_pinHashenc
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand
def platformCOSKEY(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 wrong protocol 
    dataCBOR = dataCBOR + "02"+ "05" 
    #here platformCOSKEY is not map
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def GetPINtokenwithPer(pinHashenc, key_agreement,permission):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper()

    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    dataCBOR = dataCBOR + "09"+ permission_hex
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand







def createGetPINToken(mode,subcommand,protocol,pinHashenc, key_agreement):
    cbor_subcommand   = cbor2.dumps(subcommand).hex().upper()
    cbor_protocol   = cbor2.dumps(protocol).hex().upper()
    cbor_platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    if mode == "missing.pinUvAuthProtocol":

        dataCBOR = "A3"
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    else:
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ cbor_protocol # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # getPINtoken
        
        dataCBOR = dataCBOR + "03"+ cbor_platformCOSKEY
        dataCBOR = dataCBOR + "06"+ cbor_pinHashenc 
        
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
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
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)




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
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu