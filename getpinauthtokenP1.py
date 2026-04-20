import util
import cbor2
import binascii
import Setpinp22
import os
import credentialManagement
import hashlib
import Setpinp1
import getpintokenCTAP2_2
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

        PROTOCOL = 1
        util.printcolor(util.YELLOW, "**** protocol 1****")
        util.ResetCardPower()
        util.ConnectJavaCard()

        # ------------------------------
        #  MODE → TEST DESCRIPTION
        # ------------------------------
        descriptions = {
                "validgetpintoken": """Test started: P-1 : 
        Precondition:
        1.Authenticator must have a PIN configured.
        2.Protocol version 1 must be used.
        Test Step:
        Send  a pinUvAuthToken using the getPinToken (0x05) subcommand with a correct pinHashEnc and valid command parameters. 
        Expected Result:The authenticator should return CTAP2_OK along with a valid encrypted pinUvAuthToken. """,

                "verifypintoken": """Test started: P-2 :
        Precondition:
        1.Authenticator must have a PIN configured.
        2.Protocol version 1 must be used.
        Test Case:
        Step 1: Request a pinUvAuthToken using the getPinToken (0x05) subcommand with a correct pinHashEnc and all other required parameters. 
        Expected Output: The authenticator returns CTAP2_OK and provides a valid pinUvAuthToken.

        Step 2: Verify  the returned pinUvAuthToken in an authenticatorMakeCredential command. 
        Expected Output: The command executes successfully, confirming that the pinUvAuthToken is valid.""",

        "withoutsetpin": """Test started: F-1 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Steps:
        Send a getPinToken (0x05) request with valid command parameters, including a correctly formatted pinHashEnc.
        Expected Result:
        Since no PIN is configured on the authenticator, it returns CTAP2_ERR_PIN_NOT_SET.""",

        "missing.pinUvAuthProtocol": """Test started: F-2 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request while omitting pinUvAuthProtocol.
        Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER""",
        "missing.subcommand": """Test started: F-3 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request while omitting subcommand(0x05).
        Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",


        "missing.pinHashenc": """Test started: F-4 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request while omitting pinHashenc.
        Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

        "missing.keyAgreement": """Test started: F-5 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request while omitting keyAgreement.
        Expected Result: The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

        "invalid.pinUvAuthProtocol": """Test started: F-6 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request Invalid pinUvAuthProtocol  parameter .
        Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER. """,

        "invalid.subcommand": """Test started: F-7 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request Invalid  subcommand parameter .
        Expected Result:The authenticator returns CTAP2_ERR_INVALID_SUBCOMMAND. """,

        "invalid.pinHashEnc": """Test started: F-8 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request Invalid  pinHashEnc parameter .
        Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER. """,

        "invalid.keyAgreement": """Test started: F-9 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send a getPinToken (0x05) request Invalid keyAgreement parameter .
        Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER. """,

        "Without.Permission": """Test started: F-10 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Case:
        Send an authenticatorClientPIN request using the getPinToken (0x05) subcommand, and include the credential management (cm, 0x04) permission in the request parameters.
        Since the cm (0x04) permission is not permitted with the getPinToken (0x05) subcommand, the authenticator shall return CTAP1_ERR_INVALID_PARAMETER.""",
        
        "wrongpin": """Test started: F-11 :
        Precondition: 
        1.Authenticator   have a PIN configured.
        2.Protocol version 2 must be used.
        Test Step:
        Send an authenticatorClientPIN request using the getPinToken(0x05) subcommand.
        Providing an incorrect PIN while supplying all other parameters correctly (e.g., a properly formatted pinHashEnc and valid command fields).
        Under these conditions.
        Expected Result: The authenticator is expected to return CTAP2_ERR_PIN_INVALID.""",

        "pinauthblocked": """Test started: F-12 :
        Precondition
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Step
        Send an authenticatorClientPIN request using the getPinToken (0x05) subcommand, providing an incorrect PIN while supplying all other parameters correctly (e.g., a properly formatted pinHashEnc and valid command fields).
        If the user repeatedly provides an invalid PIN for multiple consecutive attempts.
        Expected Result: The authenticator return CTAP2_ERR_PIN_AUTH_BLOCKED.""",

        "pinblocked": """Test started: F-13 :
        Precondition:  
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.
        Test Step:
        Attempt to change the PIN by issuing an authenticatorClientPIN request with the changePin (0x04) subcommand, supplying an incorrect PIN (e.g., 654321). 
        Repeat this operation until the authenticators pinRetries counter is exhausted and the PIN becomes blocked.
        Once the PIN is blocked, send an authenticatorClientPIN request using the getPinToken (0x05) subcommand with the correct PIN.
        Under these conditions.
        Expected Result:The authenticator shall return CTAP2_ERR_PIN_BLOCKED.""",

        "invalid.sharecrete": """Test started: F-14 :
        Precondition:  
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.
        Test Step:
        Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand while providing an invalid share secret .
        with  a correct pinHashEnc parameters.
        Expected Result: The authenticator should return CTAP1_ERR_INVALID_PIN.""",

        "invalid.pinHashEnclength": """Test started: F-15 :
        Precondition:  
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.
        Test Step:
        Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand while providing an invalid  pinHashEnclength(must be 16 byte but giving less or more).
        with  a correct pinHashEnc parameters.
        Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

        "pinauthblocked.retries": """Test started: F-16 :
        Precondition:  
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

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
        3.Protocol version 1 must be used.

        Test Step:
        Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an correct PIN , perform a without power cycle reset on the authenticator and then send a request with the correct PIN.
        The authenticator shall return CTAP2_ERR_PIN_AUTH_BLOCKED.""",
        "pinauth.blocked": """Test started: F-18 :
        Precondition: 
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.
        Test Step:
        1.Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN (for example, the current PIN is "123456", but "654321" is used).After multiple incorrect PIN attempts, the authenticator should return CTAP2_ERR_PIN_AUTH_BLOCKED.
        2.Once the PINAUTH is blocked, perform a power cycle reset on the authenticator and then send a request with the correct PIN.
        The authenticator should now return a valid pinUvAuthToken.
        3.Check Retry counter should be reset to 8.""",

        "platformCOSKEY.notmap": """Test started: F-19 :
        Precondition:
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.
        Test Step:
        Send CTAP2 authenticatorClientPIN getPinToken (0x05) message with platformCOSKEY not being a map (e.g., an array or string). 
        Wait for the response.
        Expected Output: The authenticator shall return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",

        "forcepinchange": """Test started: F-20 :
        1.Authenticator dont  have a PIN configured.
        2.Protocol version 1 must be used.

        Test Step:
        Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters. 
        After forcePINChange is set to true, but without performing a PIN change, if the client attempts to use the old PIN to request getPinToken (0x05).
        Expected Output:The authenticator shall not allow PIN-token retrieval and shall return CTAP2_ERR_PIN_INVALID.""",

        "forcepinchange.false": """Test started: P-6 :
        Precondition:
        1.The authenticator must already have a PIN configured, 
        2.The forcePINChange field in the authenticatorGetInfo response must be false or absent.
        3.Protocol version 1 must be used.
        Test Step:
        Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters.
        Since forcePINChange is false or not present, no PIN change is required, and the authenticator shall process the request normally and return a valid pinUvAuthToken.""",




        "changingpin": """Test started: P-7 :
        Precondition:
        1.The authenticator must already have a PIN configured, 
        2.The forcePINChange field in the authenticatorGetInfo response must beTrue.
        3.Protocol version 1 must be used.
        Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters. 
        and forcePINChange is true, a PIN change is required. After successfully changing the existing PIN, send the getPinToken (0x05) request again. 
        The authenticator shall respond with CTAP2_OK and return a valid pinUvAuthToken.""",


        "forcePINChange.token": """Test started: F-21 :
        Precondition:
        1.The authenticator must already have a PIN configured, 
        2.The forcePINChange field in the authenticatorGetInfo response must beTrue.
        3.Protocol version 1 must be used.
        Send a CTAP2 authenticatorClientPIN request using the getPinToken (0x05) subcommand with valid parameters And forcePINChange is true, a PIN change is required.
        After successfully changing the PIN, send a getPinToken (0x05) request using an incorrect PIN. 
        Expected Output:The authenticator shall reject the request and return CTAP2_ERR_PIN_INVALID..""",

        "pinBlocked.Blocked": """Test started: F-22 :
        Precondition:
        1.The authenticator must already have a PIN configured, 
        2.The forcePINChange field in the authenticatorGetInfo response must beTrue.
        3.Protocol version 2 must be used.

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
        2.Protocol version 1 must be used.

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

        "sharesecretprotol2": """Test started: F-25 :
        Precondition:
        1.The authenticator must already have a PIN configured, 
        2.Protocol version 1 must be used.

        Test Step:
        Generate the shared secret using PIN protocol 2, completing the keyAgreement and shared-secret establishment successfully.
        Then attempt to request a pinUvAuthToken using the getPinToken (0x05) subcommand but incorrectly specify PIN protocol 1, while all other command parameters are valid. Because the shared secret was established under protocol 2 but the request is made under protocol 1.
        Expected Result:The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",



        }
        if mode not in descriptions:
                raise ValueError("Invalid mode!")
        SCENARIO = util.extract_scenario(descriptions[mode]) 
        util.printcolor(util.YELLOW, descriptions[mode])

        util.run_apdu("00A4040008A0000006472F0001", "Select applet")
    

        # ------------------------------------------------------
        #  CARD RESET IS OPTIONAL (Controlled by cardreset flag)
        # ------------------------------------------------------
        try:
                scenarioCount += 1
                if str(pinset).lower() == "yes":        
                        util.run_apdu("80100000010400", "GetInfo","00")
                        if mode=="validgetpintoken":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="verifypintoken":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                util.printcolor(util.YELLOW,f"Request a pinUvAuthToken using the getPinToken (0x05) subcommand:")
                                response=Setpinp1.exstingpin(pin)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="missing.pinUvAuthProtocol":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                util.printcolor(util.YELLOW,f"  Missing Protocol: ")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "14":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="missing.subcommand":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "14":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="missing.keyAgreement":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "14":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="missing.pinHashenc":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "14":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="invalid.pinUvAuthProtocol":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="invalid.subcommand":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "3E":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)

                        elif mode =="invalid.pinHashEnc":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)

                        elif mode =="invalid.keyAgreement":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="Without.Permission":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="wrongpin":
                                Setpinp1.newsetpin()
                                pin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "31":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)

                        elif mode =="pinauthblocked":
                                Setpinp1.newsetpin()
                                pin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                for i in range(3):
                                        response , status=getPINtokenPubkey(mode, pin)
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
                                util.printcolor(util.YELLOW, "User Giving Wrong Pin Pinauthblocked :")
                        elif mode =="pinblocked":
                                Setpinp1.newsetpin()
                                pin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                for i in range(8):
                                        util.ResetCardPower()
                                        util.ConnectJavaCard()
                                        util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                                        response , status=getPINtokenPubkey(mode, pin)
                                        if i== 7:
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
                                util.printcolor(util.YELLOW, "User Giving Wrong Pin Is Blocked :")
                        elif mode =="invalid.sharecrete":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "31":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="invalid.pinHashEnclength":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="pinauthblocked.retries":
                                Setpinp1.newsetpin()
                                pin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                for i in range(3):
                                        response , status=getPINtokenPubkey(mode, pin)
                                        if i== 2:
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

                                        util.printcolor(util.YELLOW, "Step 2: send retry counter command check retry count remaining suppose 5 ")
                                        Setpinp1.pinGetRetries()
                                
                                util.printcolor(util.YELLOW, "Step 3: Send a request for a pinUvAuthToken using the getPinToken (0x05) subcommand with an incorrect PIN 8 times ")
                                for i in range(8):
                                        response , status=getPINtokenPubkey(mode, pin)
                                        if response[:2] == "34":
                                                util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                                        else:
                                                util.printcolor(util.RED, "  ❌ Test Case Failed")
                                                exit(0)
                                        util.printcolor(util.YELLOW, "Step 4: send retry counter command check retry count remaining same 5")
                                        Setpinp1.pinGetRetries()
                        elif mode =="withoutpowercyclereset":
                                Setpinp1.newsetpin()
                                
                                pin="123456"
                                wrongpin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                for i in range(3):
                                        response , status=getPINtokenPubkey(mode, wrongpin)
                                        if i== 2:
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
                                
                                util.printcolor(util.YELLOW,f"  Step 2: PIN AUTH IS BLOCKED STATE WITHOUT POWER CYCLE RESET POVIDING CURRECT PIN:{pin}")
                                response , status=getPINtokenPubkey(mode, pin)
                                if response[:2] == "34":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_BLOCKED)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)

                        elif mode =="pinauth.blocked":
                                pin="123456"
                                wrongpin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                for i in range(3):
                                        response , status=getPINtokenPubkey(mode, wrongpin)
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
                                util.printcolor(util.YELLOW,f"  Step 2: PIN AUTH IS BLOCKED STATE WITH POWER CYCLE RESET POVIDING CURRECT PIN:{pin}")
                                util.ResetCardPower()
                                util.ConnectJavaCard()
                                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                                response , status=getPINtokenPubkey(mode, pin)
                                util.printcolor(util.YELLOW, "Step 3: send retry counter command check retry count remaining 8")
                                Setpinp1.pinGetRetries()
                        elif mode =="platformCOSKEY.notmap":
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "11":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)

                        elif mode =="forcepinchange":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                permission = 0x20
                                pinToken, pubkey=getPINtokenPubkeyper(pin,permission)
                                subCommand = 0x03
                                apdu=getpintokenCTAP2_2.newMinPinLength(pinToken,subCommand)
                                response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                                util.APDUhex("80100000010400", "Get Info")
                                response , status=getPINtokenPubkey(mode, pin)
                        elif mode =="forcepinchange.false":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                permission = 0x20
                                pinToken, pubkey=getPINtokenPubkeyper(pin,permission)
                                subCommand = 0x03
                                apdu=getpintokenCTAP2_2.newMinPinLength1(pinToken,subCommand)
                                response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                                util.APDUhex("80100000010400", "Get Info")
                                response , status=getPINtokenPubkey(mode, pin)
                        elif mode =="changingpin":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                permission = 0x20
                                pinToken, pubkey=getPINtokenPubkeyper(pin,permission)
                                subCommand = 0x03
                                apdu=getpintokenCTAP2_2.newMinPinLength(pinToken,subCommand)
                                response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCES)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                                newpin="654321"#newpin
                                response=Setpinp1.changepin(pin,newpin)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCES)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                                util.APDUhex("80100000010400", "Get Info")
                                response , status=getPINtokenPubkey(mode, newpin)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCES)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="forcePINChange.token":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                permission = 0x20
                                pinToken, pubkey=getPINtokenPubkeyper(pin,permission)
                                subCommand = 0x03
                                apdu=getpintokenCTAP2_2.newMinPinLength(pinToken,subCommand)
                                response,status=util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCES)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                                newpin="654321"#newpin
                                response=Setpinp1.changepin(pin,newpin)
                                if response[:2] == "00":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCES)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                                util.run_apdu("80100000010400", "Get Info","00")
                                response , status= getPINtokenPubkey(mode, pin)
                                if response[:2] == "31":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="pinBlocked.Blocked":
                                Setpinp1.newsetpin()
                                pin="654321"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                util.printcolor(util.YELLOW,f" Step 1:Repeat this for 3 incorrect PIN attempts {pin}")
                                for i in range(3):
                                        response , status=getPINtokenPubkey(mode, pin)
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

                                util.printcolor(util.YELLOW,f" Step 2:Power Cycle and Re-Attempt Incorrect PIN Entry{pin}")
                                util.ResetCardPower()
                                util.ConnectJavaCard()
                                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                                for i in range(3):
                                        response , status=getPINtokenPubkey(mode, pin)
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
                                util.printcolor(util.YELLOW,f" Step 3:Verify Retry Counter is 2 or Not")
                                Setpinp1.pinGetRetries()
                                util.printcolor(util.YELLOW,f"Step 4: Power Cycle With  for 2 Incorrect attempts{pin}")
                                util.ResetCardPower()
                                util.ConnectJavaCard()
                                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                                for i in range(2):
                                
                                        response , status=getPINtokenPubkey(mode, pin)
                                        if i==1:
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
                                
                                pin="123456"
                                util.printcolor(util.YELLOW,f"Step 5: Providing Correct PIN {pin}")
                                response , status=getPINtokenPubkey(mode, pin)
                        elif mode =="Allpermission":
                                Setpinp1.newsetpin()
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                Setpinp1.exstingpin(pin)
                                mode="Without.Permission"
                                response , status=getPINtokenPubkey(mode, pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                                
                                mode="Allpermission"
                                response , status=getPINtokenPubkey(mode, pin)
                                if response[:2] == "02":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                        elif mode =="sharesecretprotol2":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                                response , status=getPINtokenPubkey1(mode,pin)
                                if response[:2] == "33":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
                                
                                
                                
                                #Setpinp1.pinGetRetries()
                                #getPINtokenPubkey1new(mode,pin) two share secret

                else:
                        util.run_apdu("00A4040008A0000006472F0001", "Select applet")
                        util.ResetCardPower()
                        util.ConnectJavaCard() 
                        util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                        util.run_apdu("80100000010700", "GetInfo","00")
                        if mode=="withoutsetpin":
                                pin="123456"
                                util.printcolor(util.YELLOW,f"  PIN IS NOT SET: ")
                                response , status=getPINtokenPubkey(mode,pin)
                                if response[:2] == "35":
                                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                                else:
                                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                                        exit(0)
        
        finally:
                DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
                passCount += 1

           
                
         
def getPINtokenPubkey1(mode,pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo","00")

    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:")
    response, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True) #sharesecrte from protocol 2
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:{shared_secret.hex()}")
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    protocol=1
    subcommand=5
    apdu=createGetpinToken(mode,protocol,subcommand,key_agreement,pinHashEnc)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    return response,status




def getPINtokenPubkey1new(mode,pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    
######p2
    util.printcolor(util.YELLOW,f"Providing Protocol2 getKeyAgreement:")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes1    = binascii.unhexlify(cardPublickey[2:])
    decoded_data1  = cbor2.loads(cbor_bytes1)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement1, shareSecretKey1 = util.encapsulate(decoded_data1[1])

#######p1
    util.printcolor(util.YELLOW,f"Providing Protocol1 getKeyAgreement:")
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement2, shared_secret2 = util.encapsulate_protocolP1(peer_key)
##p1
    pin_hash2 = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc2 = util.aes256_cbc_encryptP1(shared_secret2, pin_hash2)
    protocol=1
    subcommand=5
    apdu=createGetpinToken(mode,protocol,subcommand,key_agreement2,pinHashEnc2)
    util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
###p2
    
    pin_hash1    = util.sha256(pin.encode())[:16]
    pinHashEnc1  = util.aes256_cbc_encrypt(shareSecretKey1[32:],pin_hash1)
    
    protocol=2
    subcommand=5
    apdu=createGetpinToken(mode,protocol,subcommand,key_agreement1,pinHashEnc1)
    util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    
    
    #getpintokenCTAP2_2.GetPINtokeninvalidandmissingparm(mode,protocol,subcommand,pinHashEnc, key_agreement1)






    

        




                

def getPINtokenPubkey(mode,pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo","00")

    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    protocol=1
    subcommand=5
    if mode=="invalid.pinUvAuthProtocol":
         protocol=3
         util.printcolor(util.YELLOW,f"  Invalid pinUvAuthProtocol:{protocol}")
    elif mode=="invalid.subcommand":
         subcommand=0
         util.printcolor(util.YELLOW,f"  Invalid Subcommand:{subcommand}")
    elif mode=="invalid.pinHashEnc":
         pinHashEnc = os.urandom(64)
         util.printcolor(util.YELLOW,f"  Invalid pinHashEnc:{pinHashEnc.hex()}")
    elif mode=="invalid.keyAgreement":
         key_agreement, shared_secret = util.invalidcoskey(peer_key)
         pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
         pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
         formatted = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in key_agreement.items()}
         util.printcolor(util.YELLOW,f"  Invalid keyAgreements:{formatted}")
    elif mode =="Without.Permission:":
          util.printcolor(util.YELLOW, "Trying to get the PIN token without giving CM permission")
    elif mode =="wrongpin:":
          util.printcolor(util.YELLOW, "User Giving Wrong pin:{pin}")
    elif mode =="pinauthblocked:":
          util.printcolor(util.YELLOW, "User Giving Wrong pin:{pin}")
    elif mode =="pinblocked:":
          util.printcolor(util.YELLOW, "User Giving Wrong pin:{pin}")
    elif mode =="invalid.sharecrete":
          key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
          shared_secret = os.urandom(32)
          pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
          pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
          util.printcolor(util.YELLOW, f"User Giving Wrong shared secret: {shared_secret.hex()}")
          
    elif mode =="invalid.pinHashEnclength":#
          key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
          pinHashEnc =os.urandom(10) #madatory 16 byte
          
          util.printcolor(util.YELLOW, f"User Giving Wrong pinHashEnc: { pinHashEnc.hex()}")
    elif mode =="platformCOSKEY.notmap":#
          key_agreement, shared_secret = util.encapsulate_protocolkeyP1(peer_key)
          pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
          pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
          util.printcolor(util.YELLOW, f"platformCOSKEY is notmap : { pinHashEnc.hex()}")
    elif mode =="Allpermission":#
          util.printcolor(util.YELLOW, f"Without providing the permission performing the authenticator config")


        
        
    apdu=createGetpinToken(mode,protocol,subcommand,key_agreement,pinHashEnc)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    return response , status


def createGetpinToken(mode,protocol,subcommand,key_agreement,pinHashEnc):
        
        cbor_cose_key= cbor2.dumps(key_agreement).hex().upper()
        cbor_pinHashEnc = cbor2.dumps(pinHashEnc).hex().upper()
        cbor_subcommand = cbor2.dumps(subcommand).hex().upper()
        cbor_protocol   = cbor2.dumps(protocol).hex().upper()
        if mode=="missing.pinUvAuthProtocol":
            util.printcolor(util.YELLOW,f"  Missing pinUvAuthProtocol: ")
            data_cbor = "A3"
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
        elif mode=="missing.subcommand":
            util.printcolor(util.YELLOW,f"  Missing subcommand: ")
            data_cbor = "A3"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
        elif mode=="missing.pinHashenc":
            util.printcolor(util.YELLOW,f"  Missing pinHashEnc: ")
            data_cbor = "A3"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
        elif mode=="missing.keyAgreement":
            util.printcolor(util.YELLOW,f"  Missing keyAgreement: ")
            data_cbor = "A3"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
        elif mode=="Without.Permission":
            permission = 0x04
            cbor_permission   = cbor2.dumps(permission).hex().upper()
            data_cbor = "A5"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
            data_cbor += "09" + cbor_permission                   # cm permission

        elif mode=="Allpermission":
            permission = 0x20
            cbor_permission   = cbor2.dumps(permission).hex().upper()
            data_cbor = "A5"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
            data_cbor += "09" + cbor_permission                   # cm permission


            
            
        else:
            data_cbor = "A4"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc

        length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
        apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
        return apdu


def getPINtokenPubkeyper(curpin,permission):
    util.run_apdu("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =createGetPINtoken1(pinHashEnc,key_agreement,permission)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True)
    if hexstring[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCES)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)

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
         