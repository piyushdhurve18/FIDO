###############protocol1 
import util
import cbor2
import binascii
import os
import random
import getpinuvauthtokenctap2_2
import util
import binascii
import cbor2
import hashlib, hmac, binascii
import cbor2
import os
import struct
import getasserationrequest
import DocumentCreation
RP_domain          = "localhost"
pin="123456"
user="bobsmith"
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "SET PIN"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def authenticatorClientPinP2_2(mode,cardreset):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL
    PROTOCOL = 1
    util.printcolor(util.YELLOW, "****ClientSetPin All The Test Case Scenarios for p1****")

    descriptions = {
        "minimumpin.length": """Test started: P-1 :        
    Precondition: Authenticator must be Reset and has no PIN set.
    Set a PIN using the minimum allowed length, ensuring all command parameters are correct.
    The authenticator should return CTAP2_OK.""",

"maximumpin.length": """Test started : P-2:
 Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.

Step:
Set a PIN using the maximum allowed PIN length, ensuring all command parameters are valid.
Expected Result:
The authenticator returns CTAP2_OK.""",

        "random.pin" :"""Test started: P-3 : 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.
Set a new valid PIN using a random PIN length that falls between the minimum and maximum allowed PIN lengths, ensuring all command parameters are correct.
Expected Result:
The authenticator returns CTAP2_OK.""",

"exting.pin" :"""Test started: P-4 : 
Precondition:
1.The authenticator must be set .
2.Protocol version 1 must be used.
Step:
Perform protected operations—MakeCredential followed by GetAssertion—to verify the newly set PIN.
Ensure that all parameters in the PIN verification commands are valid.

Expected Result:
The authenticator returns CTAP2_OK.""",

"getpin.retries" :"""Test started: P-5 : 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.
Steps:
Step 1: Set a New Valid PIN
Set a new valid PIN after the authenticator reset.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Verify PIN Retry Counter Initialization
Send the getPINRetries command with all parameters correctly provided.
Expected Result: The authenticator returns the maximum allowed PIN retry count.""",
"wrong.pin" :"""Test started: P-6 : 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.
Steps:
Step 1: Retrieve initial PIN retry count
Send the getPINRetries command with all parameters correctly set.
Expected Result: The authenticator returns the maximum allowed PIN retry count.

Step 2: Attempt PIN change with incorrect current PIN
Send the change PIN command using an incorrect current PIN, while ensuring all other parameters are correct.
Expected Result: The authenticator returns an error indicating the PIN is incorrect.

Step 3: Verify retry count decreased
Send getPINRetries again with correct parameters.
Expected Result: The PIN retry count is reduced by one.

Step 4: Reset the authenticator and set a new valid PIN
Perform an authenticator reset.
Set a new valid PIN with all parameters correct.
Expected Result: The authenticator returns CTAP2_OK.

Step 5: Retrieve retry count after reset
Send getPINRetries once more with all parameters correct.
Expected Result: The authenticator returns the maximum allowed PIN retry count, confirming it has been restored.
""",

"pinalreayset" :"""Test started: F-1 : 
Precondition:
1.The authenticator must be set.
2.Protocol version 1 must be used.
Step:
Set  a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",
"pinlengthLess" :"""Test started: F-2 : 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.
Steps:
Step 1: Retrieve minimum PIN length
Use the getInfo command to obtain the authenticator’s minimum PIN length requirement.
Step 2: Set a PIN shorter than the platform minimum (e.g., less than 4 digits)
Attempt to set a PIN that is shorter than 4 digits, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
Step 3: Set a PIN shorter than the minimum length returned by getInfo
Attempt to set a PIN that is shorter than the minimum PIN length obtained in Step 1, ensuring all parameters are correct.
Expected Result: The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"pinlengthexced" :"""Test started: F-3 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.
Step:
Set PIN which is longer than maximum pin length, ensuring all command parameters are correct.
Expected Result:The authenticator returns CTAP2_ERR_INVALID_PARAMETER.""",

"pinnotset" :"""Test started: F-4 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.
Step:
Attempting to retrieve getPINRetries on an authenticator that has not yet had a PIN set. All command parameters are correct. 
Expected Result:The authenticator is expected to return CTAP2_ERR_PIN_NOT_SET.""",

"notpadding" :"""Test started: F-5 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.
Step:
Configure a valid PIN that is shorter than the maximum PIN length but is not padded (for example, use an 16-digit PIN with no padding)
while keeping all other command parameters correct.
Expected Result: The authenticator is expected to return CTAP2_ERR_INVALID_PARAMETER.""",

"noretries" :"""Test started: F-6 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.
Step:
Step 1: Configure a new valid PIN
Set a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_OK.
Step 2: Attempt to change the PIN using an incorrect current PIN
Send the change PIN command with an incorrect current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_INVALID.
Step 3: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters.
Expected Result: The authenticator reports a PIN retry count reduced by one from the maximum allowed retries.""",

"missing.protocol" :"""Test started: F-7 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN while omitting the pinUvAuthProtocol parameter.
Expected Result: The authenticator must return CTAP2_ERR_MISSING_PARAMETER.""",

"missing.subcommand" :"""Test started: F-8 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.
Step:
Attempt to set a new valid PIN while omitting the subCommand (setPIN 0x03).
Expected Result: The authenticator must return CTAP2_ERR_MISSING_PARAMETER.""",

"missing.keyAgreement" :"""Test started: F-9 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN while omitting the keyAgreement.
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"missing.newPinEnc" :"""Test started: F-10 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN while omitting the newPinEnc.
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"missing.pinUvAuthParam" :"""Test started: F-11 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN while omitting the pinUvAuthParam
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"Invalid.pinUvAuthProtocol" :"""Test started: F-12 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN Invalid pinUvAuthProtocol data and other parameter data should correct/valid
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"Invalid.subCommand" :"""Test started: F-13 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN Invalid subCommand (setPIN 0x03) and other parameter data should correct/valid
Expected Result:The authenticator returns  CTAP2_ERR_INVALID_SUBCOMMAND.""",

"Invalid.keyAgreement" :"""Test started: F-14 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid keyAgreement value.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",


"Invalid.newPinEnc" :"""Test started: F-15 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid newPinEnc value.
Expected Result: The authenticator should return CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"Invalid.pinUvAuthParam" :"""Test started: F-16 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid pinUvAuthParam value.
Expected Result: The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",



"Invalid.pinUvAuthParamlength" :"""Test started: F-17 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid pinUvAuthParam valuelength(must be 16 byte).
Expected Result: The authenticator should return CTAP1_ERR_INVALID_LENGTH.""",

"Invalid.newPinEnclength" :"""Test started: F-26 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid .newPinEnclength.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"paddedPin.invalid" :"""Test started: F-18 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Perform set PIN operation when paddedNewPin  is not 64 bytes in length, ensuring all remaining parameters are correct/valid.
Expected Result:The authenticator  returns CTAP1_ERR_INVALID_PARAMETER.""",

"without.paddedPin" :"""Test started: F-19 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Perform the setPIN operation using a validPIN PIN length that falls between the minimum and maximum allowed PIN lengths but  without any padding.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"paddedPininvalid" :"""Test started: F-20 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt a setPIN operation where paddedNewPin is exactly 64 bytes in length, but the padding content is intentionally malformed (e.g., the buffer is 64 bytes long but contains incorrect or corrupted data in the middle). ensuring all remaining parameters are correct/valid.
The authenticator is expected to detects the incorrect length and returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",
"Hmacreuse" :"""Test started: F-21 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Perform a setPIN operation to generate a valid newPinEnc and HMAC, and keep them for future use.
Attempt to set a new valid PIN using the setPIN (0x03) command but reuse the HMAC from the previous attempt. 
The authenticator should fail because the shared secret has changed. 
Expected Result: The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",


"alphanumeric.pin" :"""Test started: F-22 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Set a PIN using the valid PIN value that includes alphanumeric characters, ensuring all command parameters are correct.
The authenticator should return CTAP2_OK.""",

"specialchar.pin" :"""Test started: F-23 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Set a PIN using the valid PIN value that includes specialchar pin  ensuring all command parameters are correct.
The authenticator should return CTAP2_OK.""",


"randompin.continuess" :"""Test started: F-24 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Set a new valid PIN multiple times, each time continuously increasing the PIN length, ensuring the length always remains within the allowed minimum and maximum limits. All command parameters must be valid for each attempt.

Expected Result:
For every valid PIN length, the authenticator should successfully accept the PIN and return CTAP2_OK..""",

"pinauthnotbyte" :"""Test started: P-4 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Set a PIN using the valid PIN value that includes alphanumeric characters, ensuring all command parameters are correct.
The authenticator should return CTAP2_OK.""",

"keyagrrremntnotmap" :"""Test started: F-24: 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Set a PIN using the valid PIN , ensuring all command parameters are correct but keyagrremnt is not a map.
The authenticator should return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"withoutpowercycle" :"""Test started: P-6 : 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.
Steps:
Step 1: Configure a new valid PIN
Set a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Attempt to change the PIN using an incorrect current PIN
Send the change PIN command with an incorrect current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.

Step 3: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters.
Expected Result: The authenticator reports a PIN retry count reduced by one from the maximum allowed retries.
Step 4: Attempt to change the PIN using an correct current PIN without power cycle.
Send the change PIN command with an correct current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.
Step 5: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters but retries count should be decress.
""",

"withpowercycle" :"""Test started: f-25: 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 1 must be used.
Steps:
Step 1: Configure a new valid PIN
Set a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Attempt to change the PIN using an incorrect current PIN
Send the change PIN command with an incorrect current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.

Step 3: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters.
Expected Result: The authenticator reports a PIN retry count reduced by one from the maximum allowed retries.
Step 4: Attempt to change the PIN using an correct current PIN with power cycle.
Send the change PIN command with an  incorrect  PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_BLOCKED.
Step 5: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters but retries count should be decress.
""",

"protocol.keypair" :"""Test started: f-26 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Set a new valid PIN using a Valid  PIN length that falls between the minimum and maximum allowed PIN lengths,but keyagreement wii generated by protocol 1 but setPin command will send by protocol 2 and  all other command parameters are correct.
Expected Result:
The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",


    }


    if mode not in descriptions:
            raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------------------------------
    #  CARD RESET IS OPTIONAL (Controlled by cardreset flag)
    # ------------------------------------------------------
    try:
        scenarioCount += 1
        if str(cardreset).lower() == "yes":        # 
            util.ResetCardPower()
            util.ConnectJavaCard() 
            util.run_apdu("00a4040008a0000006472f0001", "Select applet")
            util.APDUhex("80100000010700", "Reset Card PIN")
            
            if mode == "minimumpin.length":
                pin="123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpin(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 

            elif mode == "maximumpin.length":
                pin="1"*63
                response=setpin(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "random.pin":
                pin = f"{random.randint(0, 12345678):08d}"
                response=setpin(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                
            elif mode == "getpin.retries":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpin(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

                util.printcolor(util.YELLOW,f"Step 2: Verify PIN retry counter initialization ")
                pinGetRetries()
            elif mode == "pinlengthLess":
                pin="123"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"Step 1: Retrieve minimum PIN length")
                util.APDUhex("80100000010400", "GetInfo")
                util.printcolor(util.YELLOW,f"Step 2:Set a PIN shorter than the platform minimum (e.g., less than 4 digits)")
                response=setpin(mode,pin)
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f"Step 3: Set a PIN shorter than the minimum length returned by getInfo")
                util.APDUhex("80100000010400", "GetInfo")
                pin="12345"
                response=setpin(mode,pin)
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinlengthexced":
                pin = "1"*65
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpin(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "protocol.keypair":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinkeypair2(mode,pin)
                if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinnotset":
                util.printcolor(util.YELLOW, f"  Without setting pin attempt to GetRetries")
                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                response,status=util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                if response[:2] == "35":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "notpadding":
                pin = "1234567890123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW, f"  Without padding attempt to set pin")
                response=setpin(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "noretries":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f" Step 1: Configure a new valid PIN")                      
                response=setpin(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f" Step 2: Attempt to change the PIN using an incorrect current PIN") 
                wrongpin="654321"
                response=changepin(wrongpin,pin)
                if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

                util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count") 
                pinGetRetries()
            elif mode == "missing.protocol":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode == "missing.subcommand":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "missing.keyAgreement":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "missing.newPinEnc":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "missing.pinUvAuthParam":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "Invalid.pinUvAuthProtocol":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "Invalid.subCommand":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "3E":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_INVALID_SUBCOMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "Invalid.keyAgreement":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode == "Invalid.newPinEnc":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode == "Invalid.pinUvAuthParam":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode == "Invalid.pinUvAuthParamlength":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "03":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_LENGTH)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "Invalid.newPinEnclength":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "paddedPin.invalid":
                pin = "12345698"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "without.paddedPin":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin) 
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "paddedPininvalid":#paddedblockcorrpted
                pin = "12345698"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin) 
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)  
            elif mode == "Hmacreuse":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)   
                if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            
            elif mode == "alphanumeric.pin":
                pin = "ABCDEF"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin) 
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "specialchar.pin":
                pin = "123@11"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin) 
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 
            elif mode == "randompin.continuess":
                pin_length=6
                for i in range(5): 
                    util.ResetCardPower()
                    util.ConnectJavaCard() 
                    randompin = ''.join(str(random.randint(0, 9)) for _ in range(pin_length))
                    util.printcolor(util.YELLOW,f"  PIN IS: {randompin}")
                    response=continuesssetpin(mode,randompin) 
                    if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)  
                    pin_length+=1
            elif mode == "pinauthnotbyte":
                
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
            elif mode == "keyagrrremntnotmap":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=setpinInvalidmode(mode,pin)
            elif mode == "withoutpowercycle":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f" Step 1: Configure a new valid PIN")                      
                response=setpin(mode,pin)
                util.printcolor(util.YELLOW,f" Step 2: Attempt to change the PIN using an incorrect current PIN") 
                wrongpin="654321"
                for i in range(3):
                    changepin(wrongpin,pin)
                
                util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count") 
                pinGetRetries()
                util.printcolor(util.YELLOW,f" Step 4: Repeat the correct  PIN command without power cycle reset") 
                
                changepin(pin,wrongpin)
                pinGetRetries()

            elif mode == "withpowercycle":
                pin = "123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f" Step 1: Configure a new valid PIN")                      
                setpin(mode,pin)
                
                util.printcolor(util.YELLOW,f" Step 2: Attempt to change the PIN using an incorrect current PIN") 
                wrongpin="765432"
                for i in range(8):
                    

                    changepin(wrongpin,pin)
                    util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count") 
                    pinGetRetries()
                
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

            

            
        else:
            if mode=="exting.pin":
                pin="123456"
                exstingpin(pin)
            elif mode=="wrong.pin":
                pin="123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 1: Retrieve initial PIN retry count")
                pinGetRetries()
                util.printcolor(util.YELLOW,f"  Step 2: Attempt to change the PIN with an incorrect current PIN")
                wrongpin="654321"
                response=changepin(wrongpin,pin)
                if response[:2] == "31":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f"  Step 3: Verify retry count decreases")
                pinGetRetries()
                util.printcolor(util.YELLOW,f"  Step 4: Reset the authenticator and set a new valid PIN")
                util.ResetCardPower()
                util.ConnectJavaCard() 
                util.run_apdu("00a4040008a0000006472f0001", "Select applet")
                util.APDUhex("80100000010700", "Reset Card PIN")
                response=setpin(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f"  Step 5: Retrieve retry count after reset")
                pinGetRetries()
            elif mode=="pinalreayset":
                pin="123456"
                response=setpin(mode,pin)
                if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
        

        

        
def changepin(pin,newpin):
    response, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
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

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response

def createCBORchangePIN_protocol1(pinHashEnc, newPINenc, pinAuth, keyAgreement):
    """
    Constructs a CBOR-encoded APDU command for ClientPIN ChangePIN (subCommand = 0x04)
    """
    cbor_map = {
        1: 1,               # pinProtocol = 1
        2: 4,               # subCommand = 0x04 (change PIN)
        3: keyAgreement,    # keyAgreement (MAP)
        4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
        5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
        6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
    }

    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()+"00"
    return apdu



def setpin(mode,pin):

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocol1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False) 
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
    print("new_pin_enc",new_pin_enc.hex())
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    if mode == "minimumpin.length":
        util.printcolor(util.YELLOW, f"Minimum PIN length: {pin}")
    elif mode == "maximumpin.length":
        util.printcolor(util.YELLOW, f"Maximum PIN length: {pin}")
    elif mode == "random.pin":
         util.printcolor(util.YELLOW, f"Random PIN: {pin}")
    elif mode == "getpin.retries":
        util.printcolor(util.YELLOW,f"****Step 1: Set a new valid PIN*****")
    elif mode == "wrong.pin":
        util.printcolor(util.YELLOW,f"PIN IS:{pin}")
    elif mode=="pinalreayset":
        util.printcolor(util.YELLOW,f"PIN Already Set:{pin}")
    elif mode=="pinlengthLesst":
        util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
    elif mode == "notpadding":
        raw_pin = pin.encode() 
        util.printcolor(util.YELLOW, f"  Without paddingt pin:{raw_pin}")
        new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, raw_pin)
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes


         
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response

def setpinkeypair2(mode,pin):

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocol1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False) 
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response

def setpinInvalidmode(mode,pin):

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocol1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False) 
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    subCommand = 3 
    pinProtocol = 1
    if mode ==  "Invalid.pinUvAuthProtocol":
        pinProtocol = 4
    elif mode ==  "Invalid.subCommand":
        subCommand = 0
    elif mode ==  "Invalid.keyAgreement":
        key_agreement[-2] = b"\xAA" * 32
        padded_pin = util.pad_pin_P1(pin, validate=False) 
        new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes
    elif mode == "Invalid.newPinEnc":
        new_pin_enc = os.urandom(64)
        util.printcolor(util.YELLOW, f" Invalid.newPinEnc :{new_pin_enc.hex()}")
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes 

    elif mode ==  "Invalid.pinUvAuthParam":
        pin_auth = b"\x00" * 16#wrong
        util.printcolor(util.YELLOW, f" Invalid.pinUvAuthParam :{pin_auth.hex()}")
    elif mode ==  "Invalid.pinUvAuthParamlength":
        pin_auth = auth[:10]
        util.printcolor(util.YELLOW, f" Invalid.pinUvAuthParamlength :{pin_auth.hex()}")
    elif mode == "Invalid.newPinEnclength":
        new_pin_enc = os.urandom(10)
        util.printcolor(util.YELLOW, f" Invalid.newPinEnc :{new_pin_enc.hex()}")
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes 
    elif mode == "paddedPin.invalid":
        # padded_pin = util.pad_pin_P1Lengthnot(pin, validate=False) 
        # util.printcolor(util.YELLOW, f" padded_pin Length Invalid :{padded_pin.hex()}")
        # new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
        # auth = util.hmac_sha256P1(shared_secret, new_pin_enc)

        # newPinEnc  = util.aes256_cbc_encryptWrongLengthPaddedPIN(shared_secret, util.pad_pin_with_expected_length(pin, 32))
        # #Fido Alliance says to pad the PIN with 0x00 for 64 length
        # auth       = util.hmac_sha256P1(shared_secret, newPinEnc ) # always 32 byte result
        # pin_auth = auth[:16] 

        new_pin_enc = util.aes256_cbc_encryptWrongLengthPaddedPIN(shared_secret, util.pad_pin_with_expected_length(pin, 80))
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes
    elif mode == "without.paddedPin":
        newpin = pin.encode()
  
        util.printcolor(util.YELLOW, f" Without padded_pin :{util.toHex(newpin)}")
        new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, newpin)
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16] 
    elif mode == "paddedPininvalid":
        padded_pin = util. wrongPad_pinP1(pin, validate=False) 
        new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes

    elif mode == "Hmacreuse":
        response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
        cbor_bytes = binascii.unhexlify(response[2:])
        decoded = cbor2.loads(cbor_bytes)
        key_agreement1, shared_secret1 = util.encapsulate_protocol1(decoded[1])
        
        padded_pin = util.pad_pin_P1(pin, validate=False) 
        new_pin_enc = util.aes256_cbc_encryptP1(shared_secret1, padded_pin)
        auth = util.hmac_sha256P1(shared_secret1, new_pin_enc)
        pin_auth1 = auth[:16]  # only first 16 bytes
        auth1=auth[:16]
        pin_auth=auth1
    elif mode == "alphanumeric.pin":
        util.printcolor(util.YELLOW, f"Alphanumeric PIN :{pin}")
    elif mode == "specialchar.pin":
        util.printcolor(util.YELLOW, f"Special char PIN :{pin}")
    elif mode == "pinauthnotbyte":
        
        pin_auth = auth[:16]  # only first 16 bytes
        #here i want what ever value is coming pin_auth convert to int 
        # Convert the bytes to an integer → INVALID for CTAP ClientPIN
        pin_auth = int.from_bytes(pin_auth, byteorder="big")
    elif mode == "keyagrrremntnotmap":
        key_agreement, shared_secret = util.keyarray(decoded[1])
        padded_pin = util.pad_pin_P1(pin, validate=False) 
        new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
        auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
        pin_auth = auth[:16]  # only first 16 bytes
        

        

    



    


    apdu = missingandinvalidParam_CBOR(mode,new_pin_enc, pin_auth, key_agreement,subCommand,pinProtocol)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response


def continuesssetpin(mode,pin):

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010700", "Reset Card PIN")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocol1(decoded[1])
    padded_pin = util.pad_pin_P1(pin, validate=False) 
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    subCommand = 3 
    pinProtocol = 1
    apdu = missingandinvalidParam_CBOR(mode,new_pin_enc, pin_auth, key_agreement,subCommand,pinProtocol)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response

def pinGetRetries():
    
    response, status =util.APDUhex("801000000606A20102020100", "Client PIN GetRetries", checkflag=True)
    cbor_data = cbor2.loads(binascii.unhexlify(response[2:])) 
    pin_retries = cbor_data[0x03]
    if not isinstance(pin_retries, int):
        util.printcolor(util.RED, f"'pinRetries' is not a number. Got type: {type(pin_retries)}")
        return
    if pin_retries > 8:
        util.printcolor(util.RED, f" Invalid 'pinRetries': {pin_retries}. Maximum allowed is 8.")
        return
    util.printcolor(util.GREEN, f"✅ Test Passed: pinRetries = {pin_retries}")

    
        
def create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement):
    cose_key = cbor2.dumps(key_agreement).hex().upper()
    cbor_newpin = cbor2.dumps(new_pin_enc).hex().upper()
    cbor_auth = cbor2.dumps(pin_auth).hex().upper()

    data_cbor = "A5"
    data_cbor += "01" + "01"            # pinProtocol = 1
    data_cbor += "02" + "03"            # subCommand = 3 (SetPIN)
    data_cbor += "03" + cose_key        # keyAgreement
    data_cbor += "04" + cbor_auth       # pinAuth
    data_cbor += "05" + cbor_newpin     # newPinEnc

    length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
    return apdu


def missingandinvalidParam_CBOR(mode,new_pin_enc, pin_auth, key_agreement,subCommand,pinProtocol):
    cose_key = cbor2.dumps(key_agreement).hex().upper()
    cbor_newpin = cbor2.dumps(new_pin_enc).hex().upper()
    cbor_auth = cbor2.dumps(pin_auth).hex().upper()
    cbor_subCommand= cbor2.dumps(subCommand).hex().upper()
    cbor_pinProtocol= cbor2.dumps(pinProtocol).hex().upper()
    if mode == "missing.protocol":
        util.printcolor(util.YELLOW, f"  Missing The Protocol P1")
        data_cbor = "A4"
        data_cbor += "02" + cbor_subCommand             # subCommand = 3 (SetPIN)
        data_cbor += "03" + cose_key                    # keyAgreement
        data_cbor += "04" + cbor_auth                   # pinAuth
        data_cbor += "05" + cbor_newpin                 # newPinEnc
    elif mode == "missing.subcommand":
        util.printcolor(util.YELLOW, f"  Missing The Subcommand")
        data_cbor = "A4"
        data_cbor += "01" + cbor_pinProtocol                       # pinProtocol = 1
        data_cbor += "03" + cose_key                               # keyAgreement
        data_cbor += "04" + cbor_auth                              # pinAuth
        data_cbor += "05" + cbor_newpin                            # newPinEnc
    elif mode == "missing.keyAgreement":
        util.printcolor(util.YELLOW, f"  Missing The keyAgreement")
        data_cbor = "A4"
        data_cbor += "01" + cbor_pinProtocol                       # pinProtocol = 1
        data_cbor += "02" + cbor_subCommand                        # subCommand = 3 (SetPIN)
        data_cbor += "04" + cbor_auth                              # pinAuth
        data_cbor += "05" + cbor_newpin                            # newPinEnc
    elif mode == "missing.newPinEnc":
        util.printcolor(util.YELLOW, f"  Missing The newPinEnc")
        data_cbor = "A4"
        data_cbor += "01" + cbor_pinProtocol                                # pinProtocol = 1
        data_cbor += "02" + cbor_subCommand                                 # subCommand = 3 (SetPIN)
        data_cbor += "03" + cose_key                                        # keyAgreement
        data_cbor += "04" + cbor_auth                                       # pinAuth
    elif mode == "missing.pinUvAuthParam":
        util.printcolor(util.YELLOW, f"  Missing The pinUvAuthParam")
        data_cbor = "A4"
        data_cbor += "01" + cbor_pinProtocol                       # pinProtocol = 1
        data_cbor += "02" + cbor_subCommand                        # subCommand = 3 (SetPIN)
        data_cbor += "03" + cose_key                               # keyAgreement
        data_cbor += "05" + cbor_newpin                            # newPinEnc

    elif mode == "pinauthnotbyte":
        cbor_auth1="sasmitaaaaaaaaaa"
        cbor_auth = cbor2.dumps(cbor_auth1).hex().upper()
        util.printcolor(util.YELLOW, f"  Missing The pinUvAuthParam:{cbor_auth}")
        data_cbor = "A5"
        data_cbor += "01" + cbor_pinProtocol                       # pinProtocol = 1
        data_cbor += "02" + cbor_subCommand                        # subCommand = 3 (SetPIN)
        data_cbor += "03" + cose_key                               # keyAgreement
        data_cbor += "04" + cbor_auth  
        data_cbor += "05" + cbor_newpin                            # newPinEnc
    else:  
        data_cbor = "A5"
        data_cbor += "01" + cbor_pinProtocol           # pinProtocol = 1
        data_cbor += "02" + cbor_subCommand            # subCommand = 3 (SetPIN)
        data_cbor += "03" + cose_key                   # keyAgreement
        data_cbor += "04" + cbor_auth                  # pinAuth
        data_cbor += "05" + cbor_newpin                # newPinEnc
        if mode=="Invalid.pinUvAuthProtocol":
            util.printcolor(util.YELLOW, f"  Invalid pinProtocol:{pinProtocol}")
        elif mode ==  "Invalid.subCommand":
             util.printcolor(util.YELLOW, f"  Invalid subCommand:{subCommand}")
        elif mode ==  "Invalid.keyAgreement":
            util.printcolor(util.YELLOW, f"  Invalid keyAgreement:{key_agreement}")
        elif mode ==  "Invalid.pinUvAuthParam":
            util.printcolor(util.YELLOW, f"  Invalid pinUvAuthParam:{pin_auth.hex()}")
        elif mode ==  "Invalid.pinUvAuthParamlength":
            util.printcolor(util.YELLOW, f"  Invalid pinUvAuthParam:{pin_auth.hex()}")



    length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
    return apdu

def exstingpin(pin):
    clientDataHash=os.urandom(32)
    util.run_apdu("00a4040008a0000006472f0001","Select applet")
    util.run_apdu("80100000010400","GetInfo")  
    pinToken = getPINtokenPubkey(pin)

    pinAuthToken = util.hmac_sha256P1(pinToken, clientDataHash)[:16]
    makeCredAPDU = createCBORmakeCred(clientDataHash, RP_domain, user, pinAuthToken);
    response,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    if response[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)
    credId =authParasing(response)
    hashchallenge = os.urandom(32)
    response = authentication(pin, hashchallenge, RP_domain, credId)
    return response
    

def authentication(curpin, clientDataHash, rp, credId):
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    pinToken = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId)
    response, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return response

    

def getPINtokenPubkey(pin):
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010400", "GetInfo","00")

    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if response[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)
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
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    if response[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = util.aes256_cbc_decryptP1(shared_secret, enc_pin_token)
    return pin_token


def authParasing(response):
    print("response",response)
    authdata=extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info = parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credid",credentialId)
    return credentialId

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




def createCBORmakeCred(clientDataHash, rp, user, pinAuthToken):

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
        },
        
    ]

    option  = {"rk": False}

    extension={"credProtect": 1, 
                "hmac-secret": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()

    ex                = cbor2.dumps(extension).hex().upper()

    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    

    dataCBOR = dataCBOR + "06" + ex
    dataCBOR = dataCBOR + "07" + rk

    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "01" + dataCBOR+"00"
    return APDUcommand

def newsetpin():
    pin="123456"
    
    util.run_apdu("00a4040008a0000006472f0001", "Select Applet")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.run_apdu("80100000010700", "Reset Card PIN (optional)","00")
    util.run_apdu("00a4040008a0000006472f0001", "Re-select Applet")
    util.run_apdu("80100000010400", "GetInfo","00")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocolP1(decoded[1])
    padded_pin = util.pad_pin_P1("123456", validate=False)  # skips min length check
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    if response[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)


    util.run_apdu("80100000010400", "GetInfo after SetPIN","00")



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
    pin_protocol       = "01"                                        # 0x07: pinProtocol = 1

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





            


