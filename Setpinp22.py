import util
import cbor2
import binascii
import os
import random
import getpinuvauthtokenctap2_2
import DocumentCreation
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "SET PIN"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

RP_domain          = "localhost"
pin="123456"
user="bobsmith"
def new():
    pin="123456"
    setpinnew(pin)




def authenticatorClientPinP2_2(mode,cardreset):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL

    PROTOCOL = 2
    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
       "minimumpin.length": """Test started: P-1 :        
Precondition: Authenticator must be Reset and has no PIN set.
Set a PIN using the minimum allowed length, ensuring all command parameters are correct.
The authenticator should return CTAP2_OK.""",


        "maximumpin.length": """Test started : P-2:
Precondition: Authenticator must be Reset and has no PIN set.
Set a PIN using the maximum allowed length, ensuring all command parameters are correct. 
The authenticator should return CTAP2_OK..""",

    "random.pin" :"""Test started: P-3 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Set a new valid PIN using a random PIN length that falls between the minimum and maximum allowed PIN lengths, ensuring all command parameters are correct.
Expected Result:
The authenticator returns CTAP2_OK..""",

"randompin.continuess" :"""Test started: P-3 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Set a new valid PIN using a random PIN length that falls between the minimum and maximum allowed PIN lengths, ensuring all command parameters are correct.
Expected Result:
The authenticator returns CTAP2_OK..""",

"randompin.exccedlength" :"""Test started: F-1 : 
Precondition:
The authenticator must be fully reset and have no PIN configured.
Protocol version 2 must be used.
Step:
Set a new valid PIN using a randomly generated PIN whose length falls within the allowed minimum and maximum PIN length limits. After setting the PIN, verify it by performing MakeCredential and GetAssertion operations using the new PIN, ensuring all command parameters are valid.
Additionally, attempt to set a PIN that exceeds the maximum allowed PIN length and confirm that the authenticator rejects it.
Expected Result:The authenticator return CTAP1_ERR_INVALID_PARAMETER.""",

"alphanumeric.pin" :"""Test started: P-4 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 2 must be used.

Step:
Set a PIN using the valid PIN value that includes alphanumeric characters, ensuring all command parameters are correct.
The authenticator should return CTAP2_OK.""",


"specialchar.pin" :"""Test started: P-5 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Set a new valid PIN using a specialcharator  PIN length that falls between the minimum and maximum allowed PIN lengths, ensuring all command parameters are correct.
Expected Result:
The authenticator returns CTAP2_OK..""",


        "exting.pin": """Test started: P-4:
Precondition: A new valid PIN must be set.
Step:
Scenario Step: Initiate a protected operation— makeCredential and authentication (getAssertion)—to verify the newly set PIN.
Ensure that all parameters in the PIN verification command are correct.
Expected Result: The authenticator returns CTAP2_OK.""",

        "getpin.retries" :"""Test started: P-5 :
Precondition:The authenticator must be reset.
Step:
Step 1: Set a new valid PIN
Set a new valid PIN after the authenticator reset.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Verify PIN retry counter initialization
Use the getPINRetries command with all parameters correct.
Expected Result: The authenticator reports the maximum allowed PIN retry count.""",


    "wrong.pin": """Test started: P-6:
Precondition:A new PIN has already been set on the authenticator.

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

"pinalreayset": """Test started: F-1:
Precondition: Authenticator has already PIN set.
Set  a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",



"pinlengthLess" :""""Test started: F-2 :
Precondition:The authenticator must be reset and must not have any PIN set.
Step 1: Retrieve minimum PIN length
Use the getInfo command to obtain the authenticator’s minimum PIN length requirement.
Step 2: Set a PIN shorter than the platform minimum (e.g., less than 4 digits)
Attempt to set a PIN that is shorter than 4 digits, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
Step 3: Set a PIN shorter than the minimum length returned by getInfo
Attempt to set a PIN that is shorter than the minimum PIN length obtained in Step 1, ensuring all parameters are correct.
Expected Result: The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

        "pinlengthexced" :"""Test started: F-3 :
Precondition:The authenticator must be reset and must not have any PIN set.
Set PIN which is longer than maximum pin length, ensuring all command parameters are correct.
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",
#added     
    "newpin": """Test started: F-4:
Precondition: Authenticator already has a PIN set.
Attempt SetPIN command again with a new PIN.Since a PIN is already set, authenticator must return CTAP2_ERR_PIN_AUTH_INVALID."""  ,  
#

    "pinnotset":"""Test started: F-4:
Precondition: Authenticator must be Reset and has no PIN set.
Step:
Attempting to retrieve getPINRetries on an authenticator that has not yet had a PIN set. All command parameters are correct. 

Expected Result:The authenticator is expected to return CTAP2_ERR_PIN_NOT_SET.""",

    "notpadding":"""Test started: F-5:
Precondition: Authenticator must be Reset and has no PIN set.
Step:
Configure a valid PIN that is shorter than the maximum PIN length but is not padded (for example, use an 16-digit PIN with no padding)
while keeping all other command parameters correct.
Expected Result: The authenticator is expected to return CTAP1_ERR_INVALID_PARAMETER.""",

    "noretries": """Test started: F-6:
Precondition:
The authenticator must be reset and must not have any PIN set.
Step 1: Configure a new valid PIN
Set a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_OK.
Step 2: Attempt to change the PIN using an incorrect current PIN
Send the change PIN command with an incorrect current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID.
Step 3: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters.
Expected Result: The authenticator reports a PIN retry count reduced by 3 from the maximum allowed retries.""",

"missing.protocol":"""Test started: F-7:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN while omitting the pinUvAuthProtocol parameter.
Expected Result: The authenticator must return CTAP2_ERR_MISSING_PARAMETER.""",


"missing.subcommand":"""Test started: F-8:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN while omitting the subCommand (setPIN 0x03).
Expected Result: The authenticator must return CTAP2_ERR_MISSING_PARAMETER.""",

"missing.keyAgreement":"""Test started: F-9:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN while omitting the keyAgreement.
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"missing.newPinEnc":"""Test started: F-10:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN while omitting the newPinEnc.
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",


"missing.pinUvAuthParam":"""Test started: F-11:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN while omitting the pinUvAuthParam
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",


"Invalid.pinUvAuthProtocol":"""Test started: F-12:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN Invalid pinUvAuthProtocol data and other parameter data should correct/valid
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"Invalid.subCommand":"""Test started: F-13:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN Invalid subCommand (setPIN 0x03) and other parameter data should correct/valid
Expected Result:The authenticator returns  CTAP1_ERR_INVALID_PARAMETER.""",


"Invalid.subCommand":"""Test started: F-14:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN Invalid subCommand (setPIN 0x03) and other parameter data should correct/valid
Expected Result:The authenticator returns  CTAP1_ERR_INVALID_COMMAND.""",

"Invalid.keyAgreement":"""Test started: F-15:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid keyAgreement value.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"Invalid.newPinEnc":"""Test started: F-16:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid newPinEnc value.
Expected Result: The authenticator should return CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"Invalid.pinUvAuthParam":"""Test started: F-17:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid pinUvAuthParam value.
Expected Result: The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",


"Invalid.pinUvAuthParamlength":"""Test started: F-18:
Precondition: The authenticator must be reset and must not have a PIN configured.
Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid pinUvAuthParam length(must be 32 byte).
Expected Result: The authenticator should return CTAP1_ERR_INVALID_LENGTH.""",


"Invalid.newPinEnclength" :"""Test started: F-26 :
Precondition:
1.The authenticator must be reset and must not have any PIN set..
2.Protocol version 1 must be used.

Step:
Attempt to set a new valid PIN using the setPIN (0x03) subcommand, with all other parameter data correctly provided, but with an invalid .newPinEnclength.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

    "invalid.param":"""Test started: F-9:
Precondition: Authenticator must be Reset and has no PIN set.
Configure a new valid PIN, making sure one of the mandatory command parameter is incorrect. 
The authenticator should respond with CTAP1_ERR_INVALID_PARAMETER.""", 

    "protocolnotsupported":"""Test started: F-10:
Precondition: Authenticator must be Reset and has no PIN set.
Attempt to set a new valid PIN, ensuring all command parameters are correct. 
However, during the setPIN operation, provide an unsupported pinUvAuthProtocol value (for example, 3,
when the authenticator only supports protocols 1 and 2). The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

   "subcomanndnotsupported":"""Test started: F-11:
   Precondition: Authenticator must be Reset and has no PIN set.
Attempt to set a new valid PIN. However, during the setPIN operation, provide an invalid setPIN subcommand value (for example, 0x0A). 
The authenticator should return CTAP1_ERR_INVALID_COMMAND.""",


    "keyAgreement.invalid": """Test started: F-12:
precondition: Authenticator must be Reset and has no PIN set.
Attempt to set a new valid PIN. However, during the setPIN operation, supply an invalid keyAgreement value 
(e.g., a public key using the wrong curve, invalid coordinates, or random bytes). When the authenticator attempts decapsulation,
it should return CTAP1_ERR_INVALID_PARAMETER.""", 

    "validkeyAgreement":"""Test started: p-8:
Precondition: Authenticator must be Reset and has no PIN set.
Attempt to set a new valid PIN, ensuring all command parameters are correct. During the setPIN operation, 
provide a valid keyAgreement value (e.g., a public key on the correct curve with valid coordinates). 
The authenticator should correctly compute the shared secret. Verify the resulting HMAC. (Verification must be successful).""",

    "hmac.notmatch":"""Test started: F-13:
Precondition: Authenticator must be Reset and has no PIN set.
During the setPIN operation, tamper with the newPinEnc ciphertext when verifying pinUvAuthParam (HMAC). 
For example, the platform generates a valid encrypted newPinEnc, then flips a byte to alter the ciphertext. 
The authenticator will verify the HMAC using the shared secret, and because the HMAC will not match, it must return CTAP2_ERR_PIN_AUTH_INVALID..""",

    "pinauth.invalid":"""Test started: F-14:
Precondition: Authenticator must be Reset and has no PIN set.
During the setPIN operation, generate a valid newPinEnc, but provide a modified pinUvAuthParam (HMAC) 
when verifying (e.g., alter 2–3 bytes of the HMAC). Since the HMAC is invalid, 
the authenticator should detect it as a signature mismatch and return CTAP2_ERR_PIN_AUTH_INVALID.""",



    "paddedPin.invalid":"""Test started: F-18:
Precondition: Authenticator must be Reset and has no PIN set.
Perform set PIN operation when paddedNewPin  is not 64 bytes in length, ensuring all remaining parameters are correct/valid.
Expected Result:The authenticator  returns CTAP1_ERR_INVALID_PARAMETER.""",


"paddedPininvalid":"""Test started: F-15:
Precondition: Authenticator must be Reset and has no PIN set.
Perform set PIN operation when paddedNewPin  is 64 bytes in length, but while making the padded pin data not correct ensuring all remaining parameters are correct/valid.
The authenticator is expected to detects the incorrect length and returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

    "without.paddedPin":"""Test started: F-16:
Precondition: Authenticator must be Reset and has no PIN set.
Perform the setPIN operation using a    validPIN PIN length that falls between the minimum and maximum allowed PIN lengths but  without any padding.
Expected Result: The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",
   
   "Hmacreuse":"""Test started: F-17:
Precondition: The authenticator must be reset and have no PIN set. 
Perform a setPIN operation to generate a valid newPinEnc and HMAC, and keep them for future use.
Attempt to set a new valid PIN using the setPIN (0x03) command but reuse the HMAC from the previous attempt. 
The authenticator should fail because the shared secret has changed. 
Expected Result: The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.""",


"keyagreement.notmap" :"""Test started: P-3 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Set a new valid PIN using a valid pin but keyagreeemnt not map Expected Result:
The authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE.""",


"withoutpowercycle" :"""Test started: P-6 : 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 2 must be used.
Steps:
Step 1: Configure a new valid PIN
Set a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Attempt to change the PIN using an incorrect current PIN
Send the change PIN command with an incorrect current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_INVALID.

Step 3: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters.
Expected Result: The authenticator reports a PIN retry count reduced by one from the maximum allowed retries.
Step 4: Attempt to change the PIN using an correct current PIN without power cycle.
Send the change PIN command with an correct current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED.
Step 5: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters but retries count should be decress.
""",


"withpowercycle" :"""Test started: f-7: 
Precondition:
1.The authenticator must be fully reset and must not have any PIN configured.
2.Protocol version 2 must be used.
Steps:
Step 1: Configure a new valid PIN
Set a new valid PIN, ensuring all command parameters are correct.
Expected Result: The authenticator returns CTAP2_OK.

Step 2: Attempt to change the PIN using an incorrect current PIN
Send the change PIN command with an incorrect current PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED.

Step 3: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters.
Expected Result: The authenticator reports a PIN retry count reduced by one from the maximum allowed retries.
Step 4: Attempt to change the PIN using an correct current PIN with power cycle.
Send the change PIN command with an correct incorrect  PIN while keeping all other parameters valid.
Expected Result: The authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED.
Step 5: Retrieve the remaining PIN retry count
Use the getPINRetries command with correct parameters but retries count should be decress and at last return CTAP2_ERR_PIN_BLOCKED.
""",

"protocol.keypair" :"""Test started: f-25 : 
Precondition: The authenticator must be reset and must not have any PIN set..
Step:
Set a new valid PIN using a Valid  PIN length that falls between the minimum and maximum allowed PIN lengths,but keyagreement wii generated by protocol 1 but setPin command will send by protocol 2 and  all other command parameters are correct.
Expected Result:
The authenticator returns  CTAP2_ERR_PIN_AUTH_INVALID.""",


    

   
   
   
   
    }
    util.ResetCardPower()
    util.ConnectJavaCard()
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])

    # ------------------------------
    #  MODE → FOR  PIN Value 
    # ------------------------------
    if mode == "minimumpin.length":
        pin = "123456"                              # minimum 6 bytes(depend on getinfo)

    elif mode == "maximumpin.length":
        pin = "1" * 63                              # maximum allowed length

    elif mode == "random.pin":
        pin = f"{random.randint(0, 12345678):08d}"   # random 8-digit PIN
    elif mode == "randompin.continuess":
        pin = f"{random.randint(0, 12345678):07d}"   # random 8-digit PIN
    elif mode == "randompin.exccedlength":
        pin = f"{random.randint(0, 12345678):08d}"   # random 8-digit PIN
    
    elif mode == "alphanumeric.pin":
        pin = "abcd12"
    elif mode == "specialchar.pin":
        pin = "abc@12" 

    elif mode == "pinlengthLess":
        pin = "123"                               # shorter than minimum → invalid

    elif mode == "pinlengthexced":
        pin = "1" * 65                         # longer than maximum → invalid

    elif mode == "getpin.retries":
        pin = "123456" 
                                        # valid PIN for the test
    elif mode == "pinalreayset":
        pin = "123456" 
    elif mode == "exting.pin": 
        pin = "123456"
    elif mode == "wrong.pin":
        pin = "123456"      
              
    elif mode =="wrong.pin1": 
        util.printcolor(util.CYAN, "Finding the GetRetries count")
        retries = getPinRetries()
        util.printcolor(util.YELLOW, f"Current PIN retries: {retries}")
        wron_pin="543278" 
        
    elif mode =="newpin": 
        util.printcolor(util.CYAN, "PIN already exists. Proceeding to attempt setting it again.")
        pin="123456"
        
    elif mode =="pinnotset": 
        pin="123456"
    elif mode =="notpadding": 
        pin="1234567890123456"
    elif mode == "noretries":
        pin="123456" 

    elif mode=="missing.protocol":
        pin="123456" 
    elif mode=="missing.subcommand":
        pin="123456" 
    elif mode=="missing.keyAgreement":
        pin="123456" 
    elif mode=="missing.pinUvAuthParam":
        pin="123456" 

    elif mode=="Invalid.pinUvAuthProtocol":
        pin="123456"
    elif mode=="Invalid.subCommand":
        pin="123456"
    elif mode=="Invalid.keyAgreement":
        pin="123456"
    elif mode=="Invalid.newPinEnc":
        pin="121212121212121212"  
    elif mode=="Invalid.pinUvAuthParam":
        pin="123456" 
    elif mode=="Invalid.pinUvAuthParamlength":
        pin="123456"  
    elif mode=="Invalid.newPinEnclength":
        pin="12345698"  

    elif mode=="protocolnotsupported":
        pin="123456"
    
    elif mode=="keyAgreement.invalid":
        pin="123456" 
    

    elif mode=="validkeyAgreement":
        pin="123456"
    elif mode=="missing.newPinEnc":
        pin="123456"  
    elif mode=="hmac.notmatch":
        pin="123456" 
    elif mode=="pinauth.invalid":
        pin="123456" 
    elif mode=="paddedPin.invalid":
        pin="12345698"
    elif mode=="paddedPininvalid":
        pin="12345698"
    elif mode=="without.paddedPin":
        pin="123456"
    elif mode=="Hmacreuse":
        pin="123456"
    elif mode=="wrong.protocol":
        pin="123456"
    elif mode=="subcomanndnotsupported":
        pin="123456" 
    elif mode=="withoutpowercycle":
        pin="123456" 
    elif mode=="withpowercycle":
        pin="123456" 
    elif mode=="protocol.keypair":
        pin="123456" 
            
    else:
        util.printcolor(util.YELLOW, f"Selected Invalid Mode ")
        # util.APDUhex("00A4040008A0000006472F0001", "Select applet")
        # setpin(pin)

    #util.printcolor(util.YELLOW, f"Selected PIN for mode '{mode}': {pin}")
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
            util.run_apdu("80100000010700", "Reset Card PIN","00")
            #util.APDUhex("80100000010400", "GetInfo")

            # if mode == "change.pin": 
            #     newPin2 = "123456"
            #     changeNewPIN(newPin,newPin2)
            if mode=="pinnotset":
                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                response,status=util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
                if response[:2] == "35":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_NOT_SET)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="getpin.retries":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"****Step 1: Set a new valid PIN*****")
                clientPinset(mode,pin)
            elif mode=="minimumpin.length":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0) 

            elif mode=="maximumpin.length":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="random.pin":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")

                response=clientPinset(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_SUCCESS)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="protocol.keypair":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinkeypair1(mode,pin)
                if response[:2] == "33":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="randompin.continuess":
                pin_length=8
                
                for i in range(5):                           # 7 + 63 more = 64 loops
                # generate random numeric PIN with current length
                    randompin = ''.join(str(random.randint(0, 9)) for _ in range(pin_length))
                    # set the PIN
                    pin=clientPinsetcontinuess(randompin) 
                    util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                    response,status=makecredntial(pin,user,RP_domain) #verify current pin 
                    if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    credId=getpinuvauthtokenctap2_2.authParasing(response)
                    clientDataHash = os.urandom(32)
                    pinToken, pubkey = getPINtokenPubkey(pin)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = getpinuvauthtokenctap2_2.createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True) 
                    
                    if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    pin_length += 1 
            
            elif mode=="randompin.exccedlength":
                pin_length=6
                
                for i in range(10):                           # 7 + 63 more = 64 loops
                # generate random numeric PIN with current length
                    randompin = str(util.random_int(pin_length))
                    # set the PIN
                    pin=clientPinsetcontinuess(randompin) 
                    util.printcolor(util.YELLOW,f"  PIN IS: {randompin}")
                    response,status=makecredntial(pin,user,RP_domain) #verify current pin 
                    if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    credId=getpinuvauthtokenctap2_2.authParasing(response)
                    clientDataHash = os.urandom(32)
                    pinToken, pubkey = getPINtokenPubkey(pin)
                    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                    apdu = getpinuvauthtokenctap2_2.createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True) 
                    if response[:2] == "00":
                            util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, "  ❌ Test Case Failed")
                        exit(0)
                    pin_length += 6 
                
                pin_length = 65
                # generate random numeric PIN with current length
                randompin = str(util.random_int(pin_length))
                # set the PIN
                pin=clientPinsetcontinuess1(randompin) 
                util.printcolor(util.YELLOW,f"  PIN IS: {randompin}")
                
                

                #attemt to set pin 
                # randompin = ''.join(str(random.randint(0, 9)) for _ in range(64))
                # clientPinsetcontinuess(randompin)
                # util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                
                
            elif mode=="alphanumeric.pin":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="specialchar.pin":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode=="pinlengthLess":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"Step 1: Retrieve minimum PIN length")
                util.APDUhex("80100000010400", "GetInfo")
                util.printcolor(util.YELLOW,f"Step 2:Set a PIN shorter than the platform minimum (e.g., less than 4 digits)")
                response=clientPinset(mode,pin)
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f"Step 3: Set a PIN shorter than the minimum length returned by getInfo")
                util.APDUhex("80100000010400", "GetInfo")
                pin="12345"
                response=clientPinset(mode,pin)
                if response[:2] == "37":
                        
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                
            elif mode=="pinlengthexced":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)


                
            elif mode =="notpadding":
                
                pin="1234567887654321"
                response=set_pin_failed_without_padding(pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "noretries":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                util.printcolor(util.YELLOW,f" Step 1: Configure a new valid PIN")                      
                response=setpin(pin)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f" Step 2: Attempt to change the PIN using an incorrect current PIN") 
                wrongpin="3333"
                for i in range(3):
                    print(f"{i} time")
                    response=changePin(wrongpin,pin)
                    if i == 2 :
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
                
                util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count") 
                getPinRetries()
            elif mode == "withoutpowercycle":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                util.printcolor(util.YELLOW,f" Step 1: Configure a new valid PIN")                      
                response=setpin(pin)
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f" Step 2: Attempt to change the PIN using an incorrect current PIN") 
                wrongpin="765432"
                for i in range(3):
                    response=changePin(wrongpin,pin)
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

                
                util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count") 
                getPinRetries()
                util.printcolor(util.YELLOW,f" Step 4: Repeat the correct  PIN command without power cycle reset") 
            
                response=changePin(pin,wrongpin)
                if i in (2,5):
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

                getPinRetries()
            elif mode == "withpowercycle":
                pin="123456"
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                util.printcolor(util.YELLOW,f" Step 1: Configure a new valid PIN")                      
                response=setpin(pin)
                if response[:2] == "00":
                    util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
                util.printcolor(util.YELLOW,f" Step 2: Attempt to change the PIN using an incorrect current PIN") 
                wrongpin="765432"
                for i in range(8):
                    # util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                    # util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count {i}") 

                    response=changePin(wrongpin,pin)
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
                    
                    
                        
                    
                
                    util.printcolor(util.YELLOW,f" Step 3: Retrieve the remaining PIN retry count") 
                    getPinRetries()
                
                    util.ResetCardPower()
                    util.ConnectJavaCard()
                    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

                
            
                
                
            elif mode=="missing.protocol":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=missingparameter(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="missing.subcommand":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=missingparameter(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="missing.keyAgreement":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=missingparameter(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="missing.newPinEnc":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=missingparameter(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="missing.pinUvAuthParam":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=missingparameter(mode,pin)
                if response[:2] == "14":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_MISSING_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Invalid.pinUvAuthProtocol":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Invalid.subCommand":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Invalid.keyAgreement":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode=="Invalid.newPinEnc":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Invalid.pinUvAuthParam":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Invalid.pinUvAuthParamlength":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "03":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_LENGTH)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode=="Invalid.newPinEnclength":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="paddedPin.invalid":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="without.paddedPin":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "02":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="paddedPininvalid":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin) 
                if response[:2] == "37":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_POLICY_VIOLATION)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Hmacreuse":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=setpinnewinvalid(mode,pin)
                if response[:2] == "33":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_ERR_PIN_AUTH_INVALID)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            


            elif mode=="protocolnotsupported":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}") 
                response=missmatchprotocol(pin)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            
            elif mode=="subcomanndnotsupported":
                pin="123456"
                response=subcmdprotocol(pin)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            

            elif mode == "keyAgreement.invalid":
                decoded_data=get_key_agreement()
                #key_agreement, shareSecretKey = util.wrongencapsulate(decoded_data[1])
                key_agreement, shareSecretKey = util.wrongkeyagreement(decoded_data[1])
                newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
                #newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin_minimal(pin))
                auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement) 
                
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)


            elif mode=="validkeyAgreement":
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
                newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
                auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            elif mode=="hmac.notmatch":
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
                newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
                auth       = util.hmac_sha256(shareSecretKey[:16], newPinEnc ) # always 16 byte resul
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "pinauth.invalid":
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
                newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
                auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc)
                auth       = bytes([auth[0] ^ 0xFF]) + auth[1:]  # flip first byte to invalidate HMAC
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status==util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="paddedPin.invalid1":#paddedPin.invalid
                
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
                newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pinlengthnotmatch(pin))
                auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
        
            elif mode=="without.paddedPin1":
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement, shareSecretKey =  util.encapsulate(decoded_data[1])
                newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.withoupadded(pin))
                auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="Hmacreuse1":
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement1, shareSecretKey1 =  util.encapsulate(decoded_data[1])
                newPinEnc1   = util.aes256_cbc_encrypt(shareSecretKey1[32:], util.pad_pin(pin))
                authold_hmac = util.hmac_sha256(shareSecretKey1[:32], newPinEnc1 ) # always 32 byte result
                ###again we generated newPinEnc using differtpin
                pin="4567"
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00A4040008A0000006472F0001", "Select applet")
                cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
                cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
                decoded_data = cbor2.loads(cbor_bytes)
                key_agreement2, shareSecretKey2 = util.encapsulate(decoded_data[1])
                newPinEnc2  = util.aes256_cbc_encrypt(shareSecretKey2[32:], util.pad_pin(pin))
                #using old hmac 
                auth      = authold_hmac
                key_agreement=key_agreement2
                newPinEnc=newPinEnc2
                pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode=="wrong.protocol":
                decoded_data=get_key_agreement_and_shared_secret()
                key_agreement, shared_secret =util.encapsulate_protocol1( decoded_data[1])
                padded_pin = util.pad_pin(pin)  
                newPinEnc = util.aes256_cbc_encryptnew(shared_secret, padded_pin)
                # Compute HMAC using same 16 bytes
                pin_auth = util.hmac_sha256(shared_secret, newPinEnc)
                auth = pin_auth[:16]
                pinSetAPDU = createCBOR1(newPinEnc, auth,  key_agreement)    
                response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
                if response[:2] == "01":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_COMMAND)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)

            
            
            # else: 
            #     print("current pin",pin) 
            #     clientPinset(mode,pin)
        else:
            if mode == "pinalreayset":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response=clientPinset(mode,pin)
            elif mode == "wrong.pin1":
                wrongPinProvide()
            elif mode=="newpin":
                setpin(pin)
            elif mode == "exting.pin":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                response,status=makecredntial(pin,user,RP_domain) #verify current pin 
                credId=getpinuvauthtokenctap2_2.authParasing(response)
                clientDataHash = os.urandom(32)
                pinToken, pubkey = getPINtokenPubkey(pin)
                pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
                apdu = getpinuvauthtokenctap2_2.createCBORmakeAssertion(clientDataHash, RP_domain, pinAuthToken, credId)
                result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
                if response[:2] == "00":
                        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, "  ❌ Test Case Failed")
                    exit(0)
            elif mode == "wrong.pin":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                util.printcolor(util.YELLOW,f"  Step 1: Retrieve initial PIN retry count")
                getPinRetries()
                util.printcolor(util.YELLOW,f"  Step 2: Attempt to change the PIN with an incorrect current PIN")
                wrongpin="654321"
                pin = "123456"
                response=changePin(wrongpin,pin)
                util.printcolor(util.YELLOW,f"  Step 3: Verify retry count decreases")
                getPinRetries()
                util.printcolor(util.YELLOW,f"  Step 4: Reset the authenticator and set a new valid PIN")
                response=setnewpin()
                util.printcolor(util.YELLOW,f"  Step 5: Retrieve retry count after reset")
                getPinRetries()
    finally:
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1




      
def wrongPinProvide():
    # ------------------------------
    #   Attempt ChangePIN with wrong PIN
    # ------------------------------
    util.printcolor(util.CYAN, "Attempting ChangePIN with wrong PIN")

    current_pin = "123456"
    wrong_pin = "5432"

    # Attempt to change PIN with wrong old PIN
    changePin(wrong_pin, current_pin)

    # Check remaining PIN retries after wrong PIN attempt
    getPinRetries()

    # ------------------------------
    #   Reset Card and Prepare to Set PIN
    # ------------------------------
    util.printcolor(util.CYAN, "Resetting Card to allow PIN setup")

    # Reset PIN on the card (APDU)
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010700", "Reset Card PIN", checkflag=True)

    # Retrieve card info after reset
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------
    #   Set new PIN
    # ------------------------------
    util.printcolor(util.CYAN, "Setting new PIN")
    setpin(current_pin)

    # Verify PIN retries after setting new PIN
    getPinRetries()
   
def cbor_build(shareSecretKey,newPinEnc,auth,key_agreement):
    pinSetAPDU = createCBOR(newPinEnc, auth,  key_agreement)    
    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)


def clientPinkeypair1(mode,pin):
    util.printcolor(util.YELLOW, "****Attempt SetPIN****")
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

    # ------------------------------
    #  GET KEY AGREEMENT
    # ------------------------------
    cardPublickey, status = util.APDUhex(
        "801000000606a20101020200",
        "Client PIN subcmd 0x02 getKeyAgreement",
        True
    )
    cbor_bytes = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    # Always padded to 64 according to protocol-2
    if mode =="paddedPininvalid":
        paddedPin = util.wrongpad_pin(pin)
    else:
        paddedPin = util.pad_pin(pin)

    # ------------------------------
    #  ENCRYPT + HMAC
    # ------------------------------
    newPinEnc = util.aes256_cbc_encrypt(shareSecretKey[32:], paddedPin)
    auth = util.hmac_sha256(shareSecretKey[:32], newPinEnc)

    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)

    # ------------------------------
    #  SEND SETPIN COMMAND
    # ------------------------------
    response,status=util.APDUhex(pinSetAPDU, "Client PIN 0x03 SetPIN", checkflag=True)
    return response

def clientPinset(mode,pin):
    util.printcolor(util.YELLOW, "****Attempt SetPIN****")
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

    # ------------------------------
    #  GET KEY AGREEMENT
    # ------------------------------
    cardPublickey, status = util.APDUhex(
        "801000000606a20102020200",
        "Client PIN subcmd 0x02 getKeyAgreement",
        True
    )
    cbor_bytes = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    # Always padded to 64 according to protocol-2
    if mode =="paddedPininvalid":
        paddedPin = util.wrongpad_pin(pin)
    else:
        paddedPin = util.pad_pin(pin)

    # ------------------------------
    #  ENCRYPT + HMAC
    # ------------------------------
    newPinEnc = util.aes256_cbc_encrypt(shareSecretKey[32:], paddedPin)
    auth = util.hmac_sha256(shareSecretKey[:32], newPinEnc)
    print("newPinEnc",newPinEnc.hex())

    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)

    # ------------------------------
    #  SEND SETPIN COMMAND
    # ------------------------------
    response,status=util.APDUhex(pinSetAPDU, "Client PIN 0x03 SetPIN", checkflag=True)

    # ------------------------------
    #  EXTRA STEP FOR getpin.retries
    # ------------------------------
    if mode == "getpin.retries":
        util.printcolor(util.YELLOW,f"Step 2: Verify PIN retry counter initialization ")
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

    return response

def clientPinsetcontinuess(pin):
    # ------------------------------
    #  Reset Card PIN
    # ------------------------------
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010700", "Reset Card PIN")
    util.printcolor(util.YELLOW, "****Attempt SetPIN****")
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

    # ------------------------------
    #  GET KEY AGREEMENT
    # ------------------------------
    cardPublickey, status = util.APDUhex(
        "801000000606a20102020200",
        "Client PIN subcmd 0x02 getKeyAgreement",
        True
    )
    cbor_bytes = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    paddedPin = util.pad_pin(pin)

    # ------------------------------
    #  ENCRYPT + HMAC
    # ------------------------------
    newPinEnc = util.aes256_cbc_encrypt(shareSecretKey[32:], paddedPin)
    auth = util.hmac_sha256(shareSecretKey[:32], newPinEnc)
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)

    # ------------------------------
    #  SEND SETPIN COMMAND
    # ------------------------------
    response,status=util.APDUhex(pinSetAPDU, "Client PIN 0x03 SetPIN", checkflag=True)
    if response[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)
    return pin

def clientPinsetcontinuess1(pin):
    # ------------------------------
    #  Reset Card PIN
    # ------------------------------
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010700", "Reset Card PIN")
    util.printcolor(util.YELLOW, "****Attempt SetPIN****")
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

    # ------------------------------
    #  GET KEY AGREEMENT
    # ------------------------------
    cardPublickey, status = util.APDUhex(
        "801000000606a20102020200",
        "Client PIN subcmd 0x02 getKeyAgreement",
        True
    )
    cbor_bytes = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    paddedPin = util.pad_pin(pin)

    # ------------------------------
    #  ENCRYPT + HMAC
    # ------------------------------
    newPinEnc = util.aes256_cbc_encrypt(shareSecretKey[32:], paddedPin)
    auth = util.hmac_sha256(shareSecretKey[:32], newPinEnc)
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)

    # ------------------------------
    #  SEND SETPIN COMMAND
    # ------------------------------
    response,status=util.APDUhex(pinSetAPDU, "Client PIN 0x03 SetPIN", checkflag=True)
    if response[:2] == "02":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP1_ERR_INVALID_PARAMETER)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)
    return pin

   

        
    





def clientPinsetnotfound(mode,pin):
    util.printcolor(util.YELLOW, "****Attempt SetPIN****")
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")

    # ------------------------------
    #  GET KEY AGREEMENT
    # ------------------------------
    cardPublickey, status = util.APDUhex(
        "801080000606a20102020200",
        "Client PIN subcmd 0x02 getKeyAgreement",
        True
    )
    cbor_bytes = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    # Always padded to 64 according to protocol-2
    paddedPin = util.pad_pin(pin)

    # ------------------------------
    #  ENCRYPT + HMAC
    # ------------------------------
    newPinEnc = util.aes256_cbc_encrypt(shareSecretKey[32:], paddedPin)
    auth = util.hmac_sha256(shareSecretKey[:32], newPinEnc)

    pinSetAPDU = createcbor(newPinEnc, auth, key_agreement)

    # ------------------------------
    #  SEND SETPIN COMMAND
    # ------------------------------
    util.APDUhex(pinSetAPDU, "Client PIN 0x03 SetPIN", checkflag=True)




def  makecredntial(pin,user,rp):
# ------------------------------
#   COMMON FIELDS
# ------------------------------
        clientDataHash = os.urandom(32)
        pinToken, pubkey = getPINtokenPubkey(pin)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
        # ------------------------------
        #   RP FEILD
        # ------------------------------
        rp_entity = {"id": rp, "name": rp}
        # ------------------------------
        #   USER FEILD
        # ------------------------------
        user_entity = {
            "id": user.encode(),
            "name": user,
            "displayName": user
        }
        # ----------------------------------------------------
        #        pubKeyCredParams 
        # ----------------------------------------------------
        pubKeyCredParams = [
                {"alg": -7, "type": "public-key"}
            ]

        makeCredAPDU = build_make_cred_apdu(
            clientDataHash,
            rp_entity,
            user_entity,
            pubKeyCredParams,
            pubkey,
            pinAuthToken)
        

        # ----------------------------------------------------
        #   SEND APDU (single or chained)
        # ----------------------------------------------------
        if isinstance(makeCredAPDU, str):
            result, status = util.APDUhex(makeCredAPDU, f"Client PIN command as subcmd 0x01 make Credential: ", checkflag=True)
        else:
            for i, apdu in enumerate(makeCredAPDU):
                result, status = util.APDUhex(
                    apdu,
                    "Rest of Data:",
                    checkflag=(i == len(makeCredAPDU) - 1)
                )

        return result, status



def changeNewPIN(curpin, newPin):
    newPin2="123456"
    # -------------------------------------------------------
    #  Step 1: Attempt ChangePIN when no PIN is set
    # -------------------------------------------------------
    util.printcolor(util.CYAN, " Attempt ChangePIN when no PIN is set ")
    changePin(curpin, newPin)
    # -------------------------------------------------------
    #  Step 2: Set a new PIN 
    # -------------------------------------------------------
    util.printcolor(util.CYAN, " Attempt TO SETPIN ")
    setpin(newPin)
    # -------------------------------------------------------
    #  Step 3: Attempt ChangePIN now with correct old PIN
    # -------------------------------------------------------
    util.printcolor(util.CYAN, " Attempt ChangePIN with old PIN ")
    changePin( newPin,newPin2)
    # -------------------------------------------------------
    #  Step 4: getPINRetries to verify counter 
    # -------------------------------------------------------
    util.printcolor(util.CYAN, " GetPINRetries ")
    util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)


# =================================================================
#    UPDATED build_make_cred_apdu()  (INCLUDES excludeList)
# =================================================================

def build_make_cred_apdu(clientDataHash, rp_entity, user_entity,
                         pubKeyCredParams,  pubkey, pinAuthToken):

    options = {"rk": True}

    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(user_entity).hex().upper()
    cbor_params  = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    # CBOR MAP (A8 = 8 entries)
    dataCBOR  = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params
    dataCBOR += "07" + cbor_options
    dataCBOR += "08" + cbor_pinAuth
    dataCBOR += "09" + "02"

    finalPayload = "01" + dataCBOR
    payload = bytes.fromhex(finalPayload)

    # Single APDU
    if len(payload) <= 255:
        lc = f"{len(payload):02X}"
        return "80100000" + lc + finalPayload

    # Chained APDU
    return util.build_chained_apdus(payload)



def set_pin_failed_without_padding(pin: str):
    
    # 1. Get key agreement
    cardPublickey, status = util.APDUhex(
        "801000000606a20102020200",
        "Client PIN subcmd 0x02 getKeyAgreement",
        True
    )

    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    raw_pin = pin.encode()
    # newPinEnc = aes256_cbc_encryptnottt(shared_secret=shareSecretKey[32:], raw_pin)
    newPinEnc = util.aes256_cbc_encryptWithoutPad(shared_secret=shareSecretKey[32:], data=raw_pin)
    auth = util.hmac_sha256(shareSecretKey[:32], newPinEnc)
    bad_cbor = createCBOR(newPinEnc, auth, key_agreement)

    
    response,status= util.APDUhex(
        bad_cbor,
        "Client PIN subcmd 0x03 SetPIN (FAILED CASE - NO PADDING)",
        checkflag=True
    )
    return response



def aes256_cbc_encryptnottt(shared_secret, data):
    # Calculate the number of padding bytes needed
    padding_needed = 16 - (len(data) % 16)
    # Only pad if data length is not already a multiple of 16

    if padding_needed != 16:
        data += b'\x00' * padding_needed

    iv = os.urandom(16)
    return 





    
def notPadded(pin):
    util.printcolor(util.YELLOW,"****Attempt to setPIN ****")
    util.printcolor(util.YELLOW,f"  PIN  data: {pin}")
                                  
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)

    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    raw_pin = pin.encode("utf-8")      # e.g. 63 bytes

    # AES CBC NO padding requires multiple of 16 → manually pad to next 16
    remainder = len(raw_pin) % 16
    if remainder != 0:
        raw_pin += b"\x00" * (16 - remainder)

    # ------------------------------
    # Step 3 — Encrypt using AES-CBC-NO-PADDING
    # ------------------------------
    newPinEnc = util.aes256_cbc_encrypt_no_padding(
        shareSecretKey[32:],   # AES key
        raw_pin              # NOT 64 bytes → spec violation
    )



    #Fido Alliance says to pad the PIN with 0x00 for 64 length  util.pad_pin(pin)
    newPinEnc  = util.aes256_cbc_encrypt_no_padding(shareSecretKey[32:], util.notPadeddPin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True);


def get_key_agreement_and_shared_secret():
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    return decoded_data
    

def get_key_agreement():
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    
    decoded_data = cbor2.loads(cbor_bytes)
    return decoded_data

def create_invalid_keyagreement():
    return {
        1: 2,                     # kty = EC2
        3: -25,                   # alg
        -1: 1,                    # crv = P-256
        -2: os.urandom(32),       # INVALID X coordinate
        -3: os.urandom(32),       # INVALID Y coordinate
    } 

def getPinRetries():
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    response, status=util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)

    cbor_data = cbor2.loads(binascii.unhexlify(response[2:])) 
    pin_retries = cbor_data[0x03]
    if not isinstance(pin_retries, int):
        util.printcolor(util.RED, f"'pinRetries' is not a number. Got type: {type(pin_retries)}")
        return
    if pin_retries > 8:
        util.printcolor(util.RED, f" Invalid 'pinRetries': {pin_retries}. Maximum allowed is 8.")
        return
    util.printcolor(util.GREEN, f"✅ Test Passed: pinRetries = {pin_retries}")

    
def setpin(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response
def setpinnew(pin):
    
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # invalid
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)



def setpinnewinvalid(mode,pin):
    
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    
        
    print("newPinEnc",newPinEnc)
    subcommand=3
    protocols =2
    if mode == "Invalid.pinUvAuthProtocol":
        protocols=3
        util.printcolor(util.YELLOW,f" invalid_pinUvAuthProtocol: {protocols}")   
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)
    elif mode == "Invalid.subCommand":
        subcommand=0
        util.printcolor(util.YELLOW,f" invalid_subCommand: {subcommand}")
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)
    elif mode == "Invalid.keyAgreement":
        key_agreement, shareSecretKey = util.wrongkeyagreement(decoded_data[1])
        util.printcolor(util.YELLOW,f" invalid_keyAgreement: {key_agreement}")
        newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
        auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)

    elif mode == "Invalid.newPinEnc":
        invalid_newPinEnc = bytearray(newPinEnc)
        util.printcolor(util.YELLOW,f"Before invalid_newPinEnc: {bytes(invalid_newPinEnc).hex()}")   

        # flip a bit somewhere inside the ciphertext (avoid the IV if you want other tests)
        flip_index = min(20, len(invalid_newPinEnc)-1)   # safe index
        invalid_newPinEnc[flip_index] ^= 0xFF
        invalid_newPinEnc = bytes(invalid_newPinEnc)
        util.printcolor(util.YELLOW,f" invalid_newPinEnc: {invalid_newPinEnc.hex()}")   
        auth       = util.hmac_sha256(shareSecretKey[:32], invalid_newPinEnc )
        pinSetAPDU = createcborinvaild(invalid_newPinEnc, auth, key_agreement,protocols,subcommand)
    elif mode == "Invalid.pinUvAuthParam": 
        auth       = util.hmac_sha256(shareSecretKey[:16], newPinEnc )
        util.printcolor(util.YELLOW,f" Invalid pinUvAuthParam: {auth.hex()}")  
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)
    elif mode == "Invalid.pinUvAuthParamlength": 
        auth      = util.hmac_sha256(shareSecretKey[:32], newPinEnc )
        pin_auth = auth[:5]
        util.printcolor(util.YELLOW,f" Invalid pinUvAuthParam Length new: {pin_auth.hex()}")  
        pinSetAPDU = createcborinvaild(newPinEnc, pin_auth, key_agreement,protocols,subcommand)
    elif mode == "Invalid.newPinEnclength": 
        # wrongPIN = os.urandom(8)
        # util.printcolor(util.YELLOW, f"PIN for Invalid.newPinEnc  length:{util.toHex(wrongPIN)}")

        # newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], wrongPIN)
        # newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
        util.printcolor(util.YELLOW, f"Valid.newPinEnc  length:{newPinEnc.hex()}")
        newPinEnc = newPinEnc[:10]

        util.printcolor(util.YELLOW, f" Invalid.newPinEnc  length:{newPinEnc.hex()}")
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)
    elif mode == "paddedPin.invalid": 
        newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin_with_expected_length(pin, 48))
        #Fido Alliance says to pad the PIN with 0x00 for 64 length
        auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)
    elif mode == "without.paddedPin": 
        newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.withoupadded(pin))
        auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc )
        pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)

    elif mode == "Hmacreuse": 
        ###again we generated newPinEnc using differtpin
            pin="4567"
            util.ResetCardPower()
            util.ConnectJavaCard()
            util.APDUhex("00A4040008A0000006472F0001", "Select applet")
            cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
            cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
            decoded_data = cbor2.loads(cbor_bytes)
            key_agreement1, shareSecretKey1 = util.encapsulate(decoded_data[1])
            newPinEnc2  = util.aes256_cbc_encrypt(shareSecretKey1[32:], util.pad_pin(pin))
            #using old hmac 
            pinSetAPDU = createcborinvaild(newPinEnc, auth, key_agreement,protocols,subcommand)
            
    response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response


def setpinnewpadedpinlength(pin):
    
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:10], newPinEnc ) # invalid
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)





def missingparameter(mode,pin):
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBORmissingparam(mode,newPinEnc, auth, key_agreement)    
    response,status=util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response

def missmatchprotocol(pin):
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = wrongProtocol(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)

def subcmdprotocol(pin):
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = subcommandPro(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)



def changePin(old_pin, new_pin):
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
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response,status=util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response


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

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
        return APDUcommand 

def createcbor(newPINenc, auth, key_agreement):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
        #dataCBOR = dataCBOR + "02"+ "03" # setPIN
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand 


def createcborinvaild(newPINenc, auth, key_agreement,protocols,subcommand):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        cbor_protocols   = cbor2.dumps(protocols).hex().upper()
        cbor_subcommand  = cbor2.dumps(subcommand).hex().upper()

        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+cbor_protocols  # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ cbor_subcommand # setPIN
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
        return APDUcommand 

def createCBOR1(newPINenc, auth, key_agreement):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ "01" # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ "03" # setPIN
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand


def wrongcreateCBOR(newPINenc, auth, key_agreement):
    # Generate a random invalid keyAgreement of similar length
    invalid_key_agreement = os.urandom(64)  # 64 bytes random data
    invalid_key_agreement_hex = invalid_key_agreement.hex().upper()

    # Convert other parameters to CBOR hex
    cbor_newPINenc = cbor2.dumps(newPINenc).hex().upper()
    cbor_auth     = cbor2.dumps(auth).hex().upper()

    # Build dataCBOR
    dataCBOR = "A5"                            # CBOR map of 5 items
    dataCBOR += "01" + "02"                     # FIDO2 protocol
    dataCBOR += "02" + "03"                     # setPIN subcommand
    dataCBOR += "03" + invalid_key_agreement_hex  # Invalid keyAgreement
    dataCBOR += "04" + cbor_auth
    dataCBOR += "05" + cbor_newPINenc

    # Compute payload length
    payload_bytes = bytes.fromhex("06" + dataCBOR)  # "06" prefix is part of APDU
    length_hex = f"{len(payload_bytes):02X}"

    # Final APDU command
    APDUcommand = "801080" + length_hex + "06" + dataCBOR
    return APDUcommand
 
def createCBORParam(newPINenc, auth, key_agreement):
        #platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ "03" # setPIN
        #dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand 

def createCBORmissingparam(mode,newPINenc, auth, key_agreement):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        if mode =="missing.protocol":
            dataCBOR = "A4"
            dataCBOR = dataCBOR + "02"+ "03" # setPIN
            dataCBOR = dataCBOR + "03"+ platformCOSKEY
            dataCBOR = dataCBOR + "04"+ cbor_auth
            dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        elif mode =="missing.subcommand":
            dataCBOR = "A4"
            dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
            dataCBOR = dataCBOR + "03"+ platformCOSKEY
            dataCBOR = dataCBOR + "04"+ cbor_auth
            dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        elif mode =="missing.keyAgreement":
            dataCBOR = "A4"
            
            dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
            dataCBOR = dataCBOR + "02"+ "03" # setPIN
            dataCBOR = dataCBOR + "04"+ cbor_auth
            dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        elif mode =="missing.newPinEnc":
            dataCBOR = "A4"
            dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
            dataCBOR = dataCBOR + "02"+ "03" # setPIN
            dataCBOR = dataCBOR + "03"+ platformCOSKEY
            dataCBOR = dataCBOR + "04"+ cbor_auth
        elif mode =="missing.pinUvAuthParam":
            dataCBOR = "A4"
            dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
            dataCBOR = dataCBOR + "02"+ "03" # setPIN
            dataCBOR = dataCBOR + "03"+ platformCOSKEY
            dataCBOR = dataCBOR + "05"+ cbor_newPINenc
            
            
        


        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR+"00"
        return APDUcommand  


def wrongProtocol(newPINenc, auth, key_agreement):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        dataCBOR = "A4"
        dataCBOR = dataCBOR + "01"+ "04" # wrong protocol 
        dataCBOR = dataCBOR + "02"+ "03" # setPIN
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand  
def subcommandPro(newPINenc, auth, key_agreement):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ "02" # fido2 
        dataCBOR = dataCBOR + "02"+ "0A" # wrong subcommand
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand  

def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)
    if hexstring[:2] == "00":
        util.printcolor(util.GREEN, "  ✅ Test Case Passed Expected Output(CTAP2_OK)")
    else:
        util.printcolor(util.RED, "  ❌ Test Case Failed")
        exit(0)

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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def setnewpin():
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.ResetCardPower()
    util.ConnectJavaCard() 
    util.run_apdu("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010700", "Reset Card PIN")
    #util.APDUhex("80100000010400", "GetInfo")
    setpin(pin)
	
	
	
	
	
	
	
	
	
	
