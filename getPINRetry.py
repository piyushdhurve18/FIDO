import util
import Setpinp22
import os
import cbor2
import binascii
import DocumentCreation

rp = "localhost"
curPin = "12345678"
user="bobsmith"
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "GET PIN RETRY"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def getPINRetries(mode, reset_required, set_pin_required):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
        "maxRetryCount": """Test started: P-1 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        When attempting to retrieve the retry count using the getPinRetries(0x01) subcommand, with all command parameters correctly provided, the authenticator is expected to return the maximum number of retries.""",

        "incorrectPinVerifyAndRetryCount": """Test started: P-2 :
        Precondition: The authenticator has been reset, a PIN is configured, and the retry count has been retrieved using the getPinRetries command.;
        Perform PIN verification with an incorrect current PIN — the verification must fail. Then retrieve the retry count again using the getPinRetries(0x01) subcommand with all parameters correctly provided; the authenticator must return a retry count reduced by one.
        Attempt PIN verification with correct PIN, the authenticator must return CTAP2_OK. Now again perform getPinRetries command, authenticator must reassign maximum allowed retry counts.""",
   
        "incorrectPinChangeAndRetryCount": """Test started: P-3 :
        Precondition: The authenticator has been reset, a PIN is configured, and the retry count has been retrieved using the getPinRetries command.;
        Perform PIN Change with an incorrect current PIN — the change PIN must fail. Then retrieve the retry count again using the getPinRetries(0x01) subcommand with all parameters correctly provided. the authenticator must return a retry count reduced by one.
        Attempt PIN Change with correct PIN, the authenticator must return CTAP2_OK. Now again perform getPinRetries command, authenticator must reassign maximum allowed retry counts.""",

        "pinBlock": """Test started: P-4 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        Perform PIN verification with an incorrect current PIN — the verification must fail. Then retrieve the retry count using the getPinRetries(0x01) subcommand with all parameters correctly provided; the authenticator must return a retry count reduced by one. Perform same operation untill retry counts come to zero, then authenticator must return CTAP2_ERR_PIN_BLOCKED.""",
   
        "afterPowerCycleSameRetryCount": """Test started: P-5 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’). After performing a power-cycle reset, retrieve the PIN retry count again. the authenticator must return the same retry count ‘XX’ as before the reset.""",

        "invalidSubCommand": """Test started: P-6 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        While performing get Pin Retries, send a invalid command parameter i.e. send subCommand: getPINRetries(0x0A). The authenticator must return CTAP2_ERR_INVALID_SUBCOMMAND.""",
   
        "subCommandAbsent": """Test started: P-7 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        While performing get Pin Retries, send a command where subCommand: getPINRetries(0x01) is absent. The authenticator must return CTAP2_ERR_MISSING_PARAMETER.""",

        "missingDataField": """Test started: P-8 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        Try to Retrieve the retry count with Zero parameters (Dont give protocol and subcommand), the authenticator must return CTAP2_ERR_MISSING_PARAMETER""",
    
        "unsupportedPinUvAuthProtocol": """Test started: P-9 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        While performing get Pin Retries, send a command where  pinUvAuthProtocol is unsupported. The authenticator must return CTAP1_ERR_INVALID_PARAMETER.""",

        "pinNotSetAndRetryCount": """Test started: P-10 :
        Precondition: The authenticator has been reset and a PIN is not configured.;
        Attempt to perform get PIN retries, the authenticator must return CTAP2_ERR_PIN_NOT_SET.""",
   
        "pinNotSet-Set-RetryCount": """Test started: P-11 :
        Precondition: The authenticator has been reset and a PIN is not configured.;
        Attempt to retrieve the PIN retry count — the authenticator must return CTAP2_ERR_PIN_NOT_SET. Perform set pin operation and set a new PIN successfully. Then retrieve the PIN retry count again; this time, the authenticator must return the maximum number of allowed retries.""",

        "misleadPowerCycle": """Test started: P-12 :
        Precondition: The authenticator has been reset, a PIN is configured, and the retry count has been retrieved using the getPinRetries command.;
        Perform PIN verification with an incorrect current PIN — the verification must fail. Then retrieve the retry count again using the getPinRetries(0x01) subcommand with all parameters correctly provided. the authenticator must return a retry count reduced by one.
        Attempt PIN verification with correct PIN, the authenticator must return CTAP2_OK. Now again perform getPinRetries command, authenticator must reassign maximum allowed retry counts.""",
   
        "invalidParameterData": """Test started: P-13 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Retrieve the retry count using the getPinRetries with invalid subCommand parameter or parameter data provided; the authenticator must return CTAP1_ERR_INVALID_PARAMETER.""",
    
        "onlyRequiredParameter": """Test started: P-14 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Retrieve the retry count using the getPinRetries but data field of command contains only required parameters , the authenticator must return Maximum Retry Counts.""",
    
        "pinVerify-retryCount-powerCycleReset": """Test started: P-15 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Steps:;
            1. Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            2. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
            3. Perform PIN verification with an incorrect PIN with again 8 times times.;
            4. Then execute the getPinRetries command to retrieve the current retry count should be same as step 2  (denoted as ‘XX’).;
            5. After performing a power-cycle reset, retrieve the PIN retry count again, the authenticator must return the same retry count ‘XX’ as step 2.""",
    
        "pinBlockMultiple": """Test started: P-16 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Steps:;
            1. Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            2. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
            3. Perform PIN verification with an incorrect PIN with again 8 times times.;
            4. Then execute the getPinRetries command to retrieve the current retry count should be same as step 2  (denoted as ‘XX’).;
            5. After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count ‘XX’ as step 2.;
            6. Perform again PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            7. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
            8. Perform PIN verification with an incorrect PIN with again 8 times times.;
            9. After performing a power-cycle reset, Then execute the getPinRetries command to retrieve the current retry count should be same as step 7  (denoted as ‘YY’).;
            10. Perform PIN verification with an incorrect PIN with again 2 times times then authenticator should return  CTAP2_ERR_PIN_BLOCKED (0x32).""",
    
         "pinBlockMultiple-Verify": """Test started: P-17 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Steps:;
            1. Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            2. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
            3. Perform PIN verification with an incorrect PIN with again 8 times times.;
            4. Then execute the getPinRetries command to retrieve the current retry count should be same as step 2  (denoted as ‘XX’).;
            5. After performing a power-cycle reset, retrieve the PIN retry count again, the authenticator must return the same retry count ‘XX’ as step 2.;
            6. Perform again PIN verification with an correct PIN.;
            7. Then execute the getPinRetries command to retrieve and reset retry counter to max count i.e 8.""",
    
        "pinBlockMultiple-Verify1": """Test started: P-18 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Steps:;
            1. Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            2. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
            3. Perform PIN verification with an incorrect PIN with again 8 times times.;
            4. Perform again PIN verification with an correct PIN; it should return CTAP2_ERR_PIN_AUTH_BLOCKED. (Because we did not did power cycle reset);
            5. Then execute the getPinRetries command to retrieve the current retry count should be same as step 2  (denoted as ‘XX’).;
            6. After performing a power-cycle reset, retrieve the PIN retry count again, the authenticator must return the same retry count ‘XX’ as step 2.;
            7. Perform again PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            8. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
            9. Perform again PIN verification with an correct PIN; it should return CTAP2_ERR_PIN_AUTH_BLOCKED. (Because we did not did power cycle reset);
            10. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
            11. Perform PIN verification with an incorrect PIN with again 8 times times.;
            12. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’). """,
    
        "pinBlockMultiple-Verify2": """Test started: P-19 :
            Precondition: The authenticator has been reset and a PIN is configured.;
            Steps:;
            1. Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            2. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
            3. Perform PIN verification with an incorrect PIN with again 8 times times.;
            4. Then execute the getPinRetries command to retrieve the current retry count should be same as step 2  (denoted as ‘XX’).;
            5. After performing a power-cycle reset, retrieve the PIN retry count again, the authenticator must return the same retry count ‘XX’ as step 2.;
            6. Perform again PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            7. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
            8. Perform PIN verification with an incorrect PIN with again 8 times times.;
            9. Then execute the getPinRetries command to retrieve the current retry count should be same as step 7  (denoted as ‘YY’).;
            10. After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count YY as step 7.;
            11. Perform PIN verification with an incorrect PIN with again 1 times times then authenticator should return  CTAP2_ERR_PIN_INVALID (0x31).;
            12. Then execute the getPinRetries command to retrieve the current retry count should be 1;
            13. Do PIN verification succesful;
            14. Then execute the getPinRetries command to retrieve the current retry count should be Max (8).""",
    


    }

    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])
    util.ResetCardPower()
    util.ConnectJavaCard()

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    if reset_required == "yes":
        util.ResetCardPower()
        util.ConnectJavaCard()
        util.APDUhex("00A4040008A0000006472F0001", "Select applet")
        util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        util.APDUhex("80100000010400", "GetInfo")

    if set_pin_required == "yes":
        Setpinp22.setpin(curPin)  #Set new pin 12345678
        if reset_required == "yes":
            print("*************** PIN Configured is : ",curPin," ***************")
        else:
            util.printcolor(util.YELLOW, "PIN is not Configured !!!")
    else:
        util.printcolor(util.YELLOW, "PIN is not Configured !!!")

    
    if mode == "maxRetryCount":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        value = getRetryCountInInteger(response)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        print("*************** Maximum PIN Retry Count  : ",value," ***************")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "incorrectPinVerifyAndRetryCount":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Maximum PIN Retry Count  : ",value," ***************")
        getPINtokenPubkey1("12348765")
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value1 = getRetryCountInInteger(response)
        if value1 == value-1:
            print("*************** Remaining PIN Retry Count  : ",value1," ***************")
            getPINtokenPubkey1(curPin)
            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value = getRetryCountInInteger(response)
            print("*************** Restored PIN Retry Count  : ",value," ***************")
        else:
            print("*************** Remaining PIN Retry Count not reduced by one  : ",value1," ***************")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "incorrectPinChangeAndRetryCount":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Maximum PIN Retry Count  : ",value," ***************")
        changePINOnly("12348765","12345678")
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value1 = getRetryCountInInteger(response)
        if value1 == value-1:
            print("*************** Remaining PIN Retry Count  : ",value1," ***************")
            changePINOnly(curPin,"12345678")
            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value = getRetryCountInInteger(response)
            print("*************** Restored PIN Retry Count  : ",value," ***************")
        else:
            print("*************** Remaining PIN Retry Count not reduced by one  : ",value1," ***************")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "pinBlock":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Total allowed PIN Retry Count  : ",value," ***************")

        if value > 0:
            while value > 0:
                util.ResetCardPower()
                util.ConnectJavaCard()
                for i in range(3):
                    getPINtokenPubkey1("12348765")
                    response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                    value = getRetryCountInInteger(response)
                    print("*************** Remaining PIN Retry Count  : ",value," ***************")
                    if value == 0:
                        util.printcolor(util.GREEN, f"PIN is blocked !!!")
                        break
        else:
            util.printcolor(util.RED, f"PIN is blocked already !")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "afterPowerCycleSameRetryCount":
        scenarioCount += 1
        for i in range(3):
            getPINtokenPubkey1("12348765")
            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value = getRetryCountInInteger(response)
            print("*************** Remaining PIN Retry Count  : ",value," ***************")
        print("*************** Remaining PIN Retry Count before Powercycle Reset  : ",value," ***************")
        util.printcolor(util.YELLOW, "Performing Powercycle Reset and Checking Retry Count again...")
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value1 = getRetryCountInInteger(response)
        print("*************** Remaining PIN Retry Count after Powercycle Reset  : ",value1," ***************")
        if value == value1:
            util.printcolor(util.GREEN, "Retry Count is same just Before and After Power Cycle Reset")
        else:
            util.printcolor(util.RED, "Retry Count is not same just Before and After Power Cycle Reset")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "invalidSubCommand":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20101020A00", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "3E":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_ERR_INVALID_SUBCOMMAND)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "subCommandAbsent":
        scenarioCount += 1
        response, status = util.APDUhex("801000000406A1010200", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "14":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_ERR_MISSING_PARAMETER)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "missingDataField":
        scenarioCount += 1
        response, status = util.APDUhex("801000000206A000", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "14":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_ERR_MISSING_PARAMETER)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "unsupportedPinUvAuthProtocol":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20103020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "02":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP1_ERR_INVALID_PARAMETER)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "pinNotSetAndRetryCount":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "35":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_ERR_PIN_NOT_SET)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "pinNotSet-Set-RetryCount":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "35":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_ERR_PIN_NOT_SET)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        util.printcolor(util.YELLOW, "Performing Set PIN...")
        Setpinp22.setpin(curPin)  #Set new pin 12345678
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        util.printcolor(util.GREEN, f"Maximum allowed retry counts: {value}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "misleadPowerCycle":
        scenarioCount += 1
        util.ResetCardPower()
        util.ConnectJavaCard()
        util.APDUhex("00a4040008a0000006472f0001","Select applet")
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "35":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_ERR_PIN_NOT_SET)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        # value = getRetryCountInInteger(response)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "invalidParameterData":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20103020A00", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        # value = getRetryCountInInteger(response)
        if status == "02":
            util.printcolor(util.GREEN, f"Test Case Passed with Expected Status Code : {status}")
        else:
            util.printcolor(util.RED, f"Test Case Failed with Status Code : {status}")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "onlyRequiredParameter":
        scenarioCount += 1
        response, status = util.APDUhex("801000000406A1020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        util.printcolor(util.GREEN, f"Maximum allowed retry counts: {value}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "pinVerify-retryCount-powerCycleReset":
        scenarioCount += 1
        for i in range(3):
            getPINtokenPubkey1("12348765")
            print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")
            
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Remaining PIN Retry Count  : ",value," ***************")
            
        for j in range(8):
            getPINtokenPubkey1("12348765")
            print("*************** ",j+1," time Incorrect PIN Verification Performed  ***************")


        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value2 = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value2," ***************")

        if value == value2:
             util.printcolor(util.GREEN, "*************** PIN Retry Count are same as previous ***************")
        else:
             util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
             failCount += 1
             exit(0)

        util.ResetCardPower()
        util.ConnectJavaCard()

        util.APDUhex("00a4040008a0000006472f0001","Select applet")
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Remaining PIN Retry Count after Power Cycle Reset : ",value," ***************")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "pinBlockMultiple":
            scenarioCount += 1
            for i in range(2):
                for j in range(3):
                    getPINtokenPubkey1("12348765")
                    print("*************** ",j+1," time Incorrect PIN Verification Performed  ***************")
                    
                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                if status == "00":
                    util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                    failCount += 1
                    exit(0)
                value = getRetryCountInInteger(response)
                print("*************** Remaining PIN Retry Count  : ",value," ***************")
                    
                for x in range(8):
                    getPINtokenPubkey1("12348765")
                    print("*************** ",x+1," time Incorrect PIN Verification Performed  ***************")


                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                if status == "00":
                    util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                    failCount += 1
                    exit(0)
                value2 = getRetryCountInInteger(response)
                print("*************** Current PIN Retry Count  : ",value2," ***************")

                if value == value2:
                    util.printcolor(util.GREEN, "*************** PIN Retry Count are same as previous ***************")
                else:
                    util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
                    failCount += 1
                    exit(0)

                util.ResetCardPower()
                util.ConnectJavaCard()

                util.APDUhex("00a4040008a0000006472f0001","Select applet")
                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                if status == "00":
                    util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                    failCount += 1
                    exit(0)
                value = getRetryCountInInteger(response)
                print("*************** Remaining PIN Retry Count after Power Cycle Reset : ",value," ***************")

            for s in range(2):
                response, status = getPINtokenPubkey1("12348765")
                print("*************** ",s+1," time Incorrect PIN Verification Performed  ***************")
            if status == "32":
                util.printcolor(util.GREEN, f"PIN is Blocked !!! with Status Code - {status}")
            else:
                util.printcolor(util.RED, f"Not Expected Status Code - {status}")
                failCount += 1
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "pinBlockMultiple-Verify":
            scenarioCount += 1
            for i in range(3):
                getPINtokenPubkey1("12348765")
                print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")
                    
            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value = getRetryCountInInteger(response)
            print("*************** Remaining PIN Retry Count  : ",value," ***************")
                    
            for j in range(8):
                getPINtokenPubkey1("12348765")
                print("*************** ",j+1," time Incorrect PIN Verification Performed  ***************")


            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value2 = getRetryCountInInteger(response)
            print("*************** Current PIN Retry Count  : ",value2," ***************")

            if value == value2:
                util.printcolor(util.GREEN, "*************** PIN Retry Count are same as previous ***************")
            else:
                util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
                failCount += 1
                exit(0)

            util.ResetCardPower()
            util.ConnectJavaCard()
            util.APDUhex("00a4040008a0000006472f0001","Select applet")

            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value = getRetryCountInInteger(response)
            print("*************** Remaining PIN Retry Count after Power Cycle Reset : ",value," ***************")

            util.printcolor(util.YELLOW, "*************** Performing PIN Verification with Correct PIN ***************")
            response , status = getPINtokenPubkey1(curPin)
            if status == "00":
                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                if status == "00":
                    util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                    failCount += 1
                    exit(0)
                value = getRetryCountInInteger(response)
                print("*************** Total Allowed Retry Counts : ",value," ***************")
            else:
                util.printcolor(util.RED, "*************** PIN Verification Failed !!! ***************")
                failCount += 1
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "pinBlockMultiple-Verify1":
        scenarioCount += 1
        for i in range(2):
            for j in range(3):
                getPINtokenPubkey1("12348765")
                print("*************** ",j+1," time Incorrect PIN Verification Performed  ***************")
                        
            response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
            if status == "00":
                util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
            else:
                util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                failCount += 1
                exit(0)
            value = getRetryCountInInteger(response)
            print("*************** Remaining PIN Retry Count  : ",value," ***************")

            if i == 0:    
                for x in range(8):
                    getPINtokenPubkey1("12348765")
                    print("*************** ",x+1," time Incorrect PIN Verification Performed  ***************")


                response , status = getPINtokenPubkey1(curPin)
                if status == "34":
                    util.printcolor(util.GREEN, f"*************** Expected Status Code - {status} (CTAP2_ERR_PIN_AUTH_BLOCKED)  ***************")
                    response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                    if status == "00":
                        util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                        failCount += 1
                        exit(0)
                    value1 = getRetryCountInInteger(response)
                    if value == value1:
                        util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value1}***************")
                    else:
                        util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
                        failCount += 1
                        exit(0)
                else:
                    util.printcolor(util.RED, f"*************** Not Expected Status Code - {status} ***************")
                    failCount += 1
                    exit(0)

                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001","Select applet")

                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                if status == "00":
                    util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                    failCount += 1
                    exit(0)
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value2} ***************")
                else:
                    util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
                    failCount += 1
                    exit(0)
            else:
                response , status = getPINtokenPubkey1(curPin) 
                if status == "34":
                    util.printcolor(util.GREEN, f"*************** Expected Status Code - {status} (CTAP2_ERR_PIN_AUTH_BLOCKED)  ***************")
                    response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                    if status == "00":
                        util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                    else:
                        util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                        failCount += 1
                        exit(0)
                    value3 = getRetryCountInInteger(response)
                    if value == value3:
                        util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value3}***************")
                    else:
                        util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
                        failCount += 1
                        exit(0)
                else:
                    util.printcolor(util.RED, f"*************** Not Expected Status Code - {status} ***************")
                    failCount += 1
                    exit(0)

                for i in range(8):
                    getPINtokenPubkey1("12348765")
                    print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")

                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                if status == "00":
                    util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
                else:
                    util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
                    failCount += 1
                    exit(0)
                value4 = getRetryCountInInteger(response)
                if value == value4:
                    util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value4}***************")
                else:
                    util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
                    failCount += 1
                    exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "pinBlockMultiple-Verify2":
        scenarioCount += 1
        #Step-1
        for i in range(3):
            getPINtokenPubkey1("12348765")
            print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")

        #Step-2
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value," ***************")

        #Step-3
        for i in range(8):
            getPINtokenPubkey1("12348765")
            print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")

        #Step-4
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value1 = getRetryCountInInteger(response)
        if value == value1:
            util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value1}***************")
        else:
            util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
            failCount += 1
            exit(0)

        #Step-5
        util.ResetCardPower()
        util.ConnectJavaCard()
        util.APDUhex("00a4040008a0000006472f0001","Select applet")

        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value2 = getRetryCountInInteger(response)
        if value == value2:
            util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value2} ***************")
        else:
            util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
            failCount += 1
            exit(0)


        #Step-6
        for i in range(3):
            response, status = getPINtokenPubkey1("12348765")
            print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")

        if status == "34":
            util.printcolor(util.GREEN, f"*************** Expected Status Code - {status}(CTAP2_ERR_PIN_AUTH_BLOCKED) ***************")
        else:
            util.printcolor(util.GREEN, f"*************** Not Expected Status Code - {status} ***************")
            failCount += 1
            exit(0)


        #Step-7
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value," ***************")

        #Step-8
        for i in range(8):
            getPINtokenPubkey1("12348765")
            print("*************** ",i+1," time Incorrect PIN Verification Performed  ***************")


        #Step-9
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value3 = getRetryCountInInteger(response)
        if value == value3:
            util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value3} ***************")
        else:
            util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
            failCount += 1
            exit(0)


        #Step-10
        util.ResetCardPower()
        util.ConnectJavaCard()
        util.APDUhex("00a4040008a0000006472f0001","Select applet")

        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value4 = getRetryCountInInteger(response)
        if value == value4:
            util.printcolor(util.GREEN, f"*************** PIN Retry Count are same as previous i.e. {value4} ***************")
        else:
            util.printcolor(util.RED, "*************** PIN Retry Count are not same as previous ***************")
            failCount += 1
            exit(0)

        #Step-11
        response, status = getPINtokenPubkey1("12348765")
        if status == "31":
            util.printcolor(util.GREEN, f"*************** Expected Status Code - {status}(CTAP2_ERR_PIN_INVALID) ***************")
        else:
            util.printcolor(util.RED, f"*************** Not Expected Status Code - {status} ***************")
            failCount += 1
            exit(0)

        #Step-12
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value5 = getRetryCountInInteger(response)
        if value5 == 1:
            util.printcolor(util.GREEN, f"*************** Current Retry Count - {value5} ***************")
        else:
            util.printcolor(util.RED, f"*************** Unexpected Retry Count - {value5} ***************")
            failCount += 1
            exit(0)

        #Step-13
        response, status = getPINtokenPubkey1(curPin)
        if status == "00":
            util.printcolor(util.GREEN, f"*************** PIN Verification Successful ***************")
        else:
            util.printcolor(util.RED, f"*************** PIN Verification Unuccessful with Status Code - {status} ***************")
            failCount += 1
            exit(0)


        #Step-14
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        if value != 1:
            util.printcolor(util.GREEN, f"*************** Current Retry Count - {value} ***************")
        else:
            util.printcolor(util.RED, f"*************** Unexpected Retry Count - {value} ***************")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


def getRetryCountInInteger(response):
    # Convert to bytes
    data = bytes.fromhex(response)

    # Find index of key 0x03
    key = 0x03
    index = data.index(key)

    # Get value after key
    value_hex = data[index + 1]

    # Convert to int
    value_int = int(value_hex)
    return value_int



def verifyPIN(curpin, rp, user):

    # ------------------------------
    #   SELECT + GETINFO
    # ------------------------------
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------
    #   COMMON FIELDS
    # ------------------------------
    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkeyTemp(curpin)
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
        return "80108000" + lc + finalPayload

    # Chained APDU
    return util.build_chained_apdus(payload)

def getPINtokenPubkeyTemp(curpin):
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

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
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

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

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

def changePINOnly(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
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

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand



def getPINtokenPubkey1(curpin):
    
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken1(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)
    
    return hexstring, status
     

    
    
   


def createGetPINtoken1(pinHashenc, key_agreement):
    
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





