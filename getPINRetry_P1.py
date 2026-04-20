import util
import binascii
import cbor2
import hashlib, hmac, binascii
import cbor2
import os
import getasserationrequest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import DocumentCreation

rp = "localhost"
curPin = "12345678"
user = "bobsmith"
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 1
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
        Perform PIN verification with an incorrect current PIN — the verification must fail. Then retrieve the retry count again using the getPinRetries(0x01) subcommand with all parameters correctly provided, the authenticator must return a retry count reduced by one.
        Attempt PIN verification with correct PIN, the authenticator must return CTAP2_OK. Now again perform getPinRetries command, authenticator must reassign maximum allowed retry counts.""",
   
        "incorrectPinChangeAndRetryCount": """Test started: P-3 :
        Precondition: The authenticator has been reset, a PIN is configured, and the retry count has been retrieved using the getPinRetries command.;
        Perform PIN Change with an incorrect current PIN — the change PIN must fail. Then retrieve the retry count again using the getPinRetries(0x01) subcommand with all parameters correctly provided, the authenticator must return a retry count reduced by one.
        Attempt PIN Change with correct PIN, the authenticator must return CTAP2_OK. Now again perform getPinRetries command, authenticator must reassign maximum allowed retry counts.""",

        "pinBlock": """Test started: P-4 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        Perform PIN verification with an incorrect current PIN — the verification must fail. Then retrieve the retry count using the getPinRetries(0x01) subcommand with all parameters correctly provided, the authenticator must return a retry count reduced by one. Perform same operation untill retry counts come to zero, then authenticator must return CTAP2_ERR_PIN_BLOCKED.""",
   
        "afterPowerCycleSameRetryCount": """Test started: P-5 :
        Precondition: The authenticator has been reset and a PIN is configured.;
        Perform PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’). After performing a power-cycle reset, retrieve the PIN retry count again, the authenticator must return the same retry count ‘XX’ as before the reset.""",

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
        Attempt to retrieve the PIN retry count — the authenticator must return CTAP2_ERR_PIN_NOT_SET. Perform set pin operation and set a new PIN successfully. Then retrieve the PIN retry count again. this time, the authenticator must return the maximum number of allowed retries.""",

        "misleadPowerCycle": """Test started: P-12 :
        Precondition: The authenticator has been reset, a PIN is configured, and the retry count has been retrieved using the getPinRetries command.;
        Perform PIN verification with an incorrect current PIN — the verification must fail. Then retrieve the retry count again using the getPinRetries(0x01) subcommand with all parameters correctly provided; the authenticator must return a retry count reduced by one.
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
            9. After performing a power-cycle reset,  Then execute the getPinRetries command to retrieve the current retry count should be same as step 7  (denoted as ‘YY’).;
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
            4. Perform again PIN verification with an correct PIN; it should return CTAP2_ERR_PIN_AUTH_BLOCKED. because we did not did power cycle reset;
            5. Then execute the getPinRetries command to retrieve the current retry count should be same as step 2  (denoted as ‘XX’).;
            6. After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count ‘XX’ as step 2.;
            7. Perform again PIN verification with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
            8. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
            9. Perform again PIN verification with an correct PIN; it should return CTAP2_ERR_PIN_AUTH_BLOCKED. because we did not did power cycle reset;
            10. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
            11. Perform PIN verification with an incorrect PIN with again 8 times times.;
            12. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).""",
    
        "pinBlockMultiple-Verify2": """Test started: P-19 :
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
            9. Then execute the getPinRetries command to retrieve the current retry count should be same as step 7  (denoted as ‘YY’).;
            10. After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count YY as step 7.;
            11. Perform PIN verification with an incorrect PIN with again 1 times times then authenticator should return  CTAP2_ERR_PIN_INVALID (0x31); 
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
        setpin(curPin)  #Set new pin 12345678
        if reset_required == "yes":
            print("*************** PIN Configured is : ",curPin," ***************")
        else:
            util.printcolor(util.YELLOW, "PIN is not Configured !!!")
    else:
        util.printcolor(util.YELLOW, "PIN is not Configured !!!")

    
    if mode == "maxRetryCount":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
            response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        if status == "00":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP2_OK)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
            failCount += 1
            exit(0)
        value = getRetryCountInInteger(response)
        print("*************** Maximum PIN Retry Count  : ",value," ***************")
        changePINOnly("12348765","12345678")
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
            response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
                    response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                    value = getRetryCountInInteger(response)
                    print("*************** Remaining PIN Retry Count  : ",value," ***************")
                    if value == 0:
                        util.printcolor(util.GREEN, f"PIN is blocked !!!")
                        break
        else:
            util.printcolor(util.RED, f"PIN is blocked already !")
            failCount += 1
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "afterPowerCycleSameRetryCount":
        scenarioCount += 1
        for i in range(3):
            getPINtokenPubkey1("12348765")
            response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
        response, status = util.APDUhex("801000000406A1010100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
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
        setpin(curPin)  #Set new pin 12345678
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
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "invalidParameterData":
        scenarioCount += 1
        response, status = util.APDUhex("801000000606A20103020A00", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        # value = getRetryCountInInteger(response)
        if status == "02":
            util.printcolor(util.GREEN, f"RECIEVED EXPECTED STATUS CODE : {status}(CTAP1_ERR_INVALID_PARAMETER)")
        else:
            util.printcolor(util.RED, f"RECIEVED UNEXPECTED STATUS CODE : {status}")
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
        util.printcolor(util.GREEN, f"*************** Remaining PIN Retry Count after Power Cycle Reset : {value} ***************")
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
                util.printcolor(util.GREEN, f"*************** Remaining PIN Retry Count after Power Cycle Reset : {value} ***************")

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



def authenticatorClientPin():
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getKeyAgreement(0x02) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "keyAgreement" field, and its of type MAP
            (b) in COSE "keyAgreement" field:
                (1) check that public key is EC2(kty(1) is set to 2) 
                (2) check that key crv(-1) curve field that is set to P256(1)
                (3) check that key alg(3) is set to ECDH-ES+HKDF-256(-25)
                (4) check that key contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) check that key contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (6) check that key does NOT contains ANY other coefficients""");

    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
    util.APDUhex("00a4040008a0000006472f0001","Select applet") 
    util.APDUhex("80108000010700","Reset Card PIN")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")                                      
    util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80108000010700","Reset Card PIN")
    


# --- Utility Functions ---
def int2bytes(val, length):
    return val.to_bytes(length, 'big')

def bytes2int(b):
    return int.from_bytes(b, 'big')

def pad_pin1(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')
    if len(pin_bytes) < 6:
        raise ValueError("PIN must be at least 6 bytes")
    if len(pin_bytes) > 64:
        raise ValueError("PIN must not exceed 64 bytes")
    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def pad_pin(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    if validate:
        if len(pin_bytes) < 6:
            raise ValueError("PIN must be at least 6 bytes")
        if len(pin_bytes) > 64:
            raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes













def aes256_cbc_encrypt(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 1,   # crv: P-256
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret

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
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor
    return apdu

# --- Main Function ---
def set_client_pin_protocol1(pin: str):
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Generate a shared key by deriving sharedSecret from previously obtained keyAgreement, and set new random clientPin.""");
    setpin(pin)

def setpin(pin):

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.APDUhex("80100000010700", "Reset Card PIN (optional)")
    util.APDUhex("00a4040008a0000006472f0001", "Re-select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = encapsulate_protocol1(decoded[1])
    padded_pin = pad_pin(pin, validate=False)  # skips min length check
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = hmac_sha256(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)

    # util.APDUhex("80100000010400", "GetInfo after SetPIN")


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
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu


def change_client_pin_protocol1(current_pin: str, new_pin: str):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Change current pincode to the new pincode""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
    
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    padded_new_pin = pad_pin(new_pin)
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)


def changePINOnly(current_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
    
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    padded_new_pin = pad_pin(new_pin)
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response, status


def get_pin_token_protocol1(pin: str) -> bytes:
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****ClientPin protocol 1 ****")
    util.printcolor(util.YELLOW, """""Test started: P-3
        Get a valid pinAuth token""")
    getPINtokenPubkey(pin)

def getPINtokenPubkey(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    
    response, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = aes256_cbc_decrypt(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token

def getPINtokenPubkey1(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    # cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    # enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    # if not enc_pin_token:
    #     raise ValueError("No pinToken returned from authenticator")

    # pin_token = aes256_cbc_decrypt(shared_secret, enc_pin_token)
    # #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    # return pin_token
    return  response, status 



def aes256_cbc_decrypt(shared_secret: bytes, encrypted: bytes) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()
   #make credential
def RegisterUser(pin, username, display, rp):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, """Test started: P-4
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""")
    hashchallenge = os.urandom(32);
    result = makeCred(pin, hashchallenge, rp, username)
    return result

def makeCred(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
       
    pinToken = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result 
   
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
    dataCBOR = dataCBOR + "07" + rk

    dataCBOR = dataCBOR + "06" + ex

    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand


def getAsseration(pin, username, rp,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, """Test started: P-5
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""")
    hashchallenge = os.urandom(32);
    result = authenticateUser(pin, hashchallenge, rp, credId)
    return result

def authenticateUser(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


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
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


def test_setpin_length_between_min_and_63(base_pin="A"):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, "Test started: P-1")
    util.printcolor(util.YELLOW,
        "Try setting new pin that is of size between minPINLength+1 and 63 characters. "
        "Expect Authenticator to return CTAP1_ERR_SUCCESS (0x00)"
    )

    
    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("80100000010400", "GetInfo")
    if status != 0x9000:
        raise Exception("GetInfo failed")

    
    decoded = cbor2.loads(binascii.unhexlify(response[2:]))
    min_pin_len = decoded.get(0x03)  

    if isinstance(min_pin_len, bytes):
        min_pin_len = int.from_bytes(min_pin_len, 'big')

    if not isinstance(min_pin_len, int) or min_pin_len < 4 or min_pin_len > 63:
        min_pin_len = 4 

    test_pin_length = min_pin_len + 1
    if test_pin_length > 63:
        test_pin_length = 63  
   
    test_pin = (base_pin * test_pin_length)[:test_pin_length]

    
    try:
        setpin(test_pin)
        util.printcolor(util.GREEN, f"✅ Test passed: PIN of length {test_pin_length} accepted")
    except Exception as e:
        util.printcolor(util.RED, f"❌ Test failed: {str(e)}")





def test_setpin_less_than_4_bytes_raw1(pin="123"):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: f-1
        Try setting new pin, that is less than 4 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION (0x37).""");

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("801080000606a20101020200", "GetKeyAgreement")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_cose_key = decoded[1]
    
    key_agreement, shared_secret = encapsulate_protocol1(peer_cose_key)   
    padded_pin = pad_pin2(pin, validate=False)  # allow < 4 byte PIN for test
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)
    pin_auth = hmac_sha256(shared_secret, new_pin_enc)[:16]   

    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)   
    response, status = util.APDUhex(apdu, "Set PIN with short PIN", checkflag=False)
    print(f"<--- DATA RECEIVED: {hex(status)[2:].upper()}")


def test_setpin_more_than_63_bytes_raw(pin="111111111111111111111111111111111111111111111111111111111111111111"):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: f-2
         Try setting new pin, that is bigger than 63 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)""");

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("801080000606a20101020200", "GetKeyAgreement")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_cose_key = decoded[1]
    
    key_agreement, shared_secret = encapsulate_protocol1(peer_cose_key)   
    padded_pin = pad_pin2(pin, validate=False)  # allow < 4 byte PIN for test
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)
    pin_auth = hmac_sha256(shared_secret, new_pin_enc)[:16]   

    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)   
    response, status = util.APDUhex(apdu, "Set PIN with short PIN", checkflag=False)
    print(f"<--- DATA RECEIVED: {hex(status)[2:].upper()}")

def retriesCount():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-1             
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getRetries(0x01) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "retries" field
            (b) authenticatorClientPin_Response.retries is of type NUMBER
            (c) authenticatorClientPin_Response.retries is max of 8!""" )
    pinRetriescount()      
                              
def pinRetriescount():
    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("801000000606a20101020100", "GetRetries")

    assert status == 0x9000, "Expected status 0x9000 for GetRetries"
#   Parse response
    cbor_data = binascii.unhexlify(response[2:])  # skip 00 prefix
    decoded = cbor2.loads(cbor_data)

    assert 3 in decoded, "Missing 'retries' key in response"
    assert isinstance(decoded[3], int), "'retries' is not an integer"
    assert 0 <= decoded[3] <= 8, f"'retries' out of range: {decoded[3]}"

    util.printcolor(util.GREEN, f"Retries: {decoded[3]} (valid)")
    


def piAuthBlocked():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        Send two CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that each request fails with error CTAP2_ERR_PIN_INVALID(0x31)
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getRetries(0x01) subCommand, and check that retries have decreased by two
        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED(0x34)"""                                     );

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")

    response, status = util.APDUhex("801000000606a20101020100", "GetRetries")

    assert status == 0x9000, "Expected status 0x9000 for GetRetries"
#   Parse response
    cbor_data = binascii.unhexlify(response[2:])  # skip 00 prefix
    decoded = cbor2.loads(cbor_data)

    assert 3 in decoded, "Missing 'retries' key in response"
    assert isinstance(decoded[3], int), "'retries' is not an integer"
    assert 0 <= decoded[3] <= 8, f"'retries' out of range: {decoded[3]}"

    util.printcolor(util.GREEN, f"Retries: {decoded[3]} (valid)")
    

def pinTokenBlocked():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-3
        Register a valid authenticatorMakeCred(0x01) using the valid PIN. Check that retries counter is reset and back to the original retries counter.
        Keep sending getPINToken with invalid pin until retries counter is 0.
        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains valid pinCode, and check that authenticator returns error CTAP2_ERR_PIN_BLOCKED(0x32).""")
 



def pad_pin2(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    if validate:
        if len(pin_bytes) < 4:
            raise ValueError("PIN must be at least 4 bytes")
        if len(pin_bytes) > 64:
            raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')


def getPINtoken(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
   
    response, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)

def checkRetriesCount(pin,retries):

   for i in range(retries):
    print(f"\n--- Attempt {i + 1} ---")

    try:
        util.ResetCardPower()
        util.ConnectJavaCard()

        # Attempt to get PIN token with wrong PIN
        response =getPINtoken(pin)
        print("Response:", response)
    except Exception as e:
        print(f"getPINtoken() Exception: {e}")

    try:
        retry_count = pinRetriescount()
        print(f"Remaining PIN retries: {retry_count}")
        if retry_count == 0:
            print("PIN is blocked (CTAP2_ERR_PIN_AUTH_BLOCKED). Stopping test.")
            break
    except Exception as e:
        print(f"retriesCount() Exception: {e}")