CMD_MAKE_CREDENTIAL = 0x01
def dataChunk(responseData):
    import util  # your util.py

    newdata = format(CMD_MAKE_CREDENTIAL, '02X')  # '01'
    encodeCBORdata = newdata + responseData
    util.printcolor(util.YELLOW, f"\nGenerating MakeCredential CBOR for struct... {encodeCBORdata}")
    
    encodeCBORdatabytes = bytes.fromhex(encodeCBORdata)
    response_apdu = None
    
    if len(encodeCBORdatabytes) > 239:
        chunk_size = 239 * 2  # hex chars
        command_chunks = util.split_command_apdu1(encodeCBORdata, chunk_size)

        # First command APDU
        first_command = "90100000"
        first_command_data = command_chunks[0]
        first_command_apdu = first_command + format(len(first_command_data) // 2, '02X') + first_command_data
        util.printcolor(util.CYAN, f"First command chain: {first_command_apdu}")

        util.APDUhex(first_command_apdu, "Registration command ->")

        for i in range(1, len(command_chunks)):
            intermediate_data = command_chunks[i]
            if i == len(command_chunks) - 1:
                last_command = "80100000"
                last_command_apdu = last_command + format(len(intermediate_data) // 2, '02X') + intermediate_data + "00"
                util.printcolor(util.CYAN, f"Last command chain: {last_command_apdu}")
                util.APDUhex( last_command_apdu, "Registration command ->")
                  
    else:
        data_length = len(encodeCBORdatabytes)
        total_length_hex = format(data_length, '02X')
        data = encodeCBORdata.upper()
        registration_command = "801000000000" + total_length_hex + data
        command = bytes.fromhex(registration_command)
        util.APDUhex(registration_command, "Registration command ->")
    return response_apdu
    