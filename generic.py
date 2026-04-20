import util
import binascii
import cbor2

def getInfo():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: P-1
        Send a valid CTAP2 GetInfo request, wait for the response and check that:
            (a) CTAP2 responseCode is CTAP1_ERR_SUCCESS(0x00)
            (b) Check that version(0x01) field is presented and is set to "FIDO_2_1"
            (c) Check that aaguid(0x03) field is presented and is 16 bytes long & Check that aaguid(0x03) field value matches Metadata.aaguid
            (d) If GetInfo contains extensions(0x03) field, check that its of type SEQUENCE, and only contains STRINGS
            (e) If GetInfo contains options(0x04) field, check that its of type MAP
            (f) If GetInfo contains maxMsgSize(0x05) field, check that its of type NUMBER
            (g) If GetInfo contains pinUvAuthProtocols(0x06) field, check that its of type SEQUENCE, and only contains NUMBERS
            (h) If GetInfo contains maxCredentialCountList(0x07) check that its of type NUMBER, greater than 0
            (i) If GetInfo contains maxCredentialIdLength(0x08) check that its of type NUMBER, greater than 0
            (j) If GetInfo contains 'transports' (0x09) check that its of type SEQUENCE, and only contains STRINGS
            (k) If GetInfo contains 'algorithms'(0x0A)  TODO                  
            (l) If GetInfo contains 'maxSerializedLargeBlobArray'(0x0B)      
            (m) If GetInfo contains 'forcePINChange'(0x0C)                   
            (n) If GetInfo contains 'minPINLength'(0x0D)                     
            (o) If GetInfo contains 'firmwareVersion'(0x0E)                  
            (p) If GetInfo contains 'maxCredBlobLength'(0x0F)                
            (q) If GetInfo contains 'maxRPIDsForSetMinPINLength'(0x10)       
            (r) If GetInfo contains 'preferredPlatformUvAttempts'(0x11)      
            (s) If GetInfo contains 'uvModality'(0x12)                       
            (t) If GetInfo contains 'certifications'(0x13)                   
            (u) If GetInfo contains 'remainingDiscoverableCredentials'(0x14) 
            (v) If GetInfo contains 'vendorPrototypeConfigCommands'(0x15)  

            (---) Check that GetInfo response equals to the metadata.authenticatorGetInfo => Included within relevant block of (*) lettered test.""")
    
    util.printcolor(util.YELLOW,"")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response, status=util.APDUhex("80100000010400", "GetInfo")
    # Check (a): CTAP1_ERR_SUCCESS
    assert status == 0x9000, f"Expected status 0x9000 but got {hex(status)}"
    util.printcolor(util.GREEN, "(a) CTAP1_ERR_SUCCESS returned")

    # Remove status word (last 4 characters) and decode CBOR
    cbor_data = binascii.unhexlify(response[2:])  # remove '01' prefix from response
    decoded = cbor2.loads(cbor_data)

    # Print full decoded map
    util.printcolor(util.CYAN, f"Decoded GetInfo response:\n{decoded}")

    # (b) Check version
    versions = decoded.get(0x01)
    assert versions is not None and "FIDO_2_1" in versions, f"(b) Missing or incorrect versions: {versions}"
    util.printcolor(util.GREEN, "(b) Version includes 'FIDO_2_1'")

    # (c) AAGUID
    aaguid = decoded.get(0x03)
    assert aaguid is not None and isinstance(aaguid, bytes) and len(aaguid) == 16, f"(c) AAGUID invalid: {aaguid}"
    util.printcolor(util.GREEN, "(c) AAGUID is valid 16-byte value")

    # (d) Extensions
    if 0x02 in decoded:
        extensions = decoded[0x02]
        assert isinstance(extensions, list), "(d) Extensions is not a list"
        assert all(isinstance(x, str) for x in extensions), "(d) All extensions should be strings"
        util.printcolor(util.GREEN, "(d) Extensions are valid")

    # (e) Options
    if 0x04 in decoded:
        assert isinstance(decoded[0x04], dict), "(e) Options is not a map"
        util.printcolor(util.GREEN, "(e) Options is a valid map")

    # (f) maxMsgSize
    if 0x05 in decoded:
        assert isinstance(decoded[0x05], int), "(f) maxMsgSize is not a number"
        util.printcolor(util.GREEN, "(f) maxMsgSize is a valid number")

    # (g) pinUvAuthProtocols
    if 0x06 in decoded:
        assert isinstance(decoded[0x06], list), "(g) pinUvAuthProtocols is not a list"
        assert all(isinstance(p, int) for p in decoded[0x06]), "(g) pinUvAuthProtocols list contains non-integers"
        util.printcolor(util.GREEN, "(g) pinUvAuthProtocols is valid")

    # (h) maxCredentialCountInList
    if 0x07 in decoded:
        val = decoded[0x07]
        assert isinstance(val, int) and val > 0, "(h) maxCredentialCountInList is not a valid number"
        util.printcolor(util.GREEN, "(h) maxCredentialCountInList is valid")

    # (i) maxCredentialIdLength
    if 0x08 in decoded:
        val = decoded[0x08]
        assert isinstance(val, int) and val > 0, "(i) maxCredentialIdLength is not a valid number"
        util.printcolor(util.GREEN, "(i) maxCredentialIdLength is valid")

    # (j) transports
    if 0x09 in decoded:
        transports = decoded[0x09]
        assert isinstance(transports, list), "(j) transports is not a list"
        assert all(isinstance(t, str) for t in transports), "(j) transports contains non-strings"
        util.printcolor(util.GREEN, "(j) transports is valid")

    # (k) algorithms
    if 0x0A in decoded:
        algorithms = decoded[0x0A]
        assert isinstance(algorithms, list), "(k) algorithms is not a list"
        util.printcolor(util.GREEN, "(k) algorithms present")

    # (l) to (v): presence and type checks
    optional_map = {
        0x0B: ("maxSerializedLargeBlobArray", int),
        0x0C: ("forcePINChange", bool),
        0x0D: ("minPINLength", int),
        0x0E: ("firmwareVersion", int),
        0x0F: ("maxCredBlobLength", int),
        0x10: ("maxRPIDsForSetMinPINLength", int),
        0x11: ("preferredPlatformUvAttempts", int),
        0x12: ("uvModality", int),
        0x13: ("certifications", dict),
        0x14: ("remainingDiscoverableCredentials", int),
        0x15: ("vendorPrototypeConfigCommands", list),
    }

    for key, (label, expected_type) in optional_map.items():
        if key in decoded:
            assert isinstance(decoded[key], expected_type), f"({label}) is not of type {expected_type.__name__}"
            util.printcolor(util.GREEN, f"({label}) is valid")

    util.printcolor(util.GREEN, "✅ GetInfo response validated successfully.")


def getInfo_option():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: P-2            
        If GetInfo contains Options field: Check that every option in options is of type Boolean. Additionally:
            (a) If "up" is set to true, check that metadata.userVerificationDetails contains VerificationMethodDescriptor that has "userVerification" set to "presence_internal"
            (b) If "uv" is set to true, check that metadata.userVerificationDetails contains VerificationMethodDescriptor that has "userVerification" set to either of "fingerprint_internal", "voiceprint_internal", "faceprint_internal", "eyeprint_internal", "handprint_internal", "pattern_internal", "pattern_external", "passcode_internal", "passcode_external"
            (c) If "uv" and "up" are false, check that metadata.userVerificationDetails contains VerificationMethodDescriptor that has "userVerification" set to "none".""");
    util.printcolor(util.YELLOW,"")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response, status = util.APDUhex("80100000010400", "GetInfo")

def getinfo():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: P-3
        If GetInfo contains pinUvAuthProtocols, and it is not empty, check that Metadata.userVerificationDetails contains VerificationMethodDescriptor set to "passcode_external".""");
    util.printcolor(util.YELLOW,"")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response, status = util.APDUhex("80100000010400", "GetInfo")

    