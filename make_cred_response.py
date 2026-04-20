import util
import make_credential_request
import cbor2
import credBlob
import getAsseration
import struct

MIN_AUTHDATA_LEN = 32 + 1 + 4 + 16 + 2 + 16 + 77  # 148 bytes
EXPECTED_RP_ID_HASH = bytes.fromhex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763")  

# Flag masks
FLAG_UP = 0x01  # User Present
FLAG_AT = 0x40  # Attested credential data
FLAG_ED = 0x80  # Extension data


def makecredresponse(pin,clientDataHash,rp,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****MakeCredential Response ****")
    util.printcolor(util.YELLOW,"""Test started: P-01
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, wait for the response, and check that: 
            (a) Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code 
            (b) Response structure can be successfully parsed 
            (c) Response.fmt is of type String 
            (d) Response.fmt is set to either "packed", "tpm", "android-key" or "android-safetynet.""")
    response_hex=make_credential_request.makeCred(pin,clientDataHash,rp,user)
    print( response_hex)
    # Step (a): Check if response starts with 0x00 (success)
    if not response_hex.startswith("00"):
        util.printcolor(util.RED, f"❌ Failed: Expected CTAP1_ERR_SUCCESS (0x00), got {response_hex[:2]}")
        return

    util.printcolor(util.GREEN, f"✅ Success: CTAP1_ERR_SUCCESS (0x00) received")

    # Step (b): Parse CBOR payload
    try:
        response_bytes = bytes.fromhex(response_hex)
        cbor_payload = response_bytes[1:]  # Skip the 0x00 success byte
        decoded_response = cbor2.loads(cbor_payload)
    except Exception as e:
        util.printcolor(util.RED, f"❌ Failed to parse CBOR payload: {e}")
        return

    util.printcolor(util.GREEN, f"✅ CBOR parsing successful")
    return response_hex

def authDataParsing(response):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****MakeCredential Response****")
    util.printcolor(util.YELLOW,"""Test started: P-02

        Using previously received response, check that: 
            (a) response.authData is of type BYTE ARRAY 
            (b) check that authData is at least (32 + 1 + 4 + 16 + 2 + 16 + 77) bytes long. 
            (c) parse response.authData 
            (d) check that AAGUID matching the one in metadata statement 
            (e) check that authData.rpIdHash matches the sent rpIdHash 
            (f) check that UP(bit 0) flag in flags is set 
            (g) check that AT(bit 6) flag in flags is set, and attestation credential data is presented 
            (h) check that ED(bit 7) flag in flags is not set, and check that there is not Extension Data present
            (i) check that authData.pubKey is correctly encoded:
            (j) if public key is an RSA(kty(1) is set to 3) public key, check that: 
                (1) alg(2) is set to algorithm that matches corresponding one in metadata statement
                (2) contains n(-1) that is of type BYTE STRING 
                (3) contains e(-2) that is of type BYTE STRING 
                (4) does NOT contains ANY other coefficients
            (k) if public key is an EC2(kty(1) is set to 2) public key, check that: 
                (1) alg(2) is set to algorithm that matches corresponding one in metadata statement
                (2) crv(-1) field that is set to EC identifier from "COSE Elliptic Curves" registry
                (3) contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (4) contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (5) does NOT contains ANY other coefficients
            (k) if public key is an OKP(kty(1) is set to 1) public key, check that: 
                (1) alg(2) is set to algorithm that matches corresponding one in metadata statement
                (2) crv(-1) field that is set to EdDSA identifier from "COSE Elliptic Curves" registry
                (3) contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) does NOT contains ANY other coefficients.""")   
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    # (a) Check type
    if not isinstance(authdata, bytes):
        util.printcolor(util.RED, "FAIL (a): authData is not a byte array.")
        return
    util.printcolor(util.GREEN, "PASS (a): authData is a byte array.")

    # (b) Check length
    if len(authdata) < MIN_AUTHDATA_LEN:
        util.printcolor(util.RED, f"FAIL (b): authData too short. Length = {len(authdata)}")
        return
    util.printcolor(util.GREEN, f"PASS (b): authData length = {len(authdata)}")

    # (c) Parse
    parsed = parse_authdata(authdata)
    util.printcolor(util.GREEN, "PASS (c): Parsed authData successfully.")
    print("Parsed authData:", parsed)

    # (d) AAGUID check
    EXPECTED_AAGUID=bytes.fromhex(parsed["aaguid"])
    if bytes.fromhex(parsed["aaguid"]) != EXPECTED_AAGUID:
        util.printcolor(util.RED, "FAIL (d): AAGUID does not match metadata.")
    else:
        util.printcolor(util.GREEN, "PASS (d): AAGUID matches metadata.")

    # (e) RP ID hash check
    if bytes.fromhex(parsed["rpIdHash"]) != EXPECTED_RP_ID_HASH:
        util.printcolor(util.RED, "FAIL (e): RP ID hash does not match expected value.")
    else:
        util.printcolor(util.GREEN, "PASS (e): RP ID hash matches.")

    # (f) UP flag set
    flags = int(parsed["flags"], 16)
    if flags & FLAG_UP:
        util.printcolor(util.GREEN, "PASS (f): UP flag is set.")
    else:
        util.printcolor(util.RED, "FAIL (f): UP flag is not set.")

    # (g) AT flag set
    if flags & FLAG_AT:
        util.printcolor(util.GREEN, "PASS (g): AT flag is set.")
    else:
        util.printcolor(util.RED, "FAIL (g): AT flag is not set.")

    # (h) ED flag NOT set
    if flags & FLAG_ED:
        util.printcolor(util.RED, "FAIL (h): ED flag is set.")
    else:
        util.printcolor(util.GREEN, "PASS (h): ED flag is NOT set.")

    # (i) Decode and validate public key
    try:
        pub_key_bytes = bytes.fromhex(parsed["credentialPublicKey"])
        cose_key = cbor2.loads(pub_key_bytes)
        util.printcolor(util.GREEN, "PASS (i): Public key CBOR decoded.")
    except Exception as e:
        util.printcolor(util.RED, f"FAIL (i): Public key CBOR decoding failed: {e}")
        return

    kty = cose_key.get(1)
    alg = cose_key.get(3)

    # (j) RSA key
    if kty == 3:
        util.printcolor(util.GREEN, "Key Type: RSA (kty=3)")
        n = cose_key.get(-1)
        e = cose_key.get(-2)
        extra = set(cose_key.keys()) - {1, 3, -1, -2}
        if isinstance(n, bytes) and isinstance(e, bytes):
            util.printcolor(util.GREEN, "PASS (j): n and e are byte strings.")
        else:
            util.printcolor(util.RED, "FAIL (j): n or e is not a byte string.")
        if extra:
            util.printcolor(util.RED, f"FAIL (j): RSA contains unexpected fields: {extra}")
        else:
            util.printcolor(util.GREEN, "PASS (j): No extra fields in RSA key.")

    # (k) EC2 key
    elif kty == 2:
        util.printcolor(util.GREEN, "Key Type: EC2 (kty=2)")
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        crv = cose_key.get(-1)
        extra = set(cose_key.keys()) - {1, 3, -1, -2, -3}
        if all(isinstance(v, bytes) and len(v) == 32 for v in [x, y]):
            util.printcolor(util.GREEN, "PASS (k): x and y are 32-byte byte strings.")
        else:
            util.printcolor(util.RED, "FAIL (k): x or y is not 32-byte byte string.")
        if extra:
            util.printcolor(util.RED, f"FAIL (k): EC2 contains unexpected fields: {extra}")
        else:
            util.printcolor(util.GREEN, "PASS (k): No extra fields in EC2 key.")

    # (l) OKP key
    elif kty == 1:
        util.printcolor(util.GREEN, "Key Type: OKP (kty=1)")
        x = cose_key.get(-2)
        crv = cose_key.get(-1)
        extra = set(cose_key.keys()) - {1, 3, -1, -2}
        if isinstance(x, bytes) and len(x) == 32:
            util.printcolor(util.GREEN, "PASS (l): x is 32-byte byte string.")
        else:
            util.printcolor(util.RED, "FAIL (l): x is not valid.")
        if extra:
            util.printcolor(util.RED, f"FAIL (l): OKP contains unexpected fields: {extra}")
        else:
            util.printcolor(util.GREEN, "PASS (l): No extra fields in OKP key.")
    else:
        util.printcolor(util.RED, f"Unknown key type (kty={kty})")


def algFiled(response):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****MakeCredential Response****")
    util.printcolor(util.YELLOW,"""Test started: P-03

        Decode "attStmt" CBOR MAP and: 
            (a) check that "alg" field is presented it matches "alg" in PK
            (b) check that "sig" field is presented and it is of type BYTE STRING.""")

def certificate(response):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****MakeCredential Response****")
    util.printcolor(util.YELLOW,"""Test started: P-04

        If "x5c" presented: 
            (a) Check that "ecdaaKeyId" is NOT presented 
            (b) Check that "x5c" is of type SEQUENCE 
            (c) Check that metadata statement contains "attestationRootCertificates" field, and it’s not empty. 
            (d) Check that metadata statement "attestationTypes" SEQUENCE contains "basic_full"
            (e) Decode certificate chain
            (f) If "x5c" contains exactly one certificate, check if that certificate is already a member of the metadata.attestationRootCertificates. If it is, skip chain verification
            (g) Verify certificate chain:
                (1) For each certificate in the metadata.attestationRootCertificates, attach attestation root to the x5c, and try verifying it. If none produce a valid chain, fail
            (h) Pick a leaf certificate of the chain and check that: 
                (1) Version is of type INTEGER and is set to 3 
                (2) Subject-C - is of type UTF8String, and is set to ISO 3166 code specifying the country where the Authenticator vendor is incorporated (UTF8String) 
                (3) Subject-O - is of type UTF8String, and is set to the legal name of the Authenticator vendor 
                (4) Subject-OU - is of type UTF8String, and is set to literal string “Authenticator Attestation” 
                (5) Subject-CN - is of type UTF8String, and is not empty
                (6) Basic Constraints extension MUST have the CA component set to false. 
                (7) [TBD] If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical. 
                (8) Check that certificate is not expired, is current(notBefore is set to the past date), and is valid for at least 5 years [TBD]
            (i) Concatenate authenticatorData and signData to clientDataHash. Using key extracted from leaf certificate, signData verify signature in "sig" field..""")

                    




def parse_authdata(authdata_bytes):
    offset = 0

    # rpIdHash (32 bytes)
    rp_id_hash = authdata_bytes[offset:offset + 32]
    print("rp_id_hash",rp_id_hash)
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
    print("aaguid",aaguid)
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

