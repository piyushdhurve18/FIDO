import binascii
import cbor2
import util
import cardResponse
import register
import transports
import make_credential_request
import os

import json
import getAsseration
import getasserationrequest
import test
import residentKey
import hmacSecret2

import getasseration_request
import clientprotocol1
import logging
import sys
import clientprotocol2
import credentialManagement

import authenticatorConfig

import entrepriseattestation
import hmacSecret
# from cborStructure import make_credential_data
RP_domain          = "localhost"
curpin="123456"
user="bobsmith"



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("fido_test_log.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

  
def createGetPINtoken(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def getPINtoken(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    
    hex_response = cardPublickey[0] if isinstance(cardPublickey, tuple) else cardPublickey
    cbor_bytes = binascii.unhexlify(hex_response)

   
    trimmed_cbor_bytes = cbor_bytes[1:]
    # Decode CBOR
    decoded_data = cbor2.loads(trimmed_cbor_bytes)
    print("Decoded CBOR:", decoded_data)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash = util.sha256(str(curpin).encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)    
    result= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);
    return result


    

    

import transports
import credProtect
import CardRestAndPINManager
import generic
import make_cred_response
if __name__ == "__main__":
    cardInstance= util.ConnectJavaCard()
    #util.printcolor(util.YELLOW,"*************************  Transports all Test Case Secnarios   *************************")
#     CardRestAndPINManager.cardReset()
#     CardRestAndPINManager.pinset_protocol2("123456")
# ## Test Case 1 – Extended APDU
#     transports.run_fido_applet_select()
#     user = "bobsmith"
# ## Test Case 2 – Extended APDU
#     transports.run_make_credential("extended", "123456", RP_domain, user)
#     util.ResetCardPower()
#     util.ConnectJavaCard()
# ## Test Case 3 – Short APDU
#     transports.run_make_credential("short", "123456", RP_domain, user)
#     util.ResetCardPower()
#     util.ConnectJavaCard()
# ## Test Case 4 – Mixed-size APDU
#     transports.run_make_credential("mixed", "123456", RP_domain, user)
# ## Test Case 5 – Mixed-size APDU   
#     transports.incorrect_INS_short()
# ## Test Case 6 – Mixed-size APDU 
#     transports.incorrect_INS_Extended()
# ## Test Case 7 – Mixed-size APDU 
#     transports.invalidLc_short()
# ## Test Case 8 – Mixed-size APDU 
#     transports.invalidLc_Extended()

################################# Generic #################################

    #util.printcolor(util.YELLOW,"*************************  Generic all Test Case Secnarios   *************************")
#     CardRestAndPINManager.cardReset()
# ## Test Case 1 
#     generic.getInfo()
# ## Test Case 2 
#     generic.getInfo_option()
# ## Test Case 3
#     generic.getinfo()
#################################  MakeCredential Request #################################

    #util.printcolor(util.YELLOW,"*************************  MakeCredential Request all Test Case Secnarios   *************************")
    # CardRestAndPINManager.cardReset()
    # CardRestAndPINManager.pinset_protocol2("123456")
    # make_credential_request.RegisterUser("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.clientDataHash("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.clientDataHashNotArray("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.rpIsMissing("123456","unifiya@arculus.com", "Platform Desktop")
    # make_credential_request.rpNotmap("123456","unifiya@arculus.com", "Platform Desktop") 
    # make_credential_request.userDataMissing("123456", "Platform Desktop", RP_domain)
    # make_credential_request.userDataNotMap("123456", "Platform Desktop", RP_domain)
    # make_credential_request.pubKeyCredParamsDataMissing("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.pubKeyCredParamsDataNotArray("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.excludeListDataNotSequence("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.extensionsDataNotMap("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.optionsDataNotMap("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
                          
#     util.ResetCardPower()
#     util.ConnectJavaCard()
#     CardRestAndPINManager.cardReset()
#     CardRestAndPINManager.pinset_protocol2("123456")
#     user="bobsmith"
#     curpin="123456"
# # RP invalid tests
#     make_credential_request.run_make_credential_invalid("rp.id", curpin, RP_domain, user)
#     make_credential_request.run_make_credential_invalid("rp.name", curpin, RP_domain, user)
#     make_credential_request.run_make_credential_invalid("rp.icon", curpin, RP_domain, user)
# # User invalid tests
#     util.ResetCardPower()
#     util.ConnectJavaCard()
#     CardRestAndPINManager.cardReset()
#     CardRestAndPINManager.pinset_protocol2("123456") 
#     make_credential_request.run_make_credential_invalid("user.id", curpin, RP_domain, user)
#     make_credential_request.run_make_credential_invalid("user.name", curpin, RP_domain, user)
#     make_credential_request.run_make_credential_invalid("user.displayName",curpin, RP_domain,  user)
#     make_credential_request.run_make_credential_invalid("user.icon", curpin, RP_domain, user)

# # pubKeyCredParams invalid tests
    # util.ResetCardPower()
    # util.ConnectJavaCard()
    # CardRestAndPINManager.cardReset()
    # CardRestAndPINManager.pinset_protocol2("123456")
    # util.printcolor(util.YELLOW, "****MakeCredential Request 4****") 
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.notMap", curpin, RP_domain, user)
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.typeMissing", curpin, RP_domain, user)
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.typeNotText", curpin, RP_domain, user)
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.algMissing", curpin, RP_domain, user)
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.algNotInt", curpin, RP_domain, user)
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.algUnsupported", curpin, RP_domain, user)
    # make_credential_request.run_make_credential_invalid("pubKeyCredParams.typeNotPublicKey", curpin, RP_domain, user)
###ExckudeList testcase 
    # util.ResetCardPower()
    # util.ConnectJavaCard()
    # CardRestAndPINManager.cardReset()
    # CardRestAndPINManager.pinset_protocol2("123456")
    # util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    # make_credential_request.ExcludeListAllTest("excludeList.typeNotPublicKey", curpin, RP_domain, user)
    #make_credential_request.ExcludeListAllTest("excludeList.typeNotPublicKey", curpin, RP_domain, user)
    #make_credential_request.ExcludeListAllTest("excludeList.typeMissing", curpin, RP_domain, user)






    #make_credential_request.pubKeyCredParamsDataNotMap(curpin,user, "Platform Desktop", RP_domain)
    #make_credential_request.pubKeyCredParamsDataIsMissing("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialParametersDataNotText("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialParametersALGmissing("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialParametersALGInteger("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialParametersALGNotSupported("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialParametersPublickeyNotSupported("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
                
    #util.ResetCardPower()
    #util.ConnectJavaCard()
    #CardRestAndPINManager.cardReset()
    #CardRestAndPINManager.pinset_protocol2("123456") 
    # make_credential_request.ExckudeList("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    # make_credential_request.ExckudeListNotTypeMap("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.ExckudeListPublicKeyCredentialDescriptor("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialDescriptorNotTypeText("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialDescriptorIdmissing("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.PublicKeyCredentialDescriptorIdnotArray("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
         
    #response=make_credential_request.duplicateCredentialId("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #print("response",response)
    #credId =getasserationrequest.authParasing(response)
    #print("credId:",credId)
    #clientDataHash = os.urandom(32)
    #util.ResetCardPower()
    #util.ConnectJavaCard()
    #make_credential_request.idFeildIsMissing("123456", clientDataHash, RP_domain, "google.com",credId)

    #util.ResetCardPower()
    #util.ConnectJavaCard()
    #CardRestAndPINManager.cardReset()
    #CardRestAndPINManager.pinset_protocol2("123456") 
    #make_credential_request.optionsDataUnknown("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.uvOptionSet("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #util.ResetCardPower()
    #util.ConnectJavaCard()
    #make_credential_request.optionsDataup("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)
    #make_credential_request.optionsupNotSet("123456","unifiya@arculus.com", "Platform Desktop", RP_domain)

 #################################  MakeCredential Response#################################
    #CardRestAndPINManager.cardReset()
    #CardRestAndPINManager.pinset_protocol2("123456")
    #clientDataHash=os.urandom(32)
    #user="bobsmith"
    #response=make_cred_response.makecredresponse("123456",clientDataHash,RP_domain,user)
    #make_cred_response.authDataParsing(response)
    #make_cred_response.algFiled(response)
    #make_cred_response.certificate(response)
 
################################# GetAssertion Request##########################################    
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#response=getAsseration.RegisterUser("123456", "youruser@example.com", "Platform Desktop", RP_domain)
#getasserationrequest.AuthenticateUser("123456",  RP_domain,response)
#getasserationrequest.AuthenticateUserRpIdMissing("123456","youruser@example.com", response)
#getasserationrequest.AuthenticateUserRpIdNotString("123456","youruser@example.com",RP_domain, response)
#getasserationrequest.AuthenticateUserclientDataHash("123456","youruser@example.com",RP_domain, response)
#getasserationrequest.AuthenticateUserclientDataHashNotString("123456","youruser@example.com",RP_domain,response)
#getasserationrequest.AuthenticateUserallowListNotSet("123456","youruser@example.com",RP_domain, response)
#getasserationrequest.AuthenticateUserallowListNotMap("123456","youruser@example.com",RP_domain, response)

#=========================2
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#RP_domain="example.com"
#response=getAsseration.RegisterUser("123456", "bobsmith", "Platform Desktop", RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasserationrequest.AuthenticateUserforOption("123456","bobsmith",  RP_domain, response)
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasserationrequest.AuthenticateUserOptionup("123456","bobsmith",  RP_domain, response)
#util.ResetCardPower()
#util.ConnectJavaCard()
#uv not supported
#getasserationrequest.AuthenticateUserOptionuv("123456","bobsmith",  RP_domain, response)
############################3
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#RP_domain="amazon.com"
#response=getAsseration.RegisterUser("123456", "bobsmith", "Platform Desktop", RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasserationrequest.AuthenticateUserallowListNOTsET("123456","bobsmith",  RP_domain, response)
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasserationrequest.AuthenticateUserallowListNOTMap("123456","bobsmith",  RP_domain, response)
#getasserationrequest.PublicKeyCredentialDescriptorType("123456","bobsmith",  RP_domain, response)
#getasserationrequest.PublicKeyCredentialDescriptorTypeNot("123456","bobsmith",  RP_domain, response)
#getasserationrequest.PublicKeyCredentialDescriptorIdMissing("123456","bobsmith",  RP_domain, response)
#getasserationrequest.PublicKeyCredentialDescriptorIdarray("123456","bobsmith",  RP_domain, response)
#getasserationrequest.PublicKeyCredentialDescriptorallowListMissing("123456","bobsmith",  RP_domain, response)

########################## GetAssertion Response ######################################
import getasseration_response
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#makecred_response=getAsseration.RegisterUser("123456", "youruser@example.com", "Platform Desktop", RP_domain)
#print("malecredential response",makecred_response)
#getasseraion_response=getasserationrequest.AuthenticateUser("123456",  RP_domain,makecred_response)
#print("getasseration response",getasseraion_response)
##print("getasseration response",getasseraion_response)
#getasseration_response.getasseration(makecred_response)
#getasseration_response.getasseration1(getasseraion_response,RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasseration_response.multi_getasseration_response("123456",RP_domain,makecred_response)
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasseration_response.getasseration_signature_verify("123456",RP_domain,makecred_response)


########################### Reset ###################################
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#getasserationrequest.DeviceResetProcess()
#RP_domain="webauthn-demo.test"
#response=getAsseration.RegisterUser("123456", "bobsmith", "Platform Desktop", RP_domain)
#clientDataHash= util.sha256(os.urandom(32))
#util.ResetCardPower()
#util.ConnectJavaCard()
#getasserationrequest.optionUpSet("123456",clientDataHash,  RP_domain,response)
#util.ResetCardPower()
#util.ConnectJavaCard() 
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#getasserationrequest.optionUpSet("123456",clientDataHash,  RP_domain, response)

######################### Options: Resident Key##############################
#import residentKey
#util.printcolor(util.YELLOW,"Resident Key all the test case scenarios")
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#residentKey.residentKey()
#RP_domain="apple.com"
##response=getAsseration.RegisterUser("123456", "bobsmith", "Platform Desktop", RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#RP_domain="google.com"
#residentKey.residentKeyrk()
#response=getAsseration.RegisterUser("123456", "johnwick", "Platform Desktop", RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#response=getAsseration.RegisterUser("123456", "alice", "Platform Desktop", RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#response=getAsseration.RegisterUser("123456", "Trust@123", "Platform Desktop", RP_domain)
#clientDataHash= util.sha256(os.urandom(32) )
#residentKey.numberOfRpId( clientDataHash, RP_domain)
##3
#util.ResetCardPower()
#util.ConnectJavaCard()
#RP_domain="fidoalliance.org"
#residentKey.checkingUVOption("123456", "Trust@123", "Platform Desktop", RP_domain)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="bobsmith"
#response=residentKey.uvNotSupported("123456", user, "Platform Desktop", RP_domain)
#residentKey.AuthenticateUser("123456", RP_domain)
###4
#residentKey.authenticatorDisplay()


################  Enterprise Attestation  supported by arculus token############################
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#entrepriseattestation.enableEP("123456")
#user="john_doe"
#hashchallenge = os.urandom(32);
#RP_domain="demo-login.test"
#entrepriseattestation.authenticatorMakeCredential("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#RP_domain="enterprisetest.certinfra.fidoalliance.org"
#entrepriseattestation.authenticatorMakeCredentials("123456",hashchallenge, RP_domain, user)
#entrepriseattestation.consumerProfile("123456")
#entrepriseattestation.notEnterPrise("123456")
#entrepriseattestation.notSupportconsumer("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="john_doe"
#hashchallenge = os.urandom(32);
#RP_domain="enterprisetest.certinfra.fidoalliance.org"
#entrepriseattestation.randomAttestionData("123456",hashchallenge, RP_domain, user)
##entrepriseattestation.attestionvalueisNotMatch("123456",hashchallenge, RP_domain, user)
#wrongrpid="abcd.com"
#entrepriseattestation.wrongrpId("123456",hashchallenge, wrongrpid, user)

##############    HMAC Secret  ######################
#util.printcolor(util.YELLOW,"HMAC Secret all the test case scenarios")
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#hmacSecret.authenticatorClientPin()
#clientprotocol1.setpin("123456")
#user="john"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#response=hmacSecret.makecredential(hashchallenge,RP_domain,user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.getAsseration("123456",  RP_domain,response)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.supporingSalt1and2("123456",  RP_domain, response)
#hmacSecret.randomHMAC("123456", RP_domain,user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.hmaconesalt("123456", RP_domain,user,response)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.hmaconesaltandsalt2("123456", RP_domain,user,response)

##############    HMAC Secret - Strict PUAT2 ######################
#util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2 all the test case scenarios ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#hmacSecret2.authenticatorClientPin()
#user="johnwick"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#response =hmacSecret2.makecredential(hashchallenge, RP_domain, user)
#hmacSecret2.getAsseration("123456",RP_domain,response)
#hmacSecret2.hmacsalt1andsal2("123456",RP_domain,response)
#hmacSecret2.randomHMAC("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret2.salt_length_insufficient("123456",RP_domain,response)
#hmacSecret2.salt_length_insufficient1("123456",RP_domain,response)


##############    CredProtect ######################
#import credProtect
#util.printcolor(util.YELLOW, "**** CredProtect all the test case scenarios ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#setpin.clientPinSet("123456")
#user="johnwick"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#credProtect.makecredential("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="bobsmith"
#hashchallenge = os.urandom(32);
#RP_domain="google.com"
#credProtect.testUVOptionalWithCredProtectAndAssertionFlows("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="stephen"
#hashchallenge = os.urandom(32);
#RP_domain="entra.com"
#credProtect.testCredProtectUVRequiredWithAssertionErrors("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="alice"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#credProtect. verify_cred_protect_level_with_credential_management("123456",hashchallenge, RP_domain, user)

##############   CredBlob ######################
#import credBlob
#util.printcolor(util.YELLOW, "**** CredBlob all the test case scenarios ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#setpin.clientPinSet("123456")
#credBlob.maxCredBlobLength("123456")
#user="stephen"
#hashchallenge = os.urandom(32);
#RP_domain="entra.com"
#credBlob.test_credblob_extension("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="bobsmith"
#hashchallenge = os.urandom(32);
#RP_domain="google.com"
#credBlob.test_credblob_extension_empty_return("123456",hashchallenge, RP_domain, user)

########### Large Blob Key***************(not supporting arculus)
#import largeBlobkey
#util.printcolor(util.YELLOW, "****  Large Blob Key all the test case scenarios ****")
#RP_domain="google.com"
#user="bobsmith"
#credId=largeBlobkey.largeBlobKey("123456", RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#largeBlobkey.largeBlobKeyGetasseration("123456", RP_domain, credId)
#util.ResetCardPower()
#util.ConnectJavaCard()
#largeBlobkey.test_blobkey_invalid("123456", RP_domain, user)
#largeBlobkey.test_blobkey_notset("123456", RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#largeBlobkey.get_assertion_invalid_largeblobkey("123456", RP_domain, credId)
#largeBlobkey.get_assertion_random("123456", RP_domain, credId)

################### minPinLength  #################################
#util.printcolor(util.YELLOW, "**** minPinLength all the test case scenarios ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("123456")
#user="john_doe"
#hashchallenge = os.urandom(32);
#RP_domain="demo-login.test"
#minpinlength.minPinLength("123456", hashchallenge, RP_domain, user)

##################ClientPin protocol 1##########################
#util.printcolor(util.YELLOW, "**** ClientPin protocol 1 all the test case scenarios ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "**** Authr-ClientPin1-GetKeyAgreement Test authenticatorClientPin(0x06) ****")
#clientprotocol1.authenticatorClientPin();
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "****Authr-ClientPin1-NewPin Test authenticatorClientPin(0x06 ****")
#clientprotocol1.set_client_pin_protocol1("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#clientprotocol1. change_client_pin_protocol1("123456","123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#clientprotocol1. get_pin_token_protocol1("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="alice"
#RP_domain="webauthn.io"
#response=clientprotocol1. RegisterUser("123456",user, "Platform Desktop", RP_domain)
#clientDataHash= util.sha256(os.urandom(32) )
#util.ResetCardPower()
#util.ConnectJavaCard()
#clientprotocol1.getAsseration("123456",clientDataHash,  RP_domain,response)
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "****Authr-ClientPin1-Policy Check authenticator correctly implementing PinProtocol security policies ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#clientprotocol1.test_setpin_length_between_min_and_63(base_pin="A")
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#clientprotocol1.test_setpin_less_than_4_bytes_raw1("123")
#CardRestAndPINManager.cardReset()
#clientprotocol1.test_setpin_more_than_63_bytes_raw("1111111111111111111111111111111111111111111111111111111111111111")
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "****Authr-ClientPin1-GetRetries Test authenticatorClientPin(0x06), of version 0x01 support of getRetries(0x01) command ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("123456")
#clientprotocol1.retriesCount()
#util.ResetCardPower()
#util.ConnectJavaCard()
#clientprotocol1.piAuthBlocked()
#clientprotocol1. getPINtoken("654321")
#clientprotocol1. getPINtoken("654321")
#clientprotocol1.pinRetriescount()
#clientprotocol1. getPINtoken("654321")


#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("123456")
#user="alice"
#hashchallenge = os.urandom(32);
#RP_domain="webauthn.io"
#clientprotocol1.pinTokenBlocked()
#clientprotocol1. makeCred("123456",hashchallenge, RP_domain,user)
#clientprotocol1.pinRetriescount()
#retries = 8
#clientprotocol1.checkRetriesCount("654321",retries)
#clientprotocol1. getPINtoken("123456")

##################ClientPin protocol 2##########################
#util.printcolor(util.YELLOW, "**** ClientPin protocol 2 all the test case scenarios ****")
#util.ResetCardPower()
#util.ConnectJavaCard()
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "**** Authr-ClientPin2-GetKeyAgreement Test authenticatorClientPin(0x06) ****")
#clientprotocol2.authenticatorClientPin()
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "****Authr-ClientPin2-NewPin Test authenticatorClientPin(0x06 ****")
#clientprotocol2.setpin_protocol2("123456")
#clientprotocol2.changePin_protocol2("123456","123456")
#util.printcolor(util.YELLOW, "****Authr-ClientPin2-GetPinToken Test authenticatorClientPin(0x06), of version 0x02 support of getPinToken(0x05) commands ****")
#clientprotocol2.pinToken_protocol2("123456")

#util.ResetCardPower()
#util.ConnectJavaCard()
#user="johnwick"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#response =clientprotocol2.makecred_protocol2("123456", hashchallenge, RP_domain, user)
#clientDataHash= util.sha256(os.urandom(32) )
#clientprotocol2.getAsseration_protocol2("123456", clientDataHash, RP_domain,response)
#util.printcolor(util.YELLOW,"")
#util.printcolor(util.YELLOW, "****Authr-ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions Test authenticatorClientPin(0x06), of version 0x02 support of getPinUvAuthTokenUsingPinWithPermissions(0x09) commands ****")
#setpin.cardreset()
#setpin.clientPinSet("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#permission=55
#clientprotocol2.pintokenWithPermission("123456",RP_domain,permission)

#util.ResetCardPower()
#util.ConnectJavaCard()
##RP_domain="example.com"
#permission=1;
#user="alice"
#hashchallenge = os.urandom(32);
#response=clientprotocol2.pintokenWithPermissionMakeCredential("123456",RP_domain,permission,hashchallenge,user)

##util.ResetCardPower()
#util.ConnectJavaCard()
#permission=2;
#hashchallenge = os.urandom(32);
#clientprotocol2.pintokenWithPermissionAsseration("123456",RP_domain,permission,hashchallenge,response)
#util.printcolor(util.YELLOW, "****Authr-ClientPin2-Policy Check authenticator correctly implementing PinProtocol security policies ****")
#clientprotocol2.clientPinSetMinimumPinLength("12345")
#clientprotocol2.clientPinSetLessthan4byte("123")
#clientprotocol2.clientPinSetbiggerThan63("1111111111111111111111111111111111111111111111111111111111111111111111") 
#clientprotocol2.clientPinSetexactly64("1111111111111111111111111111111111111111111111111111111111111111") 
#util.printcolor(util.YELLOW, "****Authr-ClientPin2-GetRetries Test authenticatorClientPin(0x06), of version 0x02 support of getPINRetries(0x01) command ****")
#setpin.clientPinSet("123456")
#clientprotocol2.retriesCount()
##clientprotocol2.pinauthBlocked("654321")
#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("123456")
#user="johnwick"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#clientprotocol2.pinretriesBlocked("123456",user,hashchallenge, RP_domain)
#clientprotocol2.getPINtokenPubkeyblocked("123456")#correctpin

#######################Credential Management API######################
#util.printcolor(util.YELLOW,"Credential Management API all the test case scnarios")
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#util.printcolor(util.YELLOW,"Authr-CredentialManagement-EnumerateRPs Test authenticatorCredentialManagement(0x0A) command support for discoverable credential metadata and enumeration functionality for RPs")
#user="mathhewaade"
#hashchallenge = os.urandom(32);
#RP_domain="yahoo.com"
#credentialManagement.createCredential("123456",hashchallenge,RP_domain,user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="mathhewaade"
#hashchallenge = os.urandom(32);
#credentialManagement.createCredentialManagemetrp("123456",hashchallenge,RP_domain,user)
##credentialManagement.credentialmgntEnumerateRPsGetNextRP()
#util.printcolor(util.YELLOW,"Authr-CredentialManagement-EnumerateCredentials Test authenticatorCredentialManagement(0x0A) command support for discoverable credential enumeration")
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#user="mathhewaade"
#hashchallenge = os.urandom(32);
#RP_domain="yahoo.com"
#credentialManagement.enumerateCredentialsBegin("123456",hashchallenge,RP_domain,user)
#credentialManagement.enumerateCredentialsGetNextCredential()
#util.printcolor(util.YELLOW,"Authr-CredentialManagement-UpdateAndDelete Test authenticatorCredentialManagement(0x0A) command, for support of Update and Delete functionality for discoverable credentials")
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#user="mathhewaade"
#hashchallenge = os.urandom(32);
##RP_domain="yahoo.com"
#credentialManagement.updateUserInformation("123456", hashchallenge, RP_domain, user)

#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="alice"
#hashchallenge = os.urandom(32);
#RP_domain="fidoallince.com"
#credentialManagement.deleteCredential("123456", hashchallenge, RP_domain, user)

################### Authenticator Config##########################
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#authenticatorConfig.authenticatorConfig("123456")
#authenticatorConfig.toggleAlwaysUv("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#authenticatorConfig.newMinPINLength("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("12345678")#checking pinlength changes or not
##authenticatorConfig.minPinLengthRPID("12345678")
#authenticatorConfig.multipleRPIDSset("12345678")






###################################Credential Management API extra teast case################################
#for update credential 1.P-Empty user name
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#user="mathhewaade"
#hashchallenge = os.urandom(32);
#RP_domain="yahoo.com"
#credentialManagement.updateInformationEmptyUser("123456", hashchallenge, RP_domain, user)
#case 2 P-Based on lenght in user name -- 4 byte,18, 50, 100
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="math"#4byte
#credentialManagement.updateuserName4byte("123456", hashchallenge, RP_domain, user)

#util.ResetCardPower()
#util.ConnectJavaCard()
#user="mathewade_profile1"#18byte
#credentialManagement. updateuserName18byte("123456", hashchallenge, RP_domain, user)

#util.ResetCardPower()
#util.ConnectJavaCard()
#user="mathewade_profile1mathewade_profile1mathewade_prof"#50byte
#credentialManagement.updateuserName50byte("123456", hashchallenge, RP_domain, user)

#util.ResetCardPower()
#util.ConnectJavaCard()
#user="mathewade_profile1mathewade_profile1mathewade_profmathewade_profile1mathewade_profile1mathewade_prof"#100byte
#credentialManagement.updateuserName100byte("123456", hashchallenge, RP_domain, user)

#case 2 P-Based on lenght in  display  -- 4 byte,18, 50, 100
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#hashchallenge = os.urandom(32);
#userdisplay="math"#4byte
#RP_domain="yahoo.com"
#user="mathwade"
#credentialManagement.updatedisplayName4byte("123456", hashchallenge, RP_domain, user,userdisplay)

#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#hashchallenge = os.urandom(32);
#userdisplay="mathewade_profile1"#18byte
#RP_domain="yahoo.com"
#user="bobsmith"
#credentialManagement.updatedisplayName18byte("123456", hashchallenge, RP_domain, user,userdisplay)

#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#hashchallenge = os.urandom(32);
#userdisplay="mathewade_profile1mathewade_profile1mathewade_prof"#50byte
#RP_domain="yahoo.com"
#user="bobsmith"
#credentialManagement.updatedisplayName50byte("123456", hashchallenge, RP_domain, user,userdisplay)

#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#hashchallenge = os.urandom(32);
#userdisplay="mathewade_profile1mathewade_profile1mathewade_profmathewade_profile1mathewade_profile1mathewade_prof"#100byte
#RP_domain="yahoo.com"
#user="bobsmith"
#credentialManagement.updatedisplayName100byte("123456", hashchallenge, RP_domain, user,userdisplay)

#util.ResetCardPower()
#util.ConnectJavaCard()
##CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#hashchallenge = os.urandom(32);
#userdisplay=""#Empty
#RP_domain="yahoo.com"
#user="bobsmith"
#credentialManagement.updatedisplayNameEmptybyte("123456", hashchallenge, RP_domain, user,userdisplay)

#F-give wrong useID-  If the supplied user parameter’s id field is not the same as the matching credential’s id field then return CTAP1_ERR_INVALID_PARAMETER

#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#hashchallenge = os.urandom(32);
#userid="math"#wronguserid
#RP_domain="yahoo.com"
#user="mathwade"
#credentialManagement.wrongUserId("123456", hashchallenge, RP_domain, user,userid)

#F-If no matching credential is found, return CTAP2_ERR_NO_CREDENTIALS.
#hashchallenge = os.urandom(32);
#userid="mathwade"
#RP_domain="yahoo.com"
#user="mathwade"
#credentialManagement.wrongCredId("123456", hashchallenge, RP_domain, user,userid)
#PIN Auth based P-RPID cm permission;the RP ID of the credential
#userDisplayName="mathwade"
#hashchallenge = os.urandom(32);
#RP_domain="yahoo.com"
#user="mathwade"
#credentialManagement.CMpermission("123456",hashchallenge, RP_domain, user,userDisplayName)
#credentialManagement.wrongCMpermission("123456",hashchallenge, RP_domain, user,userDisplayName)
#credentialManagement.noCMpermission("123456",hashchallenge, RP_domain, user,userDisplayName)
#F-RPID cm permission;the RP ID of the credential -  If not, return CTAP2_ERR_PIN_AUTH_INVALID
#credentialManagement.pinauthMissing("123456",hashchallenge, RP_domain, user,userDisplayName)
#################extra test case Delete credential manageemnt #####################
#P-Based on correcr credID without RPID
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="alice"
#hashchallenge = os.urandom(32);
#RP_domain="fidoallince.com"
#credentialManagement.deleteCredential1("123456", hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#credentialManagement.wrongCred("123456", hashchallenge, RP_domain, user)
#credentialManagement.validCMpermission1("123456", hashchallenge, RP_domain, user)
#credentialManagement.noCMpermission1("123456", hashchallenge, RP_domain, user)
#credentialManagement.wrongPinAuth("123456", hashchallenge, RP_domain, user)

############################extra test case Getting Credentials Metadata#################
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="alice"
#hashchallenge = os.urandom(32);
#RP_domain="fidoallince.com"
#credentialManagement.createCredential("123456",hashchallenge,RP_domain,user)
#credentialManagement.getmetadata("123456",hashchallenge,RP_domain,user)
#credentialManagement.wrongcmgetmetadata("123456",hashchallenge,RP_domain,user)
#credentialManagement.wrongPinauthdata("123456",hashchallenge,RP_domain,user)
#credentialManagement.pinauthIsMissing("123456",hashchallenge,RP_domain,user)

############################Extra test case enumerateRPsBegin & enumerateRPsGetNextRP#################
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#user="mathhewaade"
#hashchallenge = os.urandom(32);
#RP_domain="yahoo.com"
#credentialManagement.createCredential("123456",hashchallenge,RP_domain,user)
#credentialManagement.createCredentialManagemetrp("123456",hashchallenge,RP_domain,user)
#credentialManagement.rpwithwrongcm("123456",hashchallenge,RP_domain,user)
#credentialManagement.rpwithnocm("123456",hashchallenge,RP_domain,user)
#credentialManagement.rpwithwrongpinauth("123456",hashchallenge,RP_domain,user)
#credentialManagement.rpwithmisspinauth("123456",hashchallenge,RP_domain,user)
#credentialManagement.credentialmgntEnumerateRPsGetNextRP()

############################Extra test case enumerateCredentialsBegin & enumerateCredentialsGetNextCredential#################
#util.ResetCardPower()
#util.ConnectJavaCard()
#CardRestAndPINManager.cardReset()
#CardRestAndPINManager.pinset_protocol2("123456")
#user="mathhewaade"
#hashchallenge = os.urandom(32);
#RP_domain="yahoo.com"
#credentialManagement.enumerateCredentialsBegin("123456",hashchallenge,RP_domain,user)
#failedCse
#credentialManagement. enumerateCreBeginWrongcm("123456",hashchallenge,RP_domain,user)
#credentialManagement. enumerateCreBeginMissingcm("123456",hashchallenge,RP_domain,user)
#credentialManagement. enumerateCreBeginwrongpinauth("123456",hashchallenge,RP_domain,user)
#credentialManagement. enumerateCreBeginmissingpinauth("123456",hashchallenge,RP_domain,user)
#credentialManagement.enumerateCredentialsGetNextCredential()



##################extra test case  Authenticator Config##########################
# util.ResetCardPower()
# util.ConnectJavaCard()
# CardRestAndPINManager.cardReset()
# CardRestAndPINManager.pinset_protocol2("123456")
# authenticatorConfig.authenticatorConfig("123456")
# authenticatorConfig.toggleAlwaysUv("123456")




















############################### updated code ###################################
##################Client pin set using protocole 2.2##########################

# util.printcolor(util.YELLOW, "**** ClientPin protocol 2.2 all the test case scenarios ****")
# util.ResetCardPower()
# util.ConnectJavaCard()
# util.printcolor(util.YELLOW,"")
# Setpinp22.authenticatorClientPinP2_2("minimumpin.length")
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.authenticatorClientPinP2_2("maximumpin.length")
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.authenticatorClientPinP2_2("valid.pin")
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.authenticatorClientPinP2_2("getpin.retries")

# pin="123456"
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.usingCureentPin("exting.pin",pin, RP_domain, user)
# pin="123456"

# Setpinp22.attempttochangepin("change.pin",pin, RP_domain, user)
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.changePinNew("wrong.pin",pin)
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.changePinNew("newpin",pin)
# pin="1234"
# Setpinp22.authenticatorClientPinP2_2("pinlengthLess",pin)
# pin="111111111111111111111111111111111111111111111111111111111111111"
# Setpinp22.authenticatorClientPinP2_2("pinlengthexced",pin)
# Setpinp22.pinNotSet("pinnotset")
# Setpinp22.pinNotSet("notpadding")
# pin="123456"
# Setpinp22.changePinNew1("noretries", pin)
# Setpinp22.changePinNew1("missing.param", pin)
# Setpinp22.changePinNew1("invalid.param", pin)
# Setpinp22.setPinInvalid("keyAgreement.invalid", pin)
# Setpinp22.setPinInvalid("validkeyAgreement", pin)
# Setpinp22.setPinInvalid("hmac.notmatch", pin)
# Setpinp22.setPinInvalid("pinauth.invalid", pin)
# Setpinp22.setPinInvalid("paddedPin.invalid", pin)
# Setpinp22.setPinInvalid("without.paddedPin", pin)
# Setpinp22.setPinInvalid("Hmacreuse", pin)
# Setpinp22.setPinInvalid("wrong.protocol", pin)




##################Client pin set using protocole 2.2##########################

# util.printcolor(util.YELLOW, "**** ClientPin protocol 2.2 all the test case scenarios ****")
# util.ResetCardPower()
# util.ConnectJavaCard()
# util.printcolor(util.YELLOW,"")
# #pin="1234"
# Setpinp22.authenticatorClientPinP2_2("minimumpin.length",pin)
# util.ResetCardPower()
# util.ConnectJavaCard()
# #pin="111111111111111111111111111111111111111111111111111111111111111"  #62+1char
# Setpinp22.authenticatorClientPinP2_2("maximumpin.length",pin)
# #pin="123456"

# # util.ResetCardPower()
# # util.ConnectJavaCard()
# pin="123456"
# Setpinp22.authenticatorClientPinP2_2("valid.pin",pin)
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.authenticatorClientPinP2_2("getpin.retries",pin)
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.usingCureentPin("exting.pin",pin, RP_domain, user)
# pin="123456"
# Setpinp22.attempttochangepin("change.pin",pin, RP_domain, user)
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.changePinNew("wrong.pin",pin)
# util.ResetCardPower()
# util.ConnectJavaCard()
# Setpinp22.changePinNew("newpin",pin)
# pin="1234"
# Setpinp22.authenticatorClientPinP2_2("pinlengthLess",pin)
# pin="111111111111111111111111111111111111111111111111111111111111111"
# Setpinp22.authenticatorClientPinP2_2("pinlengthexced",pin)
# Setpinp22.pinNotSet("pinnotset")
# Setpinp22.pinNotSet("notpadding")
# pin="123456"
# Setpinp22.changePinNew1("noretries", pin)
# Setpinp22.changePinNew1("missing.param", pin)
# Setpinp22.changePinNew1("invalid.param", pin)
# Setpinp22.setPinInvalid("keyAgreement.invalid", pin)
# Setpinp22.setPinInvalid("validkeyAgreement", pin)
# Setpinp22.setPinInvalid("hmac.notmatch", pin)
# Setpinp22.setPinInvalid("pinauth.invalid", pin)
# Setpinp22.setPinInvalid("paddedPin.invalid", pin)
# Setpinp22.setPinInvalid("without.paddedPin", pin)
# Setpinp22.setPinInvalid("Hmacreuse", pin)
# Setpinp22.setPinInvalid("wrong.protocol", pin)


import DocumentCreation
FILE_NAME = DocumentCreation.FILE_NAME
HEADING_TEXT = DocumentCreation.HEADING_TEXT
TESTER_NAME = DocumentCreation.TESTER_NAME
DESCRIPTION = DocumentCreation.DESCRIPTION

doc, summaryTable, detailedTable = DocumentCreation.build_document(HEADING_TEXT, TESTER_NAME, DESCRIPTION)

##################Client get PIN Retry with CTAP 2.2 -- PROTOCOL 1##########################


import getPINRetry_P1

util.printcolor(util.YELLOW, "**** CTAP 2.2 -- getPINRetries(0x01) -- Protocol 1 -- Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"

# getPINRetry_P1.getPINRetries("maxRetryCount",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 1 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("incorrectPinVerifyAndRetryCount",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 2 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("incorrectPinChangeAndRetryCount",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 3 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinBlock",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 4 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("afterPowerCycleSameRetryCount",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 5 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("invalidSubCommand",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 6 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("subCommandAbsent",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 7 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("missingDataField",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 8 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("unsupportedPinUvAuthProtocol",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 9 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinNotSetAndRetryCount",reset_required,set_pin_not_required)  
# util.printcolor(util.BLUE,"\n\n########### 10 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

getPINRetry_P1.getPINRetries("pinNotSet-Set-RetryCount",reset_required,set_pin_not_required)  
util.printcolor(util.BLUE,"\n\n########### 11 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("misleadPowerCycle",reset_required,set_pin_not_required)  
# util.printcolor(util.BLUE,"\n\n########### 12 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("invalidParameterData",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 13 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("onlyRequiredParameter",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 14 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinVerify-retryCount-powerCycleReset",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 15 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinBlockMultiple",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 16 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinBlockMultiple-Verify",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 17 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinBlockMultiple-Verify1",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 18 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

# getPINRetry_P1.getPINRetries("pinBlockMultiple-Verify2",reset_required,set_pin_required)  
# util.printcolor(util.BLUE,"\n\n########### 19 : Get Pin Retry (Protocol-ONE) Test Executed ##########")

DocumentCreation.add_summary_row(summaryTable, getPINRetry_P1.COMMAND_NAME, getPINRetry_P1.PROTOCOL, getPINRetry_P1.scenarioCount, getPINRetry_P1.passCount, getPINRetry_P1.failCount)
DocumentCreation.saveAllFiles(doc, FILE_NAME)
exit(0)







# #################Client get PIN Retry with CTAP 2.2 -- PROTOCOL 2##########################


import getPINRetry


util.printcolor(util.YELLOW, "**** CTAP 2.2 -- getPINRetries(0x01) -- Protocol 2 -- Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"

getPINRetry.getPINRetries("maxRetryCount",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 1 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("incorrectPinVerifyAndRetryCount",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 2 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("incorrectPinChangeAndRetryCount",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 3 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinBlock",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 4 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("afterPowerCycleSameRetryCount",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 5 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("invalidSubCommand",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 6 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("subCommandAbsent",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 7 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("missingDataField",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 8 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("unsupportedPinUvAuthProtocol",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 9 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinNotSetAndRetryCount",reset_required,set_pin_not_required)  
util.printcolor(util.BLUE,"\n\n########### 10 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinNotSet-Set-RetryCount",reset_required,set_pin_not_required)  
util.printcolor(util.BLUE,"\n\n########### 11 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("misleadPowerCycle",reset_required,set_pin_not_required)  
util.printcolor(util.BLUE,"\n\n########### 12 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("invalidParameterData",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 13 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("onlyRequiredParameter",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 14 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinVerify-retryCount-powerCycleReset",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 15 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinBlockMultiple",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 16 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinBlockMultiple-Verify",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 17 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinBlockMultiple-Verify1",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 18 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

getPINRetry.getPINRetries("pinBlockMultiple-Verify2",reset_required,set_pin_required)  
util.printcolor(util.BLUE,"\n\n########### 19 : Get Pin Retry (Protocol-TWO) Test Executed ##########")

DocumentCreation.add_summary_row(summaryTable, getPINRetry.COMMAND_NAME, getPINRetry.PROTOCOL, getPINRetry.scenarioCount, getPINRetry.passCount, getPINRetry.failCount)







##################Client Key Agreement with CTAP 2.2##########################

import keyAgreement


util.printcolor(util.YELLOW, "**** CTAP 2.2 - keyAgreement(0x02) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
protocol = "PROTOCOL_ONE"

for k in range(2):
    keyAgreement.getKeyAgreement("formatCheckKeyAgreement",reset_not_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"1 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("checkGeneratedSharedSecret",reset_not_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"2 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("setPINKeyAgreement",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"3 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("verifyPINKeyAgreement",reset_not_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"4 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("changePINKeyAgreement",reset_not_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"5 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("missingParameterKeyAgreement",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"6 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("invalidProtocolKeyAgreement",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"7 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("invalidSubCommandKeyAgreement",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"8 : Key Agreement {protocol} Test Executed")

    keyAgreement.getKeyAgreement("consecutiveKeyAgreement",reset_not_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"9 : Key Agreement {protocol} Test Executed")

    DocumentCreation.add_summary_row(summaryTable, keyAgreement.COMMAND_NAME, keyAgreement.PROTOCOL, keyAgreement.scenarioCount, keyAgreement.passCount, keyAgreement.failCount)
    keyAgreement.failCount = 0
    keyAgreement.passCount = 0
    keyAgreement.scenarioCount = 0
    protocol = "PROTOCOL_TWO"





##################Client pin set using protocole 1##########################
import Setpinp1
util.printcolor(util.YELLOW, "**** Client PIN Set with CTAP 2.2 protocol 1 ****")
util.printcolor(util.YELLOW,"")
reset_requried="yes"
reset_not_requried="no"
Setpinp1.authenticatorClientPinP2_2("minimumpin.length",reset_requried)#succes
Setpinp1.authenticatorClientPinP2_2("maximumpin.length",reset_requried)
Setpinp1.authenticatorClientPinP2_2("random.pin",reset_requried)
Setpinp1.newsetpin()
Setpinp1.authenticatorClientPinP2_2("exting.pin",reset_not_requried)
Setpinp1.authenticatorClientPinP2_2("getpin.retries",reset_requried)
Setpinp1.authenticatorClientPinP2_2("wrong.pin",reset_not_requried)
Setpinp1.authenticatorClientPinP2_2("pinalreayset",reset_not_requried)
Setpinp1.authenticatorClientPinP2_2("pinlengthLess",reset_requried)
Setpinp1.authenticatorClientPinP2_2("pinlengthexced",reset_requried)
Setpinp1.authenticatorClientPinP2_2("pinnotset",reset_requried)
Setpinp1.authenticatorClientPinP2_2("notpadding",reset_requried) 
Setpinp1.authenticatorClientPinP2_2("noretries",reset_requried)

Setpinp1.authenticatorClientPinP2_2("missing.protocol",reset_requried)
Setpinp1.authenticatorClientPinP2_2("missing.subcommand",reset_requried)
Setpinp1.authenticatorClientPinP2_2("missing.keyAgreement",reset_requried)
Setpinp1.authenticatorClientPinP2_2("missing.newPinEnc",reset_requried)
Setpinp1.authenticatorClientPinP2_2("missing.pinUvAuthParam",reset_requried)

Setpinp1.authenticatorClientPinP2_2("Invalid.pinUvAuthProtocol",reset_requried)
Setpinp1.authenticatorClientPinP2_2("Invalid.subCommand",reset_requried)
Setpinp1.authenticatorClientPinP2_2("Invalid.keyAgreement",reset_requried)
Setpinp1.authenticatorClientPinP2_2("Invalid.newPinEnc",reset_requried)
Setpinp1.authenticatorClientPinP2_2("Invalid.pinUvAuthParam",reset_requried)
Setpinp1.authenticatorClientPinP2_2("Invalid.pinUvAuthParamlength",reset_requried)

Setpinp1.authenticatorClientPinP2_2("Invalid.newPinEnclength",reset_requried) 
Setpinp1.authenticatorClientPinP2_2("paddedPin.invalid",reset_requried)
Setpinp1.authenticatorClientPinP2_2("without.paddedPin",reset_requried)
Setpinp1.authenticatorClientPinP2_2("paddedPininvalid",reset_requried)#paddedblock
Setpinp1.authenticatorClientPinP2_2("Hmacreuse",reset_requried)
Setpinp1.authenticatorClientPinP2_2("alphanumeric.pin",reset_requried)
Setpinp1.authenticatorClientPinP2_2("specialchar.pin",reset_requried)
Setpinp1.authenticatorClientPinP2_2("randompin.continuess",reset_requried)
Setpinp1.authenticatorClientPinP2_2("protocol.keypair",reset_requried)
DocumentCreation.add_summary_row(summaryTable, Setpinp1.COMMAND_NAME, Setpinp1.PROTOCOL, Setpinp1.scenarioCount, Setpinp1.passCount, Setpinp1.failCount)
Setpinp1.failCount = 0
Setpinp1.passCount = 0
Setpinp1.scenarioCount = 0
util.printcolor(util.CYAN, f"PROTOCOL 1 EXECUTED")

##################Client setpin(0x03) using ctap 2.2##########################

import Setpinp22
util.printcolor(util.YELLOW, "**** Client PIN Set with CTAP 2.2 protocol 2 ****")
util.printcolor(util.YELLOW,"")
reset_requried="yes"
reset_not_requried="no"

Setpinp22.authenticatorClientPinP2_2("minimumpin.length",reset_requried)#succes
Setpinp22.authenticatorClientPinP2_2("maximumpin.length",reset_requried)
Setpinp22.authenticatorClientPinP2_2("random.pin",reset_requried)

Setpinp22.setnewpin()
Setpinp22.authenticatorClientPinP2_2("exting.pin",reset_not_requried)
Setpinp22.authenticatorClientPinP2_2("getpin.retries",reset_requried)
Setpinp22.authenticatorClientPinP2_2("wrong.pin",reset_not_requried)
Setpinp22.authenticatorClientPinP2_2("pinalreayset",reset_not_requried)
Setpinp22.authenticatorClientPinP2_2("pinlengthLess",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("pinlengthexced",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("pinnotset",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("notpadding",reset_requried) #success
Setpinp22.authenticatorClientPinP2_2("noretries",reset_requried)#success

Setpinp22.authenticatorClientPinP2_2("missing.protocol",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("missing.subcommand",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("missing.keyAgreement",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("missing.newPinEnc",reset_requried)#success
Setpinp22.authenticatorClientPinP2_2("missing.pinUvAuthParam",reset_requried)#success

Setpinp22.authenticatorClientPinP2_2("Invalid.pinUvAuthProtocol",reset_requried)
Setpinp22.authenticatorClientPinP2_2("Invalid.subCommand",reset_requried)###pending idemia wrong 3e
Setpinp22.authenticatorClientPinP2_2("Invalid.keyAgreement",reset_requried)#asking
Setpinp22.authenticatorClientPinP2_2("Invalid.newPinEnc",reset_requried)
Setpinp22.authenticatorClientPinP2_2("Invalid.pinUvAuthParam",reset_requried)
Setpinp22.authenticatorClientPinP2_2("Invalid.pinUvAuthParamlength",reset_requried)
Setpinp22.authenticatorClientPinP2_2("Invalid.newPinEnclength",reset_requried)


Setpinp22.authenticatorClientPinP2_2("paddedPin.invalid",reset_requried) 
Setpinp22.authenticatorClientPinP2_2("without.paddedPin",reset_requried)
Setpinp22.authenticatorClientPinP2_2("paddedPininvalid",reset_requried)#padded block corrpted pending
Setpinp22.authenticatorClientPinP2_2("Hmacreuse",reset_requried)#succes
Setpinp22.authenticatorClientPinP2_2("alphanumeric.pin",reset_requried)
Setpinp22.authenticatorClientPinP2_2("specialchar.pin",reset_requried)
Setpinp22.authenticatorClientPinP2_2("randompin.continuess",reset_requried)
Setpinp22.authenticatorClientPinP2_2("withoutpowercycle",reset_requried)
Setpinp22.authenticatorClientPinP2_2("withpowercycle",reset_requried)
Setpinp22.authenticatorClientPinP2_2("randompin.exccedlength",reset_requried)
Setpinp22.authenticatorClientPinP2_2("protocol.keypair",reset_requried)
DocumentCreation.add_summary_row(summaryTable, Setpinp22.COMMAND_NAME, Setpinp22.PROTOCOL, Setpinp22.scenarioCount, Setpinp22.passCount, Setpinp22.failCount)
Setpinp22.failCount = 0
Setpinp22.passCount = 0
Setpinp22.scenarioCount = 0
util.printcolor(util.CYAN, f"PROTOCOL 2 EXECUTED")




##################Client PIN Change with CTAP 2.2##########################


import changePIN2_2
import clientprotocol1
import clientprotocol2

util.printcolor(util.YELLOW, "**** CTAP 2.2 - changePIN(0x04) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
protocol = "PROTOCOL_ONE"

for i in range(2):
    changePIN2_2.changePin("minimumNewPinLength",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"1 : Change PIN {protocol} Test Executed")
    
    changePIN2_2.changePin("maximumNewPinLength",reset_required,set_pin_required,protocol) 
    util.printcolor(util.BLUE,f"2 : Change PIN {protocol} Test Executed")
    
    changePIN2_2.changePin("validNewPinLength",reset_required,set_pin_required,protocol)   
    util.printcolor(util.BLUE,f"3 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("protectedOperation",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"4 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("getPinRetries",reset_required,set_pin_required,protocol) 
    util.printcolor(util.BLUE, f"5 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("notSet-ChangeFail-Set-Change-RetryCount",reset_required,set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"6 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("set-Change-Change-Verify",reset_required,set_pin_required,protocol)
    util.printcolor(util.BLUE,f"7 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("randomCurrentPin",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"8 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newPinShorterThanMinPin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"9 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newPinLongerThanMaxPin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"10 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinShorterThanMinPin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"11 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinLongerThanMaxPin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"12 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinNewPinShorterThanMinPin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"13 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinNewPinLongerThanMaxPin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"14 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newPinShorterThanMinPin_PinNotSet",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"15 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newPinLongerThanMaxPin_PinNotSet",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"16 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinShorterThanMinPin_PinNotSet",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"17 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinLongerThanMaxPin_PinNotSet",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"18 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinNewPinShorterThanMinPin_PinNotSet",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"19 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("curPinNewPinLongerThanMaxPin_PinNotSet",reset_required,set_pin_not_required,protocol)  
    util.printcolor(util.BLUE,f"20 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newPinWithoutPadding",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"21 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("reducePINRetriesCount",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"22 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("multipleChangePinBlock",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"23 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("multipleIncorrectChangePin_LastCorrectChangePIN",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"24 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("unsupportedProtocolChangePin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"25 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("invalidSubCommandChangePin",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"26 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("missingMandatoryParameters",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"27 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("invalidKeyAgreement",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"28 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("invalidParametersForChangePIN",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"29 : Change PIN {protocol} Test Executed")
   
    changePIN2_2.changePin("incorrectPINHashEnc",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"30 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("incorrectPinHashEnc3Times",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"31 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("malformedNewPINEnc",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"32 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newPinEncNotPaddedto64Bytes",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"33 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("forceChangePINisTRUE",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"34 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("forceChangePINisTRUEWithDifferentPIN",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"35 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("invalidatePinUvAuthToken",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"36 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("invalidatePinUvAuthTokenWithSamePIN",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"37 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("forceMinimumNewPinLengthChangePIN",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"38 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("forceMinimumNewPinLengthChangePIN_ValidCase",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"39 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("newAlphanumericPIN",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"40 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("nonZeroPadding",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"41 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("protocolMismatch",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"42 : Change PIN {protocol} Test Executed")

    changePIN2_2.changePin("checkRetryCountsForDifferentStatusCode",reset_required,set_pin_required,protocol)  
    util.printcolor(util.BLUE,f"43 : Change PIN {protocol} Test Executed")

    DocumentCreation.add_summary_row(summaryTable, changePIN2_2.COMMAND_NAME, changePIN2_2.PROTOCOL, changePIN2_2.scenarioCount, changePIN2_2.passCount, changePIN2_2.failCount)
    changePIN2_2.failCount = 0
    changePIN2_2.passCount = 0
    changePIN2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"
        





# #############################protocol 1###########################
import getpinauthtokenP1
import Setpinp1
util.printcolor(util.YELLOW, "******** getpintoken(0x05) ctap2.2 protocol 1 ****")
util.printcolor(util.YELLOW,"")
pin="123456"

pinset="yes"
pinnotset="no"
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("validgetpintoken",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("verifypintoken",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("withoutsetpin",pin,pinnotset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("missing.pinUvAuthProtocol",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("missing.subcommand",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("missing.pinHashenc",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("missing.keyAgreement",pin,pinset)

getpinauthtokenP1.authenticatorGetPinTokenP2_2("invalid.pinUvAuthProtocol",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("invalid.subcommand",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("invalid.keyAgreement",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("invalid.pinHashEnc",pin,pinset)

getpinauthtokenP1.authenticatorGetPinTokenP2_2("Without.Permission",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("wrongpin",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("pinauthblocked",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("pinblocked",pin,pinset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("invalid.sharecrete",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("invalid.pinHashEnclength",pin,pinset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("pinauthblocked.retries",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("withoutpowercyclereset",pin,pinset)

Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("pinauth.blocked",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("platformCOSKEY.notmap",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("forcepinchange",pin,pinset)

Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("forcepinchange.false",pin,pinset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("changingpin",pin,pinset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("forcePINChange.token",pin,pinset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("pinBlocked.Blocked",pin,pinset)
Setpinp1.newsetpin()
getpinauthtokenP1.authenticatorGetPinTokenP2_2("Allpermission",pin,pinset)
getpinauthtokenP1.authenticatorGetPinTokenP2_2("sharesecretprotol2",pin,pinset)
DocumentCreation.add_summary_row(summaryTable, getpinauthtokenP1.COMMAND_NAME, getpinauthtokenP1.PROTOCOL, getpinauthtokenP1.scenarioCount, getpinauthtokenP1.passCount, getpinauthtokenP1.failCount)
getpinauthtokenP1.failCount = 0
getpinauthtokenP1.passCount = 0
getpinauthtokenP1.scenarioCount = 0
util.printcolor(util.CYAN, f"PROTOCOL 1 EXECUTED")


# #############################protocol 2###########################
import getpintokenCTAP2_2
util.printcolor(util.YELLOW, "**** getpintoken(0x05) ctap2.2 protocol2  ****")
util.printcolor(util.YELLOW,"")
pin="12345688"
getpintokenCTAP2_2.setpin(pin)
pinset="yes"
pinnotset="no"
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("validgetpintoken",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("verifypintoken",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("withoutsetpin",pin,pinnotset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("missing.pinUvAuthProtocols",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("missing.subcommand",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("missing.pinHashenc",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("missing.keyAgreement",pin,pinset)

getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("invalid.pinUvAuthProtocol",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("invalid.subcommand",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("invalid.pinHashEnc",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("invalid.keyAgreement",pin,pinset)

getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("permission",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("wrongpin",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("wrongpin.repeatedly",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("pinblocked",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("invalid.share secret",pin,pinset) 
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("invalid.pinHashEnclength",pin,pinset) 
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("pinauthblocked",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("withoutpowercyclereset",pin,pinset)

getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("pinauth.blocked",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("pinHashEnc.notbyte",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("platformCOSKEY.notmap",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("forcepinchange",pin,pinset)

getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("forcepinchange.false",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("changingpin",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("forcePINChange.token",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("pinBlocked.Blocked",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("forcechangepinwrong",pin,pinset)
getpintokenCTAP2_2.setpin(pin)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("Allpermission",pin,pinset)
getpintokenCTAP2_2.authenticatorGetPinTokenP2_2("sharesecretprotol1",pin,pinset)
DocumentCreation.add_summary_row(summaryTable, getpintokenCTAP2_2.COMMAND_NAME, getpintokenCTAP2_2.PROTOCOL, getpintokenCTAP2_2.scenarioCount, getpintokenCTAP2_2.passCount, getpintokenCTAP2_2.failCount)
getpintokenCTAP2_2.failCount = 0
getpintokenCTAP2_2.passCount = 0
getpintokenCTAP2_2.scenarioCount = 0
util.printcolor(util.CYAN, f"PROTOCOL 2 EXECUTED")


##################getpintokenUVauth using permission(0x09) with CTAP2.2 protocol 1 ##########################
#Testing done
import getpinuvauthtokenctap2_2
import getpintokenpermissionp2
util.printcolor(util.YELLOW, "**** getPinUvAuthTokenUsingPinWithPermissions CTAP2.2 all the test case secnarios****")
util.printcolor(util.YELLOW,"")
pin="123456"

pinset="yes"
pinnotset="no"

for protocol in [1,2]:
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("cmPermission",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("acfgPermission",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("mcPermission",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("gaPermission",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("lbwpermission",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("bepermission",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("getpinToken",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("permission.zero",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("verifycmper",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("verifyacfgper",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("verifymcper",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("verifygaper",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("withoutpingetpintoken",pin,pinnotset,protocol)


    getpintokenpermissionp2.getPinUvAuthTokenP2_2("InvalidPIN",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("InvalidpinHashEnc",pin,pinset,protocol)#implement
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("Invalidkey_agreement",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("Invalidpermission",pin,pinset,protocol)#
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("Invalidsubcommand",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("Invalidprotocol",pin,pinset,protocol)

    getpintokenpermissionp2.getPinUvAuthTokenP2_2("missingpinHashenc",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("missingkeyAgreement",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("missingsubcommand",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("missingprotocol",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("missingpermission",pin,pinset,protocol)

    getpintokenpermissionp2.getPinUvAuthTokenP2_2("pinauthblocked",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("pinauthblocked.pin",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("pinretry",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("withpowercycle",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("pinblocked",pin,pinset,protocol)

    getpintokenpermissionp2.getPinUvAuthTokenP2_2("Invalidkey_sharesecret",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("platformCOSKEY.notmap",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("pinHashEnc.notbyte",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("forcepinset",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("changepin",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("forcechangepin.false",pin,pinset,protocol)

    getpintokenpermissionp2.getPinUvAuthTokenP2_2("withoutpermission.getasseration",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("withoutpermission.makecredential",pin,pinset,protocol)
    getpintokenpermissionp2.getPinUvAuthTokenP2_2("withoutpermission.cm",pin,pinset,protocol)
    DocumentCreation.add_summary_row(summaryTable, getpintokenpermissionp2.COMMAND_NAME, getpintokenpermissionp2.PROTOCOL, getpintokenpermissionp2.scenarioCount, getpintokenpermissionp2.passCount, getpintokenpermissionp2.failCount)
    getpintokenpermissionp2.failCount = 0
    getpintokenpermissionp2.passCount = 0
    getpintokenpermissionp2.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {[protocol]} EXECUTED")

# #testingpending
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("permissionalloperation",pin,pinset,protocol)
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("Invalidrpid",pin,pinset,protocol)#
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("missingrpid",pin,pinset,protocol)#testingpending
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("getpintokenmappingnotsequence",pin,pinset,protocol)#testing pending
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("rpidmatching",pin,pinset,protocol) #actually it is pass not cbor map not sequence
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("rpidnotmatching",pin,pinset,protocol)
# #getpintokenpermissionp2.getPinUvAuthTokenP2_2("rpgetasseration",pin,pinset,protocol)









############################################################################################################
############################################################################################################
############################################################################################################
############################################################################################################
################################ AUTHENTICATOR CREDENTIAL MANAGEMENT (0x0A) ################################
############################################################################################################
############################################################################################################
############################################################################################################
############################################################################################################




##################Get Creds Meta Data with CTAP 2.2##########################

import cbor2
import getCredsMetadata2_2 


util.printcolor(util.YELLOW, "**** CTAP 2.2 - getCredsMetadata(0x01) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
make_cred_required = "yes"
make_cred_not_required = "no"

protocol = "PROTOCOL_ONE"
# protocol = "PROTOCOL_TWO"
getCredsMetadata2_2.resetPowerCycle(True)

################### REMOVE COMMENT IF YOU WANT DYNAMIC MAX CRED COUNT ######################
response, status = util.APDUhex("00A4040008A0000006472F0001", "Select applet")
util.ResetCardPower()
util.ConnectJavaCard()
response, status = util.APDUhex("00A4040008A0000006472F0001", "Select applet")
response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
response, status = util.APDUhex("80100000010400", "GetInfo")
allowedMakeCredCounts = util.getInfoMaximumCredsCountsInteger(response)
print("allowedMakeCredCounts ==========> ",allowedMakeCredCounts)
if status != "00":
    util.printcolor(util.BLUE,f"GET INFO COMMAND FAILED IN fidoApplication.py WITH STATUS CODE - {status}")
#############################################################################################
for i in range(2):
    no = 0
    no += 1
    #1
    getCredsMetadata2_2.executeGetCredMetaData("fidoTool_PositiveCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #2
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_WithoutPinUvAuthParamCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    #3
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_MissingMandatoryParamCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #4
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_UnsupportedProtocolCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    #5
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_PersistenTokenWithoutPCMRPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #6
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_PinUvAuthTokenWithoutCMPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #7
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_IncorrectPinUvAuthParamCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #8
    getCredsMetadata2_2.executeGetCredMetaData("fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #9
    getCredsMetadata2_2.executeGetCredMetaData("self_UsingPersistentPinUvAuthTokenWithPCMRPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #10
    getCredsMetadata2_2.executeGetCredMetaData("self_UsingPinUvAuthTokenWithCMPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #11
    getCredsMetadata2_2.executeGetCredMetaData("self_InvalidSubcommandCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #12
    getCredsMetadata2_2.executeGetCredMetaData("self_TruncatedPinUvAuthParamFromPersistentTokenCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #13
    getCredsMetadata2_2.executeGetCredMetaData("self_TruncatedPinUvAuthParamFromPinUvAuthTokenCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #14
    getCredsMetadata2_2.executeGetCredMetaData("self_ExpiredPersistenPinUvAuthTokenCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #15
    getCredsMetadata2_2.executeGetCredMetaData("self_ExpiredPinUvAuthTokenCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #16
    getCredsMetadata2_2.executeGetCredMetaData("self_OnlyOneCredentialSlotRemainWithPCMRPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #17
    getCredsMetadata2_2.executeGetCredMetaData("self_OnlyOneCredentialSlotRemainWithCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #18
    getCredsMetadata2_2.executeGetCredMetaData("self_MultipleGetCredsMetaDataWithPCMRPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #19
    getCredsMetadata2_2.executeGetCredMetaData("self_MultipleGetCredsMetaDataWithCMPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #20
    getCredsMetadata2_2.executeGetCredMetaData("self_DeleteCredAndCheckReducedCredCountWithPCMRPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #21
    getCredsMetadata2_2.executeGetCredMetaData("self_DeleteCredAndCheckReducedCredCountWithCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #22
    getCredsMetadata2_2.executeGetCredMetaData("self_DeleteOneCredAndCheckCredMetaDataWithPCMRPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #23
    getCredsMetadata2_2.executeGetCredMetaData("self_DeleteOneCredAndCheckCredMetaDataWithCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #24
    getCredsMetadata2_2.executeGetCredMetaData("self_CheckPowerCycleEffectAfterDeleteCredMetaDataWithPCMRPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #25
    getCredsMetadata2_2.executeGetCredMetaData("self_CheckPowerCycleEffectAfterDeleteCredMetaDataWithCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #26
    getCredsMetadata2_2.executeGetCredMetaData("self_CredStorageFull_DeleteOneCredPCMRPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #27
    getCredsMetadata2_2.executeGetCredMetaData("self_CredStorageFull_DeleteOneCredCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    #28
    getCredsMetadata2_2.executeGetCredMetaData("self_MakeMaxPossibleRemainingResidentCredentialsCountZeroCase", reset_not_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    #29
    getCredsMetadata2_2.executeGetCredMetaData("self_CheckPowerCycleEffectAfterTwoCredMetaDataWithPCMRPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #30
    getCredsMetadata2_2.executeGetCredMetaData("self_CheckPowerCycleEffectAfterTwoCredMetaDataWithCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #31
    getCredsMetadata2_2.executeGetCredMetaData("self_InvalidPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #32
    getCredsMetadata2_2.executeGetCredMetaData("self_MalformedOrderCBORCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #33
    getCredsMetadata2_2.executeGetCredMetaData("self_WithoutCredentialGetCredMetaDataWithCMPermissionCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #34
    getCredsMetadata2_2.executeGetCredMetaData("self_NoPINSetWithoutCredentialGetCredMetaDataWithCMPermissionCase", reset_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #35
    getCredsMetadata2_2.executeGetCredMetaData("self_ResetNewPINAndGetCredMetaDataWithCMPermissionCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #36
    getCredsMetadata2_2.executeGetCredMetaData("self_ChangePINAndGetCredMetaDataWithCMPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #37
    getCredsMetadata2_2.executeGetCredMetaData("self_ProtocolSwappingForKeyAgreementAndGetCredsMetaDataCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
   
    no += 1
    #38
    getCredsMetadata2_2.executeGetCredMetaData("self_MakeCredWithoutPINAlwaysUvFalseCase", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    #39
    getCredsMetadata2_2.executeGetCredMetaData("self_MakeCredWithPINSetGetPINToken_05", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    # #40
    getCredsMetadata2_2.executeGetCredMetaData("self_MakeCredChangeRKValueEachTime", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    DocumentCreation.add_summary_row(summaryTable, getCredsMetadata2_2.COMMAND_NAME, getCredsMetadata2_2.PROTOCOL, getCredsMetadata2_2.scenarioCount, getCredsMetadata2_2.passCount, getCredsMetadata2_2.failCount)
    getCredsMetadata2_2.failCount = 0
    getCredsMetadata2_2.passCount = 0
    getCredsMetadata2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"




################## Enumerate RP ##########################

import cbor2
import enumerateRPs2_2 
import DocumentCreation

util.printcolor(util.YELLOW, "**** CTAP 2.2 - enumerateRPsBegin (0x02) and enumerateRPsGetNextRP (0x03) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
make_cred_required = "yes"
make_cred_not_required = "no"

protocol = "PROTOCOL_ONE"
# protocol = "PROTOCOL_TWO"
enumerateRPs2_2.resetPowerCycle(True)
# ##################### REMOVE COMMENT IF YOU WANT DYNAMIC MAX CRED COUNT ######################
response, status = util.APDUhex("00A4040008A0000006472F0001", "Select applet")
response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
response, status = util.APDUhex("80100000010400", "GetInfo")
if status != "00":
    util.printcolor(util.BLUE,f"GET INFO COMMAND FAILED IN fidoApplication.py WITH STATUS CODE - {status}")
allowedMakeCredCounts = util.getInfoMaximumCredsCountsInteger(response)
print("allowedMakeCredCounts ==========> ",allowedMakeCredCounts)

# ############################################################################################
for i in range(2):
    no = 0
    no += 1
    ##1
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoTool_PositiveCase_with_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##2
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoTool_PositiveCase_with_CM", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##3
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_WithoutPinUvAuthParamCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")

    no += 1
    ##4
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_MissingMandatoryParamCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##5
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_UnsupportedProtocolCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")

    no += 1
    ##6
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_PinUvAuthTokenWithoutPermissionCase", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")

    no += 1
    ##7
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##8
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_NoDiscoverableCredWithPCMRPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##9
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_NoDiscoverableCredWithCMPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##10
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_OneRpWithPCMRPermission", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##11
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_OneRpWithCMPermission", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##12
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_MultipleRpWithPCMRPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##13
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_MultipleRpWithCMPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##14
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("fidoDoc_EnumerateRpGetNextRpWithPCMRPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##15
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_AlteredPinUvAuthParamWithPCMR", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##16
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_AlteredPinUvAuthParamWithCM", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##17
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_MissingSubCommandRPBegin", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##18
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_MissingProtocolRPBegin", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")

    no += 1
    ##19
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_PinUvAuthParamWithoutAnyPermission", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##20
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_PinUvAuthParamWrongPermission", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##21
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_DirectNextRPCommand", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")

    no += 1
    ##22
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_RPsEnumeratedAlready", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##23
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_CommandBetweenRPBeginAndRPNext", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##24-- 
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_PowerResetBetweenRPBeginAndRPNext", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##25
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_ExtraParameterRPNext", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##26
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_MissingSubCommandRPNext", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##27
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_ProcotolSwappinPinUvAuthParam", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")

    no += 1
    ##28
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID32Bytes", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##29
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID64Bytes", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##30
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##31
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_Truncated", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##32
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_rpName64Bytes", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##33
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_rpName255Bytes", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    #34
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_MakeCredWithoutPINAlwaysUvFalseCase", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")
    
    no += 1
    35
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_MakeCredWithPINSetGetPINToken_05", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    36
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_MakeCredChangeRKValueEachTime", reset_not_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: getCredsMetaData with {protocol} Execution Complete")

    no += 1
    ##37
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID32Bytes_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##38
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID64Bytes_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##39
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##40
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_Truncated_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##41
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_rpName64Bytes_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    no += 1
    ##42
    enumerateRPs2_2.executeEnumerateRPsBeginAndEnumerateRPsGetNextRP("self_rpID255Bytes_rpName255Bytes_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateRPs with {protocol} Execution Complete")
    
    DocumentCreation.add_summary_row(summaryTable, enumerateRPs2_2.COMMAND_NAME, enumerateRPs2_2.PROTOCOL, enumerateRPs2_2.scenarioCount, enumerateRPs2_2.passCount, enumerateRPs2_2.failCount)
    enumerateRPs2_2.failCount = 0
    enumerateRPs2_2.passCount = 0
    enumerateRPs2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"




################## Enumerate Credential for an RPs ##########################

import cbor2
import enumerateCred2_2 

util.printcolor(util.YELLOW, "**** CTAP 2.2 - enumerateCredentialsBegin (0x04) and enumerateCredentialsGetNextCredential (0x05) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
make_cred_required = "yes"
make_cred_not_required = "no"

protocol = "PROTOCOL_ONE"
# protocol = "PROTOCOL_TWO"
enumerateCred2_2.resetPowerCycle(True)
##################### REMOVE COMMENT IF YOU WANT DYNAMIC MAX CRED COUNT ######################
response, status = util.APDUhex("00A4040008A0000006472F0001", "Select applet")
response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
response, status = util.APDUhex("80100000010400", "GetInfo")
if status != "00":
    util.printcolor(util.BLUE,f"GET INFO COMMAND FAILED IN fidoApplication.py WITH STATUS CODE - {status}")
allowedMakeCredCounts = util.getInfoMaximumCredsCountsInteger(response)
print("allowedMakeCredCounts ==========> ",allowedMakeCredCounts)

############################################################################################
for i in range(2):
    no = 0

    no += 1
    #1
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoTool_PositiveCase_with_PCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
   
    no += 1
    #2
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoTool_PositiveCase_with_CM", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
 
    no += 1
    ##3
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_ExactOneCredentialForOneRpIDCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
 
    no += 1
    ##4
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_CheckTotalCredsCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##5
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_CheckNextCredentialResponseFieldsCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##6
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_CheckNextCredentialNumberOfTimesCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    #7
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_CheckEnumerationStateCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##8
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_MostRecentCredCheck", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##9
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_MaximumCredentialWithSingleRpIDCheck", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##10
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_MaximumCredentialWithDifferentRpIDCheck", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##11
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_UserEntityTruncationCheck", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##12
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_AbsentOptionalUserFields", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##13
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_CheckCredentialID", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##14
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_CheckCredProtectPolicy", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##15
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_CheckThirdPartyPayment", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##16
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_MissingPinUvAuthParam", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##17
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_MissingRpIDHash", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##18
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_InvalidProtocol", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##19
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_InvalidPinUvAuthParamWithPCMR", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")

    no += 1
    ##20
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_InvalidPinUvAuthParamWithoutPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##21
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_InvalidPinUvAuthParamWithCM", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##22
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_PinAuthTokenAssociatedRpID", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##23
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_NoDiscoverableCredential", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##24
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("fidoDoc_WithoutPriorCredentialBeginCommandExecuteNext", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##25
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_AllCredentialAlreadyEnumerated", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##26
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_PowerCycleBetweenBeginAndNext", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##27
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_ChangePinBetweenBeginAndNext", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##28
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_MoreThan32BytesRpIDHash", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##29
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_MissingPinUvAuthProtocol", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##30
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_OldPinUvAuthParam", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##31
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_GetPINTokenWith0x05", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##32
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_PINotSetMakeCredAndWithoutPinAuthParamEnumerateCredential", reset_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##33
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_PINotSetDirectNextEnumerateCredential", reset_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##34
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_PINotSetMakeCredAndWithRkAlwaysUvFalse", reset_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    no += 1
    ##35
    enumerateCred2_2.executeEnumerateCredentialsBeginAndEnumerateCredentialsGetNextCredential("self_ProtocolSwapping", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: EnumerateCredentials with {protocol} Execution Complete")
    
    DocumentCreation.add_summary_row(summaryTable, enumerateCred2_2.COMMAND_NAME, enumerateCred2_2.PROTOCOL, enumerateCred2_2.scenarioCount, enumerateCred2_2.passCount, enumerateCred2_2.failCount)
    enumerateCred2_2.failCount = 0
    enumerateCred2_2.passCount = 0
    enumerateCred2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"



################## Delete Credential for an RPs ##########################

import cbor2
import deleteCred2_2

util.printcolor(util.YELLOW, "**** CTAP 2.2 - deleteCredential (0x06) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
make_cred_required = "yes"
make_cred_not_required = "no"

protocol = "PROTOCOL_ONE"
# protocol = "PROTOCOL_TWO"
deleteCred2_2.resetPowerCycle(True)
##################### REMOVE COMMENT IF YOU WANT DYNAMIC MAX CRED COUNT ######################
response, status = util.APDUhex("00A4040008A0000006472F0001", "Select applet")
response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
response, status = util.APDUhex("80100000010400", "GetInfo")
if status != "00":
    util.printcolor(util.BLUE,f"GET INFO COMMAND FAILED IN fidoApplication.py WITH STATUS CODE - {status}")
allowedMakeCredCounts = util.getInfoMaximumCredsCountsInteger(response)
print("allowedMakeCredCounts ==========> ",allowedMakeCredCounts)

############################################################################################
for i in range(2):
    no = 0

    no += 1
    #1
    deleteCred2_2.executeDeleteCredentials("fidoTool_PositiveCase_with_CM", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #2
    deleteCred2_2.executeDeleteCredentials("fidoDoc_PositiveCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #3
    deleteCred2_2.executeDeleteCredentials("self_PositiveCaseMaxCredForSingleRp", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #4
    deleteCred2_2.executeDeleteCredentials("self_PositiveCaseMaxCredForDifferentRp", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #5
    deleteCred2_2.executeDeleteCredentials("fidoDoc_MissingPinUvAuthParamCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #6
    deleteCred2_2.executeDeleteCredentials("fidoDoc_MissingMandatoryParamInSubCommandParamsCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #7
    deleteCred2_2.executeDeleteCredentials("fidoDoc_UnsupportedPinUvAuthProtocolCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #8
    deleteCred2_2.executeDeleteCredentials("fidoDoc_InvalidPinUvAuthParamCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #9
    deleteCred2_2.executeDeleteCredentials("fidoDoc_PinUvAuthTokenWithoutCMPermissionCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #10
    deleteCred2_2.executeDeleteCredentials("fidoDoc_PinUvAuthTokenWithAssociatedRpIDCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #11
    deleteCred2_2.executeDeleteCredentials("fidoDoc_CredentialIDNotMatchCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #12
    deleteCred2_2.executeDeleteCredentials("self_PinUvAuthParamWithDifferentSubCommandCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #13
    deleteCred2_2.executeDeleteCredentials("self_PinUvAuthParamExcludesSubCommandParamsCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #14
    deleteCred2_2.executeDeleteCredentials("self_PinUvAuthParamWithDifferentCredentialIdCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #15
    deleteCred2_2.executeDeleteCredentials("self_TruncatedPinUvAuthParamCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #16
    deleteCred2_2.executeDeleteCredentials("self_LongerPinUvAuthParamCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #17
    deleteCred2_2.executeDeleteCredentials("self_DifferentProcotolForPinUvAuthTokenCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #18
    deleteCred2_2.executeDeleteCredentials("self_PermissionOtherThanCMForPinUvAuthTokenCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #19
    deleteCred2_2.executeDeleteCredentials("self_OldPinUvAuthTokenCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #20
    deleteCred2_2.executeDeleteCredentials("self_IncorrectHashAlgorithmForPinUvAuthParamCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #21
    deleteCred2_2.executeDeleteCredentials("self_CredentialIDIncorrectTypeCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #22
    deleteCred2_2.executeDeleteCredentials("self_EmptyCredentialIDCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #23
    deleteCred2_2.executeDeleteCredentials("self_VeryLargeCredentialIDCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #24
    deleteCred2_2.executeDeleteCredentials("self_UnsupportedParamInSubCommandParamsCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #25
    deleteCred2_2.executeDeleteCredentials("self_UnsupportedTypeInSubCommandParamsCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #26
    deleteCred2_2.executeDeleteCredentials("self_InvalidSubCommandValueCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #27
    deleteCred2_2.executeDeleteCredentials("self_MultipleCredentialIdEntriesCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #28
    deleteCred2_2.executeDeleteCredentials("self_AlreadyDeletedCredentialIdCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #29
    deleteCred2_2.executeDeleteCredentials("self_InvalidCBORMapOrderCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #30
    deleteCred2_2.executeDeleteCredentials("self_DuplicateDeleteCommandCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #31
    deleteCred2_2.executeDeleteCredentials("self_MissingPinUvAuthProtocolCase", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #32
    deleteCred2_2.executeDeleteCredentials("self_SwapProtocolsForPinUvAuthTokenAndDeleteCommand", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
 
    no += 1
    #33
    deleteCred2_2.executeDeleteCredentials("self_WithoutPinSetPinUvAuthTokenAndDelete", reset_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #34
    deleteCred2_2.executeDeleteCredentials("self_NonBytePinUvAuthParam", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #35
    deleteCred2_2.executeDeleteCredentials("self_NonIntegerPinUvAuthProtocol", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #36
    deleteCred2_2.executeDeleteCredentials("self_EmptySubCommandParamsMap", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #37
    deleteCred2_2.executeDeleteCredentials("self_IncorrectConcatenationOrderToComputePinUvAuthParam", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #38
    deleteCred2_2.executeDeleteCredentials("self_PinUvAuthParamComputeOverOnlySubCommandParams", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #39
    deleteCred2_2.executeDeleteCredentials("self_PinUvAuthTokenAfterPowerCycleReset", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #40
    deleteCred2_2.executeDeleteCredentials("self_CredentialCreateWithoutPINSetAndDeleteCredCommandWithPinUvAuthParam", reset_required, set_pin_not_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #41
    deleteCred2_2.executeDeleteCredentials("self_MissingSubCommand", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    no += 1
    #42
    deleteCred2_2.executeDeleteCredentials("self_DeleteCredWithPersistentPinUvAuthTokenWithPCMRPermission", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: DeleteCredential with {protocol} Execution Complete")
    
    DocumentCreation.add_summary_row(summaryTable, deleteCred2_2.COMMAND_NAME, deleteCred2_2.PROTOCOL, deleteCred2_2.scenarioCount, deleteCred2_2.passCount, deleteCred2_2.failCount)
    deleteCred2_2.failCount = 0
    deleteCred2_2.passCount = 0
    deleteCred2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"




###########################################################
##################### UPDATE USER INFO #########################
###########################################################

import updateuserinfoctap2
util.printcolor(util.YELLOW, "**** authenticatorCredentialManagement (0x0A) subcommand updateuserinformation(0x07)****")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinset="no"
for protocols in [1,2]:
    updateuserinfoctap2.getPinUvAuthTokenP2_2("updateuserinfo.T",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("updateuserinfo.D",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("emptyuser&display",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("missing.emptyuser&display",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("useridlength20",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("useridlength64",pinset,protocols,pin)#
    updateuserinfoctap2.getPinUvAuthTokenP2_2("emptyuser&display.length4update",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("emptyuser&display.length4",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.length20update",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.length20",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.length50update",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.length50",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.length100update",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.length100",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.lengthemptyupdated",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.lengthempty",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.fieldabsentupdated",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("username.fieldabsent",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.4byte",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.4byteverify",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.20byte",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.20byteverify",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.50byte",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.50byteverify",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.100byte",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userdisplayname.100byteverify",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("emptyuserdisplayname",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("emptyuserdisplayname.verify",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("displaynameabsent",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("displaynameabsent.verify",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("randomupdate",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("pinUvAuthParam.missing",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("subCommandParams.missing",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("unsupportedprotocol",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("withoutcm.permission",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("rpidnotmatch",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("credidnotmatch",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("useridnotmatch",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("useridlengthexceed",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("emptycredId",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("invalidcredId",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("useridnotencoded",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("useridisempty",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("subcommand.missing",pinset,protocols,pin)#different yubikey 33 card 14 switchbit 12 thales 14
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userentity.null",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("credidfield.null",pinset,protocols,pin) #yubikey 2e,card 14,thales 22,switchbit 14
    updateuserinfoctap2.getPinUvAuthTokenP2_2("publickeytyemissing",pinset,protocols,pin)#card 14,yubikey 14 thales 22,switchbit 00
    updateuserinfoctap2.getPinUvAuthTokenP2_2("subcommandparamfeildnull",pinset,protocols,pin) #all 14 thales 33
    updateuserinfoctap2.getPinUvAuthTokenP2_2("credidtagwrong",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("userentitytagwrong",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("credidtypenotpublickey",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("subcommandparamnotmap",pinset,protocols,pin) #yubikey 02,card 11,thales11,switchbit 11
    updateuserinfoctap2.getPinUvAuthTokenP2_2("invalidsubcommand",pinset,protocols,pin)#yubikey 33,card 01,thales 14 switchbit 12
    updateuserinfoctap2.getPinUvAuthTokenP2_2("pinauthparamlengthgreter",pinset,protocols,pin) # yubikey 03 card 33
    updateuserinfoctap2.getPinUvAuthTokenP2_2("pinauthparamlengthless",pinset,protocols,pin)
    updateuserinfoctap2.getPinUvAuthTokenP2_2("withoutregistercredid",pinset,protocols,pin) #card 2e,yubikey 33 thales 2e,swissbit 2e
    updateuserinfoctap2.getPinUvAuthTokenP2_2("pinauthparamTruncate",pinset,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, updateuserinfoctap2.COMMAND_NAME, updateuserinfoctap2.PROTOCOL, updateuserinfoctap2.scenarioCount, updateuserinfoctap2.passCount, updateuserinfoctap2.failCount)
    updateuserinfoctap2.failCount = 0
    updateuserinfoctap2.passCount = 0
    updateuserinfoctap2.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")





import enableEnterpriseAttestationctap2
util.printcolor(util.YELLOW, "**** Authenticator config enable entrepriseattestion****")
util.printcolor(util.YELLOW,"")
pin="123456"
pinset="yes"
pinnotset="no"

for protocols in [1,2]:
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("enable.atttrue",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epundefined",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("attep2",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("randomep",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epincorrect",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("invalidrp",pinset,protocols,pin)

    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("enable.attestation",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epfalse.subcommandmissing",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epfalse.subcommandinvalid",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("always uvtrue",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("always uvtrue.protocolmissing",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("always uvtrue.protocolinvalid",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("alwaysuvtrue.verificationfailed",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("alwaysuvtrue.afgpermission",pinset,protocols,pin)

    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("enableattestaion.getinfo",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("missing.protocol",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("missing.pinUvAuthParam",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("missing.subcommand",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("invalidsubcomaand",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("invalidprotocol",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("makecred",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("makecredepfalse",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("attestion2",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("attestion2epfalse",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("randomattestion",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("exceptattestion",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("Anyrpid",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("wrongrpid",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("verifyfailed",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epvaluewrong",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("invalidpinauthparam",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("messagelengthless",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("messagelengthgreater",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("messageformatnot",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("ep.false",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("nonentrprise",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("pinauthnotbyte",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("eptrytodisable",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epdisable",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epdisableinitial",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("epdisabletrytoprovideep",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("notprovidingpermission",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("Verfysignature",pinset,protocols,pin)
    enableEnterpriseAttestationctap2.getPinUvAuthTokenP2_2("signaturefailed",pinset,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, enableEnterpriseAttestationctap2.COMMAND_NAME, enableEnterpriseAttestationctap2.PROTOCOL, enableEnterpriseAttestationctap2.scenarioCount, enableEnterpriseAttestationctap2.passCount, enableEnterpriseAttestationctap2.failCount)
    enableEnterpriseAttestationctap2.failCount = 0
    enableEnterpriseAttestationctap2.passCount = 0
    enableEnterpriseAttestationctap2.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")


##########################################################################
##########################################################################
##########################################################################
################# authenticonfig Subcommand  toggleAlwaysUv###
##########################################################################
##########################################################################
##########################################################################
import toggleAlwaysUv
util.printcolor(util.YELLOW, "**** Authenticator config  toggleAlwaysUv(0x02)1****")
util.printcolor(util.YELLOW,"")
pin="123456"
pinset="yes"
pinnotset="no"
for protocols in [1,2]:
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuvwitoutpin",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("makeCredUvNotRqd",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuv",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuv.getinfo",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuv.makecred",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("makeCredUvNotRqdtrue",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuvpinauthparam",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("resetcommannd",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuv.paramadded",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuvtrueminimumpinlength",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuvtrueprotocol",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuvtrueinvalidprotocol",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysuvtrueverificationfailed",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("withoutafgpermission",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("alwaysUv.opposite",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("subcommand.missing",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("pinUvAuthParam.missing",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("pinUvAuthProtocol.missing",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("invalid.subcommand",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("invalid.pinUvAuthParam",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("invalid.pinUvAuthProtocol",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("verification.failed",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("pinauthparm.lengthless",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("pinauthparm.lengthgreater",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("toggleAlwaysUv.disable",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("toggleAlwaysUv.enable",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("messageformat.wrong",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("afgpermission.notprovide",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("protocolviceversa",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("pinauthparam.notbyte",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("toggleAlwaysUvreset",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("pinauthoken",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("featurenotbedisable",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("Verfysignature",pinset,protocols,pin)
    toggleAlwaysUv.getPinUvAuthTokenP2_2("signaturefailed",pinset,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, toggleAlwaysUv.COMMAND_NAME, toggleAlwaysUv.PROTOCOL, toggleAlwaysUv.scenarioCount, toggleAlwaysUv.passCount, toggleAlwaysUv.failCount)
    toggleAlwaysUv.failCount = 0
    toggleAlwaysUv.passCount = 0
    toggleAlwaysUv.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")



###########################################################################
###########################################################################
###########################################################################
################## authenticonfig Subcommand minimumpinlength ###
###########################################################################
###########################################################################
###########################################################################

#Testing done

import minimumpinlength_authticonfig
pinset="yes"
pinnotset="no"
pin="112233"

for protocols in [1,2]:
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("getinfo",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("getinfowithoutpin",pinnotset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("newpinlength",pinnotset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("newpinlengthwithpin",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("forcechangepinTrue",pinnotset,protocols,pin) #negative test case
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("forcechangepinTruewithpin",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("forcechangepinSetTrue",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("Authrizedrp",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("Authrizedrpwithpinlengthset",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("Authrizedrpwithallparam",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("unAuthrizedrp",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("resetauthenticator",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("pincomplexity",pinset,protocols,pin)

    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("pinlengthdecreses",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("forcepintruepin",pinnotset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("keystoragefull",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("missingpinauthparam",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("protocolmissing",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("subcommandismissing",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("subcommandparamismissing",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("invalidpinauthparam",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("pinauthparamlengthinvalid",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("pinauthparamlengthless",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("invalidprotocol",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("invalidsubcommand",pinset,protocols,pin)
    minimumpinlength_authticonfig.getPinUvAuthTokenP2_2("invalidsubcommandparam",pinset,protocols,pin)

    DocumentCreation.add_summary_row(summaryTable, minimumpinlength_authticonfig.COMMAND_NAME, minimumpinlength_authticonfig.PROTOCOL, minimumpinlength_authticonfig.scenarioCount, minimumpinlength_authticonfig.passCount, minimumpinlength_authticonfig.failCount)
    minimumpinlength_authticonfig.failCount = 0
    minimumpinlength_authticonfig.passCount = 0
    minimumpinlength_authticonfig.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")



###########################################################################
###########################################################################
###########################################################################
################## AUTHENTICATOR MAKE CREDENTIAL ##########################
###########################################################################
###########################################################################
###########################################################################

import cbor2
import authenticatorMakeCredential2_2

util.printcolor(util.YELLOW, "**** CTAP 2.2 - authenticatorMakeCredential (0x01) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
make_cred_required = "yes"
make_cred_not_required = "no"

protocol = "PROTOCOL_ONE"
# protocol = "PROTOCOL_TWO"
authenticatorMakeCredential2_2.resetPowerCycle(True)
##################### REMOVE COMMENT IF YOU WANT DYNAMIC MAX CRED COUNT ######################
response, status = util.APDUhex("00A4040008A0000006472F000100", "Select applet")
response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
response, status = util.APDUhex("80100000010400", "GetInfo")
if status != "00":
    util.printcolor(util.BLUE,f"GET INFO COMMAND FAILED IN fidoApplication.py WITH STATUS CODE - {status}")
allowedMakeCredCounts = util.getInfoMaximumCredsCountsInteger(response)
print("allowedMakeCredCounts ==========> ",allowedMakeCredCounts)

# ############################################################################################
for i in range(2):
    no = 0

    no += 1
    #1
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_1", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #2
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_2", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
 
    no += 1
    #3
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_3", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
 
    no += 1
    #4
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_4", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
 
    no += 1
    #5
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_5", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #6
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_6", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
   
    no += 1
    #7
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_7", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #8
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_8", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #9
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_9", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #10
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_10", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #11
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_11", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #12
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_12", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #13
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_13", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #14
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_14", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #15
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_15", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #16
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_16", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #17
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_17", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #18
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_18", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #19
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_19", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #20
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_20", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #21
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_21", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #22
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_22", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #23
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_23", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #24
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_24", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #25
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_25", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #26
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_26", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #27
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_27", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #28
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_28", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #29
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_29", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #30
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_30", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #31
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_31", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #32
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_32", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #33
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_33", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #34
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_34", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    ## #35 ---> Do Not Execute because uv not support
    ## authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_35", reset_required, set_pin_required, protocol)
    ## util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #36
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_36", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #37
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_37", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #38
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_38", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #39
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_39", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    ## #40 >>>> Not Implemented Because UV not support
    ## authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_40", reset_required, set_pin_required, protocol)
    ## util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #41
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_41", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #42
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_42", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #43
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_43", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #44
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_44", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #45
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_45", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #46
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_46", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #47
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoTool_47", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #48
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_1", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #49
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_2", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #50
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_3", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #51
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_4", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #52
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_5", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #53
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_6", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #54
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_7", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #55
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_8", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #56
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_9", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #57
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_10", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #58
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_11", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #59
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_12", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #60
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_13", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #61
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_14", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #62
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_15", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #63
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_16", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #64
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_17", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #65
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_18", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #66
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_19", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #67
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_20", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #68
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_21", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #69
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_22", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #70
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_23", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #71
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_24", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #72
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_25", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #73
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_26", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #74
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_27", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #75
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_28", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #76
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_29", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #77
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_30", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #78
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_31", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #79
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_32", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #80
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_33", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #81
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_34", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #82
    ## authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_35", reset_required, set_pin_required, protocol)
    ## util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #83
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_36", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #84
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_37", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #85
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_38", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #86
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_39", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #87
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_40", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #88
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_41", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #89
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_42", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #90
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_43", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #91
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_44", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #92
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_45", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #93
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_46", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #94
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_47", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #95
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_48", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #96
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_49", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #97
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_50", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #98
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_51", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #99
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_52", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #100
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_53", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #101
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_54", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #102
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_55", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #103
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_56", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #104
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_57", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #105
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_58", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #106
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_59", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #107
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_60", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #108
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_61", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #109
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_62", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #110
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_63", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
 
    no += 1
    #111
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_64", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
 
    no += 1
    #112
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_65", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #113
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_66", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #114
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_67", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #115
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_68", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #116
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_69", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #117
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_70", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #118
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_71", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #119
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_72", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #120
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_73", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #121
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_74", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #122
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_75", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #123
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_76", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #124 == Covered in 71
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_77", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #125
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_78", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #126
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_79", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##127 == Already covered in positive cases
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_80", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##128 == Already covered in positive cases
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_81", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #129
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_82", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #130
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_83", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #131
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_84", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #132
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_85", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #133
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_86", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #134
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_87", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #135 == Already Covered in 69
    #authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_88", reset_required, set_pin_required, protocol)
    #util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #136
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_89", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    

    no += 1
    #137
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_90", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #138
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_91", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #139
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_92", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##140
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_93", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##141
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_94", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##142
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_95", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #143
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_96", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #144
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_97", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #145
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_98", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##146
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_99", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #147
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_100", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##148 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_101", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##149 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_102", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##150 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_103", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##151 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_104", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##152 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_105", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##153 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_106", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##154 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_107", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##155 ==> Temporary Commented after fixing run it
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_108", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #156
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_109", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #157
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_110", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #158
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_111", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #159
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_112", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #160
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_113", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #161
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_114", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #162
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_115", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #163
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_116", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #164
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_117", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #165
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_118", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #166
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_119", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #167
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_120", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #168
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_121", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #169
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_122", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #170
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_123", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #171
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_124", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #172
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_125", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #173
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_126", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #174
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_127", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #175
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_128", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #176
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_129", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #177
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_130", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #178
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_131", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##179 ==> Not Implemented 
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_132", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##180 ==> Not Implemented
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_133", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #181
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_134", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #182
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_135", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #183
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_136", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #184
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_137", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #185
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_138", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #186
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_139", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #187
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_140", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    188
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_141", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #189
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_142", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #190
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_143", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #191
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_144", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #192
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_145", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #193
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_146", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #194
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_147", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #195
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_148", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #196
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_149", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #197
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_150", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    ##198 ==> Covered in fidoStd_147
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_151", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##199 ==> Already Covered Positive 
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_152", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##200 ==> Already Covered Positive 
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_153", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #201
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_154", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #202
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_155", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #203
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_156", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #204
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_157", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #205
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_158", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #206
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_159", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #207
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_160", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #208
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_161", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #209
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_162", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #210
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_163", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##211 ==> Already Covered
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_164", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##212 ==> Already Covered
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_165", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##213 ==> Already Covered
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_166", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #214
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_167", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #215
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_168", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    ##216
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_169", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##217
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_170", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##218
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_171", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##219
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_172", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##220
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_173", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##221
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_174", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #222
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_175", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #223
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_176", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #224
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_177", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #225
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_178", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #226
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_179", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #227
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_180", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #228
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_181", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #229
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_182", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #230
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_183", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #231
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_184", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #232
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_185", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #233
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_186", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #234
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_187", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #235
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_188", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #236
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_189", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #237
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_190", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #238
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_191", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #239
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_192", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #240
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_193", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##241 == Not Support
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_194", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##242 == Not Support
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_195", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #243
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_196", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##244
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_197", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##245
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_198", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##246
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_199", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #247
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_200", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    
    no += 1
    #248
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_201", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##249
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_202", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #250
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_203", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##251
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_204", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##252
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_205", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##253
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_206", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##254
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_207", reset_required, set_pin_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")


    no += 1
    #255
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_1", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    ##256 ==> Already covered in above case
    ##authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_2", reset_required, set_pin_not_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #257
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_3", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #258
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_4", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")
    

    no += 1
    #259
    #authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_5", reset_required, set_pin_not_required, protocol)
    #util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #260
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_6", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #261
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_7", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #262
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_8", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #263
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_9", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #264
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_10", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #265
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_11", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #266
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_12", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #267
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("self_13", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #268
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_208", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #269
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_209", reset_required, set_pin_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #270
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_210", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    no += 1
    #271
    authenticatorMakeCredential2_2.executeAuthenticatorMakeCredential("fidoStd_211", reset_required, set_pin_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: MakeCredential with {protocol} Execution Complete")

    DocumentCreation.add_summary_row(summaryTable, authenticatorMakeCredential2_2.COMMAND_NAME, authenticatorMakeCredential2_2.PROTOCOL, authenticatorMakeCredential2_2.scenarioCount, authenticatorMakeCredential2_2.passCount, authenticatorMakeCredential2_2.failCount)
    authenticatorMakeCredential2_2.failCount = 0
    authenticatorMakeCredential2_2.passCount = 0
    authenticatorMakeCredential2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"




##########################################################################
##########################################################################
##########################################################################
#################     MAKE CRED EXTENSION - HMAC      ####################
##########################################################################
##########################################################################
##########################################################################

import makecredextensionhmac_secret
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) Extension HmacSercert Extension ***********")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinsetrequried="yes"
pinnotrequried="no"

for protocols in [1,2]:
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest1",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest2",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest3",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest4",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest5",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest6",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("getinfocase5",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("getinfocase6",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase7",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase8",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase9",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase10",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase11",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase12",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase13",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase14",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase15",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase16",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase17",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase18",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase19",pinnotrequried,protocols,pin)

    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase20",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase21",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase22",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase23",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase24",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase25",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest7",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest8",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest9",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest10",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest11",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("tooltest12",pinsetrequried,protocols,pin)

    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase26",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase27",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase28",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase29",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase30",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase31",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase32",pinsetrequried,protocols,pin)#pending
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase33",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase34",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase35",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase36",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase37",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase38",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase39",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret.getPinUvAuthTokenP2_2("hmaccase40",pinsetrequried,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, makecredextensionhmac_secret.COMMAND_NAME, makecredextensionhmac_secret.PROTOCOL, makecredextensionhmac_secret.scenarioCount, makecredextensionhmac_secret.passCount, makecredextensionhmac_secret.failCount)
    makecredextensionhmac_secret.failCount = 0
    makecredextensionhmac_secret.passCount = 0
    makecredextensionhmac_secret.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")

##########################################################################
##########################################################################
##########################################################################
#################  MAKE CRED EXTENSION - CRED PROTECT  ###################
##########################################################################
##########################################################################
##########################################################################

import makecredextension
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) extension credprotect****")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinset="no"

for protocols in [1,2]:
    makecredextension.getPinUvAuthTokenP2_2("credprotect01",pinset,protocols,pin)#card 14 yubikwey pass,all pass
    makecredextension.getPinUvAuthTokenP2_2("credprotect02",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("credprotect03",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("credmanagement",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("getinfo.extension",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvoptional",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("rktruecred01",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvwithcredId",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvwithcredIdrktrue",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvrequried",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvrequrieduvtrue",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvoptinalwithoutpinverify",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvoptinalwithoutpinrktrue",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("credidwithoutpinverify",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("credidwithoutpinrktrue",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvrequriedwithoutpinverify",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("uvrequriedwithoutpinrktrue",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("u2fauthentication",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("u2fauthenticationwithpin",pinset,protocols,pin)

    makecredextension.getPinUvAuthTokenP2_2("credvaluewrongwithpin",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("credvaluewrong",pinset,protocols,pin)
    makecredextension.getPinUvAuthTokenP2_2("mapsizewrong",pinset,protocols,pin)#switchbit 02 yubikey 12  card 14 thales 12
    DocumentCreation.add_summary_row(summaryTable, makecredextension.COMMAND_NAME, makecredextension.PROTOCOL, makecredextension.scenarioCount, makecredextension.passCount, makecredextension.failCount)
    makecredextension.failCount = 0
    makecredextension.passCount = 0
    makecredextension.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")


##########################################################################
##########################################################################
##########################################################################
##############  MAKE CRED EXTENSION - THIRD PARTY PAYMENT  ###############
##########################################################################
##########################################################################
##########################################################################

import makecredextensionthirdPartyPayment
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) Extension thirdPartyPayment ***********")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinsetrequried="yes"
pinnotrequried="no"
for protocols in [1,2]:
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("getinfo",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("getinfowithoutpin",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase3",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase4",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase5",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase6",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase7",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase8",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase9",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase10",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase11",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase12",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase13",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase14",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase15",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase16",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase17",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase18",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase19",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase20",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase21",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase22",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase23",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase24",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase25",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase26",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase27",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase28",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase29",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase30",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase31",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase32",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase33",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase34",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase35",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase36",pinsetrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase37",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase38",pinnotrequried,protocols,pin)
    makecredextensionthirdPartyPayment.getPinUvAuthTokenP2_2("thardpartytestcase39",pinsetrequried,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, makecredextensionthirdPartyPayment.COMMAND_NAME, makecredextensionthirdPartyPayment.PROTOCOL, makecredextensionthirdPartyPayment.scenarioCount, makecredextensionthirdPartyPayment.passCount, makecredextensionthirdPartyPayment.failCount)
    makecredextensionthirdPartyPayment.failCount = 0
    makecredextensionthirdPartyPayment.passCount = 0
    makecredextensionthirdPartyPayment.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")



##########################################################################
##########################################################################
##########################################################################
###################  MAKE CRED EXTENSION - CRED BLOB  ####################
##########################################################################
##########################################################################
##########################################################################

import makecredextensioncredblob
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) extension credblob.***********")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinset="no"

for protocols in [1,2]:

    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblob.T",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblob.Discoverable",pinset,protocols,pin)#makecred response our card is getting false
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobnotsetinmakecred",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("verfycredblob",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobwithu2f",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutcredblobmakecred",pinset,protocols,pin)

    ## makecredextensioncredblob.getPinUvAuthTokenP2_2("credbloblengthexceed",pinset,protocols,pin)#pending yubikey 03
    
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credbloblengthzero",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobandcredprotect",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobandcredprotect02",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobandcredprotect03",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("getasseration.credblobfalse",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("extensionmappresent",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutincludingextension",pinset,protocols,pin)

    makecredextensioncredblob.getPinUvAuthTokenP2_2("nondiscoverable",pinset,protocols,pin)  ## Failed with SWs = 6200 in make cred
   
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobnotstoremakecred",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credbloblengthincress",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobnotpresent",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobfalseauthention",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobnotauthention",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobkeyauthention",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobnotstore",pinset,protocols,pin)


    makecredextensioncredblob.getPinUvAuthTokenP2_2("credblobwithoutpin",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredblobnotstore",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredbloblengthincess",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpingetasserationfalse",pinset,protocols,pin)#3b switcbit
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpingetasserationnot",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpinnondiscoverable",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutStrongextension",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredblobincress",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredblobextension",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredblobfalse",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredblobauthentication",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("withoutpincredblobnot",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("u2fauthenticationwithpin",pinset,protocols,pin)
    makecredextensioncredblob.getPinUvAuthTokenP2_2("u2fregistationwitoutpin",pinset,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, makecredextensioncredblob.COMMAND_NAME, makecredextensioncredblob.PROTOCOL, makecredextensioncredblob.scenarioCount, makecredextensioncredblob.passCount, makecredextensioncredblob.failCount)
    makecredextensioncredblob.failCount = 0
    makecredextensioncredblob.passCount = 0
    makecredextensioncredblob.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")



##########################################################################
##########################################################################
##########################################################################
################  MAKE CRED EXTENSION - MIN PIN LENGTH  ##################
##########################################################################
##########################################################################
##########################################################################

import makecredextensionminpinlength
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) Extension MinPinLength Extension ***********")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinsetrequried="yes"
pinnotrequried="no"

for protocols in [1,2]:
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case1setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("getinfo",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("authorizedrp",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("unauthorizedrp",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case4setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case5setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case6setminpin",pinsetrequried,protocols,pin)#yubikey2c all other card igonre
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case7setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case8setminpin",pinsetrequried,protocols,pin) 
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case9setminpin",pinsetrequried,protocols,pin) #problem 33 minimumpinlength
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case11setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case12setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case13setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case14setminpin",pinsetrequried,protocols,pin)
    
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case15setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case16setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case17setminpin",pinsetrequried,protocols,pin)
    
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case18setminpin",pinsetrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case19setminpin",pinsetrequried,protocols,pin)

    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case20setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case21setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case22setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case23setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case24setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case25setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case26setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case27setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case28setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case29setminpin",pinnotrequried,protocols,pin)
    makecredextensionminpinlength.getPinUvAuthTokenP2_2("case30setminpin",pinnotrequried,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, makecredextensionminpinlength.COMMAND_NAME, makecredextensionminpinlength.PROTOCOL, makecredextensionminpinlength.scenarioCount, makecredextensionminpinlength.passCount, makecredextensionminpinlength.failCount)
    makecredextensionminpinlength.failCount = 0
    makecredextensionminpinlength.passCount = 0
    makecredextensionminpinlength.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")

##########################################################################
##########################################################################
##########################################################################
###############  MAKE CRED EXTENSION - HMAC SECRET MC  ###################
##########################################################################
##########################################################################
##########################################################################

import makecredextensionhmac_secret_mc
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) Extension HmacSercert-MC ***********")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinsetrequried="yes"
pinnotrequried="no"


for protocols in [1,2]:
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("getinfo",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase2",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase3",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase4",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase5",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase6",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase7",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase8",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase9",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase10",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase11",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase12",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase13",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase14",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase15",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase16",pinsetrequried,protocols,pin)

    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase17",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase18",pinsetrequried,protocols,pin)

    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase19",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase20",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase21",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase22",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase23",pinsetrequried,protocols,pin) #protocol 0 hmac yubikey working
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase24",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase25",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase26",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase27",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase28",pinsetrequried,protocols,pin) 
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase29",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase30",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase31",pinsetrequried,protocols,pin)

    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase32",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase33",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase34",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase35",pinsetrequried,protocols,pin)#yubikeyworking
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase36",pinsetrequried,protocols,pin)#bug requried 3b
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase37",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase38",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase39",pinsetrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("hmac_secret_mccase12",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("u2fregistationwithauthentication",pinnotrequried,protocols,pin)
    makecredextensionhmac_secret_mc.getPinUvAuthTokenP2_2("u2fregistation",pinsetrequried,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, makecredextensionhmac_secret_mc.COMMAND_NAME, makecredextensionhmac_secret_mc.PROTOCOL, makecredextensionhmac_secret_mc.scenarioCount, makecredextensionhmac_secret_mc.passCount, makecredextensionhmac_secret_mc.failCount)
    makecredextensionhmac_secret_mc.failCount = 0
    makecredextensionhmac_secret_mc.passCount = 0
    makecredextensionhmac_secret_mc.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")


##########################################################################
##########################################################################
##########################################################################
################  MAKE CRED EXTENSION - PIN COMPLEXITY  ##################
##########################################################################
##########################################################################
##########################################################################

import makecredextension_pinComplexityPolicy
util.printcolor(util.YELLOW, "**** authenticatorMakeCredential (0x01) Extension pinComplexityPolicy ***********")
util.printcolor(util.YELLOW,"")
pin="11223344"
pinsetrequried="yes"
pinnotrequried="no"
for protocols in [1,2]:
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("forcepintruet1",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("forcepintruet2",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("getinfo",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("getinfowithoutpin",pinnotrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("pincomplexitytrue",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("pincomplexitytruerkfalse",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("Authenticatorreset",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("UnauthorizedRpId",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("CheckPinComplexity",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("minimumpinlength",pinnotrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("minimumpinlengthwithpin",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("extensionminimumpinlength",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("normalpinset",pinsetrequried,protocols,pin)   ##Failed 
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("unautherizedrplist",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("nondiscoverable",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("normalpinsetafterpincomplexity",pinsetrequried,protocols,pin) ##Failed
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("randompin",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("serialpin",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("pinnotsetafterreset",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("clientchangepin",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("cborwrong",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("u2fregistationwithoupin",pinnotrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("u2fregistationwithpin",pinsetrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("checkSetPINBlockListPINs",pinnotrequried,protocols,pin)
    makecredextension_pinComplexityPolicy.getPinUvAuthTokenP2_2("checkChangePINBlockListPINs",pinsetrequried,protocols,pin)
    DocumentCreation.add_summary_row(summaryTable, makecredextension_pinComplexityPolicy.COMMAND_NAME, makecredextension_pinComplexityPolicy.PROTOCOL, makecredextension_pinComplexityPolicy.scenarioCount, makecredextension_pinComplexityPolicy.passCount, makecredextension_pinComplexityPolicy.failCount)
    makecredextension_pinComplexityPolicy.failCount = 0
    makecredextension_pinComplexityPolicy.passCount = 0
    makecredextension_pinComplexityPolicy.scenarioCount = 0
    util.printcolor(util.CYAN, f"PROTOCOL {protocols} EXECUTED")











##########################################################################
##########################################################################
##########################################################################
#################  AUTHENTICATOR GET ASSERTION  ##########################
##########################################################################
##########################################################################
##########################################################################

import cbor2
import authenticatorGetAssertion2_2

util.printcolor(util.YELLOW, "**** CTAP 2.2 - authenticatorGetAssertion (0x02)/authenticatorGetNextAssertion(0x08) Scenarios ****")
util.printcolor(util.YELLOW,"")

reset_required = "yes"
reset_not_required = "no"
set_pin_required = "yes"
set_pin_not_required = "no"
make_cred_required = "yes"
make_cred_not_required = "no"

protocol = "PROTOCOL_ONE"
# protocol = "PROTOCOL_TWO"
authenticatorGetAssertion2_2.resetPowerCycle(True)
##################### REMOVE COMMENT IF YOU WANT DYNAMIC MAX CRED COUNT ######################
response, status = util.APDUhex("00A4040008A0000006472F000100", "Select applet")
response, status = util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
response, status = util.APDUhex("80100000010400", "GetInfo")
if status != "00":
    util.printcolor(util.BLUE,f"GET INFO COMMAND FAILED IN fidoApplication.py WITH STATUS CODE - {status}")
allowedMakeCredCounts = util.getInfoMaximumCredsCountsInteger(response)
print("allowedMakeCredCounts ==========> ",allowedMakeCredCounts)


############################################################################################
for i in range(2):
    no = 0

    #################################################################
    ########################### FIDO TOOL ###########################
    #################################################################

    no += 1
    #1
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_1", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #2
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_2", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #3
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_3", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #4
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_4", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #5
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_5", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #6
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_6", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #7
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_7", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #8
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_8", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #9
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_9", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #10
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_10", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #11
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_11", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #12
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_12", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #13
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_13", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #14
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_14", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #15
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_15", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #16
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_16", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #17
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_17", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #18
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_18", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #19
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_19", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #20
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoTool_20", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    ###############################################################
    ##################### FIDO STANDARD ###########################
    ###############################################################

    no += 1
    #21
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_1", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #22
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_2", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")
   
    no += 1
    #23
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_3", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #24
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_4", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##25 -- There is no limit for rp.id; So not implemented
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_5", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #26
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_6", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #27
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_7", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #28
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_8", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #29
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_9", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #30
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_10", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #31
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_11", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #32
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_12", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #33
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_13", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #34
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_14", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #35
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_15", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #36
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_16", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #37
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_17", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #38
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_18", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #39
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_19", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #40
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_20", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #41
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_21", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #42
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_22", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #43
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_23", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #44
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_24", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #45
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_25", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #46
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_26", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #47
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_27", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #48
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_28", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #49
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_29", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##50 ==> Covered in TOOL case no. 19 & 20
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_30", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #51
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_31", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #52
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_32", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #53
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_33", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #54
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_34", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #55
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_35", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #56
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_36", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #57
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_37", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##58 ==> Covered in fidoStd_2
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_38", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #59
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_39", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #60
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_40", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #61
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_41", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##62 == > Covered in 31
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_42", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #63
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_43", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #64
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_44", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #65
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_45", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #66
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_46", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##67 ==> Already Covered
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_47", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #68
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_48", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #69
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_49", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #70
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_50", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##71 ==> Already Covered
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_51", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##72 ==> Already Covered
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_52", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##73 ==> Already Covered
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_53", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##74 ==> Already Covered
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_54", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #75
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_55", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##76 ==> Cant implement because there is no signCount limit
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_56", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##77 ==> Actually Get PIN Token Command will return 31 so it is already implemented
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_57", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##78 ==> Actually Get PIN Token Command will return 31 so it is already implemented
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_58", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #79
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_59", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##80
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_60", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #81
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_61", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##82 
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_62", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##83
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_63", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ###84
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_64", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##85
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_65", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##86
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_66", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##87
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_67", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #88
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_68", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #89
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_69", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##90
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_70", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #91
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_71", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #92
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_72", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #93
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_73", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##94
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_74", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #95
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_75", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##96
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_76", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##97
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_77", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##98
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_78", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #99
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_79", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #100
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_80", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##101
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_81", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #102
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_82", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #103
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_83", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #104
    #authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_84", reset_required, set_pin_required, make_cred_required, protocol)
    #util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##105
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_85", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##106
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_86", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##107
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_87", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##108
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_88", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##109
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_89", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##110
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_90", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##111
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_91", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##112
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_92", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #113
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_93", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##114
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_94", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #115
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_95", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #116
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("fidoStd_96", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    ################################################################
    ########################## SELF ################################
    ################################################################

    no += 1
    #117
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_1", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #118
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_2", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #119
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_3", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##120
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_4", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##121
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_5", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #122
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_6", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #123
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_7", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##124
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_8", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##125
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_9", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##126
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_10", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##127
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_11", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##128
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_12", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##129
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_13", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #130
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_14", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #131
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_15", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #132
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_16", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")
    
    no += 1
    #133
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_17", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #134
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_18", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #135
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_19", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #136
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_20", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #137
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_21", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #138
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_22", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #139
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_23", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #140
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_24", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##141
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_25", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #142
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_26", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #143
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_27", reset_required, set_pin_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #144
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_28", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #145
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_29", reset_required, set_pin_required, make_cred_not_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##146 == > Invalid Scenario
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_30", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##147
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_31", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##148
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_32", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##149
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_33", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##150
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_34", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##151
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_35", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##152
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_36", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    ##153
    ##authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_37", reset_required, set_pin_required, make_cred_required, protocol)
    ##util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    no += 1
    #154
    authenticatorGetAssertion2_2.executeAuthenticatorGetAssertion("self_38", reset_required, set_pin_not_required, make_cred_required, protocol)
    util.printcolor(util.BLUE,f"Test Case {no}: Get Assertion with {protocol} Execution Complete")

    DocumentCreation.add_summary_row(summaryTable, authenticatorGetAssertion2_2.COMMAND_NAME, authenticatorGetAssertion2_2.PROTOCOL, authenticatorGetAssertion2_2.scenarioCount, authenticatorGetAssertion2_2.passCount, authenticatorGetAssertion2_2.failCount)
    authenticatorGetAssertion2_2.failCount = 0
    authenticatorGetAssertion2_2.passCount = 0
    authenticatorGetAssertion2_2.scenarioCount = 0
    protocol = "PROTOCOL_TWO"










DocumentCreation.saveAllFiles(doc, FILE_NAME)





















































































###################          sasmita cade    ###############################################
# util.printcolor(util.YELLOW, "**** Client PIN Set with CTAP 2.2 ****")
# util.printcolor(util.YELLOW,"")
# reset_requried="yes"
# reset_not_requried="no"
#Setpinp22.authenticatorClientPinP2_2("minimumpin.length",reset_requried)#succes
# Setpinp22.authenticatorClientPinP2_2("maximumpin.length",reset_requried)
#Setpinp22.authenticatorClientPinP2_2("random.pin",reset_requried)
#Setpinp22.setnewpin()
#Setpinp22.authenticatorClientPinP2_2("exting.pin",reset_not_requried)
#Setpinp22.authenticatorClientPinP2_2("getpin.retries",reset_requried)
#Setpinp22.authenticatorClientPinP2_2("wrong.pin",reset_not_requried)
#Setpinp22.authenticatorClientPinP2_2("pinalreayset",reset_not_requried)

#Setpinp22.authenticatorClientPinP2_2("wrong.pin1",reset_not_requried)#new

#Setpinp22.authenticatorClientPinP2_2("pinlengthLess",reset_requried)#success
# Setpinp22.authenticatorClientPinP2_2("pinlengthexced",reset_requried)#success
# Setpinp22.authenticatorClientPinP2_2("newpin",reset_not_requried)#success
# Setpinp22.authenticatorClientPinP2_2("pinnotset",reset_requried)#success

#Setpinp22.authenticatorClientPinP2_2("notpadding",reset_requried) #11

#Setpinp22.authenticatorClientPinP2_2("noretries",reset_requried)#success
#Setpinp22.authenticatorClientPinP2_2("missing.param",reset_requried)#success
#Setpinp22.authenticatorClientPinP2_2("invalid.param",reset_requried)#card 33or02(optional)
#Setpinp22.authenticatorClientPinP2_2("protocolnotsupported",reset_requried)#success

#Setpinp22.authenticatorClientPinP2_2("subcomanndnotsupported",reset_requried) #card 12 yubikey 01
#Setpinp22.authenticatorClientPinP2_2("keyAgreement.invalid",reset_requried)#card 12 yubikey 00

#Setpinp22.authenticatorClientPinP2_2("validkeyAgreement",reset_requried)#success
#Setpinp22.authenticatorClientPinP2_2("hmac.notmatch",reset_requried)#sucess
#Setpinp22.authenticatorClientPinP2_2("pinauth.invalid",reset_requried)#success

#Setpinp22.authenticatorClientPinP2_2("paddedPin.invalid",reset_requried) #yubikey 02 card 37
#Setpinp22.authenticatorClientPinP2_2("without.paddedPin",reset_requried)

#Setpinp22.authenticatorClientPinP2_2("Hmacreuse",reset_requried)#succes
#Setpinp22.authenticatorClientPinP2_2("wrong.protocol",reset_requried) #success





























##################getpintokenUVauth using permission(0x09) with CTAP2.2##########################
# import getpinuvauthtokenctap2_2
# util.printcolor(util.YELLOW, "**** getPinUvAuthTokenUsingPinWithPermissions CTAP2.2 all the test case secnarios****")
# util.printcolor(util.YELLOW,"")
# pin="123456"
# getpinuvauthtokenctap2_2.restPin(pin)
# pinset="yes"
# pinnotset="no"
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("cmPermission",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("acfgPermission",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("mcPermission",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("gaPermission",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("lbwpermission",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("bepermission",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("getpinToken",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("permission.zero",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("verifycmper",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("verifyacfgper",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("verifymcper",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("verifygaper",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("withoutpingetpintoken",pin,pinnotset)

#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("InvalidPIN",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("InvalidpinHashEnc",pin,pinset)#pending
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("Invalidkey_agreement",pin,pinset)#failed 12
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("Invalidpermission",pin,pinset)#failed pending
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("piuvauthmissing",pin,pinset)

#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("keyAgreementmissing",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("subcommandInvalid",pin,pinset)#failed 12
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("pinauthblocked",pin,pinset)
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("pinauthblocked.pin",pin,pinset)
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("pinretry",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("withpowercycle",pin,pinset)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("pinblocked",pin,pinset)
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("Invalidkey_sharesecret",pin,pinset)#failed 12
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("platformCOSKEY.notmap",pin,pinset)#failed 12
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("pinHashEnc.notbyte",pin,pinset)
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("forcepinset",pin,pinset)#failed
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("changepin",pin,pinset)
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("changewrongpin",pin,pinset)
#getpinuvauthtokenctap2_2.restPin(pin)
#getpinuvauthtokenctap2_2.getPinUvAuthTokenP2_2("forcechangepin.false",pin,pinset)





























































































################### minPinLength  #################################
#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("123456")
#user="john_doe"
#hashchallenge = os.urandom(32);
#RP_domain="demo-login.test"
#minpinlength.minPinLength("123456", hashchallenge, RP_domain, user)

################  Enterprise Attestation ############################
#util.ResetCardPower()
#util.ConnectJavaCard()
#setpin.clientPinSet("123456")
#entrepriseattestation.enableEP("123456")
#user="john_doe"
#hashchallenge = os.urandom(32);
#RP_domain="demo-login.test"
#entrepriseattestation.authenticatorMakeCredential("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#RP_domain="enterprisetest.certinfra.fidoalliance.org"
#entrepriseattestation.authenticatorMakeCredentials("123456",hashchallenge, RP_domain, user)
#entrepriseattestation.consumerProfile("123456")
#entrepriseattestation.notEnterPrise("123456")
#entrepriseattestation.notSupportconsumer("123456")
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="john_doe"
#hashchallenge = os.urandom(32);

#RP_domain="enterprisetest.certinfra.fidoalliance.org"
#entrepriseattestation.randomAttestionData("123456",hashchallenge, RP_domain, user)
#entrepriseattestation.attestionvalueisNotMatch("123456",hashchallenge, RP_domain, user)
#wrongrpid="abcd.com"
#entrepriseattestation.wrongrpId("123456",hashchallenge, wrongrpid, user)

##############    HMAC Secret  ######################

#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#hmacSecret.authenticatorClientPin()
#clientprotocol1.setpin("123456")
#user="john"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#response=hmacSecret.makecredential(hashchallenge,RP_domain,user)
#authdata= getAsseration.extract_authdata(response)
#credential_info = getAsseration.parse_authdata(authdata)
#clientDataHash= util.sha256(os.urandom(32) )
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.getAsseration("123456",  RP_domain, credential_info["credentialId"])
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.supporingSalt1and2("123456",  RP_domain, credential_info["credentialId"])
#hmacSecret.randomHMAC("123456", RP_domain,user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.hmaconesalt("123456", RP_domain,user,credential_info["credentialId"])
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.hmaconesaltandsalt2("123456", RP_domain,user,credential_info["credentialId"])

##############    HMAC Secret - Strict PUAT2 ######################
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#hmacSecret2.authenticatorClientPin()
#user="johnwick"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#response =hmacSecret2.makecredential(hashchallenge, RP_domain, user)
#authdata= getAsseration.extract_authdata(response)
#credential_info = getAsseration.parse_authdata(authdata)
#clientDataHash= util.sha256(os.urandom(32) )
#hmacSecret2.getAsseration("123456",RP_domain,credential_info["credentialId"])
#hmacSecret2.hmacsalt1andsal2("123456",RP_domain,credential_info["credentialId"])
#hmacSecret2.randomHMAC("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret2.salt_length_insufficient("123456",RP_domain,credential_info["credentialId"])
#hmacSecret2.salt_length_insufficient1("123456",RP_domain,credential_info["credentialId"])

##############    CredProtect ######################
#import credProtect
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#setpin.clientPinSet("123456")
#user="johnwick"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#credProtect.makecredential("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="bobsmith"
#hashchallenge = os.urandom(32);
#RP_domain="google.com"
#credProtect.testUVOptionalWithCredProtectAndAssertionFlows("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="stephen"
#hashchallenge = os.urandom(32);
#RP_domain="entra.com"
#credProtect.testCredProtectUVRequiredWithAssertionErrors("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="alice"
#hashchallenge = os.urandom(32);
#RP_domain="example.com"
#credProtect. verify_cred_protect_level_with_credential_management("123456",hashchallenge, RP_domain, user)
##############   CredBlob ######################
#import credBlob
#util.ResetCardPower()
#util.ConnectJavaCard()
#hmacSecret.cardReset()
#setpin.clientPinSet("123456")
#credBlob.maxCredBlobLength("123456")
#user="stephen"
#hashchallenge = os.urandom(32);
#RP_domain="entra.com"
#credBlob.test_credblob_extension("123456",hashchallenge, RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#user="bobsmith"
#hashchallenge = os.urandom(32);
#RP_domain="google.com"
#credBlob.test_credblob_extension_empty_return("123456",hashchallenge, RP_domain, user)

########### Large Blob Key***************
# import largeBlobkey
#RP_domain="google.com"
#user="bobsmith"
#credId=largeBlobkey.largeBlobKey("123456", RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#largeBlobkey.largeBlobKeyGetasseration("123456", RP_domain, credId)
#util.ResetCardPower()
#util.ConnectJavaCard()
#largeBlobkey.test_blobkey_invalid("123456", RP_domain, user)
#largeBlobkey.test_blobkey_notset("123456", RP_domain, user)
#util.ResetCardPower()
#util.ConnectJavaCard()
#largeBlobkey.get_assertion_invalid_largeblobkey("123456", RP_domain, credId)
#largeBlobkey.get_assertion_random("123456", RP_domain, credId)



######################### testingdata#######################
# import credBlob
#hmacSecret.cardReset()
#setpin.clientPinSet("123456")
#user="stephen"
#hashchallenge = os.urandom(32);
#RP_domain="entra.com"
#credBlob.test_credblob_extension1("123456",hashchallenge, RP_domain, user)

   