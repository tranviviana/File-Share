package client

// CS 161 Project 2
import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

/*------------ Struct Section -------------*/
type User struct {
	username          []byte //marshaled version
	hashedPasswordKDF []byte //marshaled version protected
	PrivateRsaKey     []byte //private key type marshaled --> encrypted --> maced
	SignatureKey      []byte //private key type marshaled --> encrypted --> maced
}
type Invitation struct {
	//this struct is DELETED after accept invitation
	CommsKey     []byte //key Argon2key(filename,owner,direct recipient) for the communications channel --> marshaled --> RSA Encrypted --> Rsa Signed
	CommsChannel []byte //UUID of the commschannel RSA encrypted and signed
}
type CommunicationsChannel struct {
	FileKey    []byte //randomly generated key which will change in revocation
	FileStruct []byte //randomly generated UUID which will change in revocation
	SharedWith []byte //generated random bytes
}
type Accepted struct {
	CommsKey     []byte //User Choice of encryption but rederivable
	CommsChannel []byte //User choice of encryption but rederivable
}
type File struct {
	FileLength       []byte //uint --> marshal --> enc with File key hashKDF filelength
	FileContentFront []byte //uuid of the front filecontent struct --> marshal --> enc with File key hashKDF filecontentFront
}
type FileContent struct {
	BlockEncrypted []byte //string --> marshal --> enc with file key hashkdf UUID + current block
}

/* ----------- END Struct Section -----------*/
/*------------ Helper Functions -------------*/
/***------------------------------------------------------ General Helper Functions ------------------------------***/
func ConstructKey(hardCodedText string, errorMessage string, protectedKey []byte) (key []byte, err error) {
	//hash the hardcoded text with protected key then slice to get size 16
	byteHardCodedText, err := json.Marshal(hardCodedText)
	if err != nil {
		return nil, errors.New(errorMessage + "specifically marshalling")
	}
	wholeKey, err := userlib.HashKDF(protectedKey, byteHardCodedText)
	key = wholeKey[0:16]
	if err != nil {
		return nil, errors.New(errorMessage)
	}
	return key, nil
}
func EncThenMac(encryptionKey []byte, macKey []byte, objectHidden []byte) (macEncryptedObject []byte, err error) {
	//pass in the MARSHALED objects get back an encrypted and mac object

	IV := userlib.RandomBytes(16)
	//MAC(ENC(RSAprivateKey))
	//convert to byte
	encryptedObject := userlib.SymEnc(encryptionKey, IV, objectHidden)
	tagEncryptedObject, err := userlib.HMACEval(macKey, encryptedObject)
	if err != nil {
		return nil, errors.New("could not generate MAC tag over hidden object")
	}
	//full encrypted and mac tagged RSA private key
	macEncryptedObject = append(tagEncryptedObject, encryptedObject...)
	return macEncryptedObject, nil
}
func CheckMac(protectedObject []byte, macKey []byte) (ok bool, err error) {
	//ensures integrity by checking the mac tag at the front of the protected object
	//check the size of inputs
	if len(protectedObject) < 64 {
		return false, errors.New("protected object is too small")
	}
	if len(macKey) < 16 {
		return false, errors.New("macKey is too small")
	}
	//slice the protected object in the mac tag and encrypted object
	macTag := protectedObject[:64]
	encryptedObject := protectedObject[64:]
	//ensure against corruption
	possiblyCorruptedTag, err := userlib.HMACEval(macKey, encryptedObject)
	if err != nil {
		return false, errors.New("could not reconstruct the mac tag in checking the mac")
	}
	ok = userlib.HMACEqual(macTag, possiblyCorruptedTag)
	if !ok {
		return false, errors.New("INTEGRITY ERROR")
	}
	return ok, nil

func Decrypt(protectedObject []byte, decryptionKey []byte) (decryptedObject []byte, err error) {
	//decrypts the object using the key
	//check length minimum
	encryptedObject := protectedObject[64:]
	if len(encryptedObject) < userlib.AESBlockSizeBytes {
		return nil, errors.New("object length is too short to decrypt")
	}
	//use symmetric decryption on slice of protected object without the mac beginning
	decryptedObject = userlib.SymDec(decryptionKey, encryptedObject)
	return decryptedObject, nil
}
func CheckAndDecrypt(protectedObject []byte, macKey []byte, decryptionKey []byte) (decryptedObject []byte, err error) {
	//checks integrity and decrypts the object with the key
	ok, err := CheckMac(protectedObject, macKey)
	if !ok {
		return nil, err
	}
	decryptedObject, err = Decrypt(protectedObject, decryptionKey)
	if err != nil {
		return nil, err
	}
	return decryptedObject, nil
}
func RestoreRSAPublic(username string) (PkeyOnKeystore string, publicKey userlib.PublicKeyType, err error) {
	//returns the user's RSA key value pair in key store
	//marshal the username and hashkdf inut text
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not marshal username")
	}
	hardCodedText, err := json.Marshal("KeyStore RSA public key")
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not marshal hard coded text for RSA")
	}
	keyStoreKeyBytes, err := userlib.HashKDF(hardCodedText[:16], byteUsername)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not hash username")
	}
	jsonKeyStoreBytes, err := json.Marshal(keyStoreKeyBytes)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not marshal keyStoreByte to a json readable")
	}
	var keyStoreKey string
	err = json.Unmarshal(jsonKeyStoreBytes, &keyStoreKey)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not unmarshal to convert bytes to a string")
	}
	//find unique hash corresponding RSA key value pair
	RSAPublicKey, ok := userlib.KeystoreGet(keyStoreKey)
	if !ok {
		return "", userlib.PublicKeyType{}, errors.New("no RSA Public key found for username")
	}
	return keyStoreKey, RSAPublicKey, nil
}
func RestoreVERIFICATIONPublic(username string) (VkeyOnKeystore string, verificationKey userlib.PublicKeyType, err error) {
	//returns key value pair of user's public verification key
	//marshal the username and hashkdf input text
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not marshal username")
	}
	hardCodedText, err := json.Marshal("KeyStore Signature and Verification")
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not marshal hard coded text for Signature and Verification")
	}
	tempKeyStoreBytes, err := userlib.HashKDF(hardCodedText[:16], byteUsername)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not hashKDF once for Signature and Verification")
	}
	//hash again for the verification key
	keyStoreKeyBytes, err := userlib.HashKDF(tempKeyStoreBytes[:16], byteUsername)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not hashKDF twice for Signature and Verification")
	}
	//marshal and unmarshal the double hashed user
	jsonKeyStoreKey, err := json.Marshal(keyStoreKeyBytes)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not marshal keyStoreByte to a json readable")
	}
	var keyStoreKey string
	err = json.Unmarshal(jsonKeyStoreKey, &keyStoreKey)
	if err != nil {
		return "", userlib.PublicKeyType{}, errors.New("could not unmarshal to convert bytes to a string")
	}
	//find its corresponding unique verification key in keystore
	verificationKey, ok := userlib.KeystoreGet(keyStoreKey)
	if !ok {
		return "", userlib.PublicKeyType{}, errors.New("no verification key found for username")
	}
	return keyStoreKey, verificationKey, nil
}

/***------------------------------------------------------ END General Helper Functions ------------------------------***/
/***------------------------------------------------------INIT and GETUSER Helper Functions ------------------------------***/
func MakeRSAKey(byteUsername []byte, hashedPassword []byte) (publicKey userlib.PublicKeyType, protectedPrivateKey []byte, err error) {
	//make the RSA key for user
	//marshal text to hash username
	hardCodedText, err := json.Marshal("KeyStore RSA public key")
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not marshal hard coded text for RSA")
	}
	keyStoreKeyBytes, err := userlib.HashKDF(hardCodedText[:16], byteUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not hashKDf hard coded text for RSA")
	}
	jsonKeyStoreBytes, err := json.Marshal(keyStoreKeyBytes)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not marshal keyStoreByte to a json readable")
	}
	//unmarshal hashed key
	var keyStoreKey string
	err = json.Unmarshal(jsonKeyStoreBytes, &keyStoreKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not unmarshal to convert bytes to a string")
	}
	//create random public and private key to add to keystore
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not generate unique RSA keys")
	}
	bytePrivateKey, err := json.Marshal(privateKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not convert private key type to byte type")
	}
	err = userlib.KeystoreSet(keyStoreKey, publicKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not set the RSA public key")
	}
	//encrypt and mac the private key to put in user struct
	privateKeyEncryption, err := ConstructKey("rsa private key encryption", "could not create encryption key for RSA private key", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, err
	}
	privateKeyMac, err := ConstructKey("rsa private key MAC", "could not create mac key for RSA private key", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, err
	}
	protectedPrivateKey, err = EncThenMac(privateKeyEncryption, privateKeyMac, bytePrivateKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, err
	}
	return publicKey, protectedPrivateKey, nil
}
func MakeSignatureKey(byteUsername []byte, hashedPassword []byte) (verification userlib.PublicKeyType, signingKey []byte, err error) {
	//make signature key for user and add to keystore
	//marshal input to hash the username twice
	hardCodedText, err := json.Marshal("KeyStore Signature and Verification")
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not marshal hard coded text for Signature and Verification")
	}
	tempKeyStoreBytes, err := userlib.HashKDF(hardCodedText[:16], byteUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not hashKDF once for Signature and Verification")
	}
	keyStoreKeyBytes, err := userlib.HashKDF(tempKeyStoreBytes[:16], byteUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not hashKDF twice for Signature and Verification")
	}
	jsonKeyStoreKeyByte, err := json.Marshal(keyStoreKeyBytes)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not marshal keyStoreByte to a json readable")
	}
	//unmarshal double hashed username to create signaute and verification key
	var keyStoreKey string
	err = json.Unmarshal(jsonKeyStoreKeyByte, &keyStoreKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not unmarshal to convert bytes to a string")
	}
	signatureKey, verificationKey, err := userlib.DSKeyGen()
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not generate unique Signature and Verification keys")
	}
	byteSignatureKey, err := json.Marshal(signatureKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not convert signature key type to byte type")
	}
	//add the key value pair to keystore
	err = userlib.KeystoreSet(keyStoreKey, verificationKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not set the Signature and Verification public key")
	}
	//encrypt and mac the Signature private key using Hashkdf and the hashed Password to put in user struct
	signatureKeyEncryption, err := ConstructKey("signature key encryption", "could not create encryption key for Signature and Verification key", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, err
	}
	signatureKeyMac, err := ConstructKey("signature key MAC", "could not create mac key for Signature and Verification key", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, err
	}
	protectSignatureKey, err := EncThenMac(signatureKeyEncryption, signatureKeyMac, byteSignatureKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, err
	}
	return verificationKey, protectSignatureKey, nil
}
func CheckUserExistenceByte(byteUsername []byte) (exist bool, err error) {
	//check the user exists in keystore using username in bytes
	var stringUsername string
	err = json.Unmarshal(byteUsername, &stringUsername)
	if err != nil {
		return false, errors.New("could not unmarshal to convert bytes to string")
	}
	return CheckUserExistenceString(stringUsername)
}
func CheckUserExistenceString(username string) (exist bool, err error) {
	//check the user exists in keystore using username in string
	//checks if the user has an RSA Key in keystore
	_, _, err = RestoreRSAPublic(username)
	if err != nil {
		return false, err
	}
	//checks if the user has a signature in keystore
	_, _, err = RestoreVERIFICATIONPublic(username)
	if err != nil {
		return false, err
	}
	//user exists if it has keys in keystore
	return true, nil
}
func ReconstructInitialize(usernameInput string, password string) (createdUUID uuid.UUID, hashedPassword []byte, username []byte, err error) {
	//gets uuid, hashed password, and hashed username from string username & password
	//marshal username, password, and text
	byteUsername, err := json.Marshal(usernameInput)
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not marshal the username")
	}
	bytePassword, err := json.Marshal(password)
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not marshal the password")
	}
	hardCodedText, err := json.Marshal("hard-coded text for usernameUUID generation")
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not marshal the hardcoded text")
	}
	//creates hashed password and uuid from marshaled input
	hashedPasswordKDF := userlib.Argon2Key(bytePassword, byteUsername, 16)
	passwordHashedForUUID, err := userlib.HashKDF(hashedPasswordKDF, hardCodedText)
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not hashKDF our password")
	}
	userUUID, err := uuid.FromBytes(passwordHashedForUUID[:16])
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not create the userUUID")
	}
	return userUUID, hashedPasswordKDF, byteUsername, nil
}

/***------------------------------------------------------END INIT and GETUSER Helper Functions ------------------------------***/
/***------------------------------------------------------General Store, Load, Append File ------------------------------***/
func GetKeyFileName(filename string, hashedPasswordKDF []byte, username []byte) (cCAprotectedKey []byte, protectedFilename []byte, err error) {
	//returns the basis key that the communications struct and a struct should be encrypted wtih
	byteFilename, err := json.Marshal(filename)
	if err != nil {
		return nil, nil, errors.New("could not marshal filename")
	}
	byteHardCodedText, err := json.Marshal("cc or a hard-coded text")
	if err != nil {
		return nil, nil, errors.New("could not marshal hard coded text")
	}
	//hash kdf the password for more "security"
	cCApasswordKey, err := userlib.HashKDF(hashedPasswordKDF, byteHardCodedText)
	if err != nil {
		return nil, nil, errors.New("could not hash kdf the filename")
	}
	cCAByteKey := append(byteFilename, cCApasswordKey...)
	cCAByteKey = append(cCAByteKey, username...)
	cCAprotectedKey = userlib.Argon2Key(cCAByteKey, username, 16) // hashKDF

	filenameEncryptionKey, err := ConstructKey("my filename encryption key", "could not create an encryption key for filename", cCAprotectedKey)
	if err != nil {
		return nil, nil, err
	}
	filenameMacKey, err := ConstructKey("my filename mac key", "could not create a mac key for filename", cCAprotectedKey)
	if err != nil {
		return nil, nil, err
	}
	protectedFilename, err = EncThenMac(filenameEncryptionKey, filenameMacKey, byteHardCodedText)
	if err != nil {
		return nil, nil, err
	}
	return cCAprotectedKey, protectedFilename, nil

}

/***------------------------------------------------------Step One to Getting a File------------------------------***/
func RegenerateUUIDCCA(cCAprotectedKey []byte) (CCAuuid uuid.UUID, err error) {
	//first step that a person reaches rwhen storing/loading/ or appending to a file
	//get the uuid of the communication channel OR acceptance struct depending on if owner OR sharer respectively -- from a protected argon2key
	//hash the protected key
	hardCodedText, err := json.Marshal("UUID key to hash with protected key for cc and a struct")
	if err != nil {
		return uuid.Nil, errors.New("could not marshal text")
	}
	ccaUUIDkey, err := userlib.HashKDF(cCAprotectedKey, hardCodedText[:16])
	if err != nil {
		return uuid.Nil, errors.New("could not hashkdf the protected key for CC or A structs")
	}
	//get communications channel OR acceptance uuid
	CCAuuid, err = uuid.FromBytes(ccaUUIDkey[:16])
	if err != nil {
		return uuid.Nil, errors.New("could not convert ccaUUIDkey to accessible uuid")
	}
	return CCAuuid, nil
}

func GetCCorA(CCAuuid uuid.UUID) (protectedCCA []byte, exists bool) {
	protectedCCA, ok := userlib.DatastoreGet(CCAuuid)
	if !ok {
		return nil, false
	}
	return protectedCCA, true
}

func IsCC(protectedCCA []byte, cCAprotectedKey []byte) (owner bool, err error) {
	//BE CAREFUL USING THIS ONE
	//protectedCCA to minimize calls to datastorre
	cCaEncryptionKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", cCAprotectedKey)
	if err != nil {
		return false, err
	}
	cCaMacKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", cCAprotectedKey)
	if err != nil {
		return false, err
	}
	ByteCCAAddress, err := CheckAndDecrypt(protectedCCA, cCaMacKey, cCaEncryptionKey)
	if err != nil {
		return false, err
	}
	var CCAddress CommunicationsChannel
	err = json.Unmarshal(ByteCCAAddress, &CCAddress)
	if err != nil {
		var AAddress Accepted
		err = json.Unmarshal(ByteCCAAddress, &AAddress)
		if err != nil {
			return false, errors.New("could not unmarshal CommunicationsChannel and Acceptance struct")
		}
		return false, nil
	}
	return true, nil
}

/*-----------------OWNER's Edition: Protecting and Restoring CC channel----------------------*/

func ProtectOwnerCC(cCAprotectedKey []byte) (protectedOwnerCCStruct []byte, err error) {
	//called in the initial stored file and when you revoke so that the communications channel of the owner is updated and stored in datasotre with the proper information
	var ownerCC CommunicationsChannel
	protectedShareWith, err := ProtectFileSharedWith(cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	protectedFileKey, err := ProtectFileKey(cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	protectedFileUUID, err := ProtectFileUUID(cCAprotectedKey)
	if err != nil {
		return nil, err
	}

	ownerCC.FileKey = protectedFileKey
	ownerCC.FileStruct = protectedFileUUID
	ownerCC.SharedWith = protectedShareWith

	bytesOwnerCC, err := json.Marshal(ownerCC)
	if err != nil {
		return nil, errors.New("could not marshal the owner's communication node")
	}
	encryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	macCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", cCAprotectedKey)
	if err != nil {
		return nil, err
	}

	protectedOwnerCC, err := EncThenMac(encryptionCCStructKey, macCCStructKey, bytesOwnerCC)
	if err != nil {
		return nil, err
	}
	return protectedOwnerCC, nil
}

/*------Helper functions for Protect Owner CC ------*/
func ProtectFileKey(cCAprotectedKey []byte) (protectedFileKey []byte, err error) {
	// in owners communication channel
	fileSourceKey := userlib.RandomBytes(128)
	fileSalt := userlib.RandomBytes(128)
	fileKey := userlib.Argon2Key(fileSourceKey, fileSalt, 16)
	encryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	protectedFileKey, err = EncThenMac(encryptionFileKey, macFileKey, fileKey)
	if err != nil {
		return nil, err
	}
	return protectedFileKey, nil
}
func ProtectFileUUID(cCAprotectedKey []byte) (protectedFileUUID []byte, err error) {
	// in owners communication channel
	randomUUID := uuid.New()
	byteRandomUUID, err := json.Marshal(randomUUID)
	if err != nil {
		return nil, errors.New("could not marshal random UUID to hide file")
	}
	encryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	protectedFileUUID, err = EncThenMac(encryptionFileUUID, macFileUUID, byteRandomUUID)
	if err != nil {
		return nil, err
	}
	return protectedFileUUID, nil
}

func ProtectFileSharedWith(cCAprotectedKey []byte) (protectedSharedWith []byte, err error) {
	sharedWith := userlib.RandomBytes(16)
	encryptionSharedWith, err := ConstructKey("encryption key for list of people file was shared with", "could not create sharedWith encryption", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	macSharedWith, err := ConstructKey("mac key for list of people file was shared with", "could not create sharedWith mac", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	protectedSharedWith, err = EncThenMac(encryptionSharedWith, macSharedWith, sharedWith)
	if err != nil {
		return nil, err
	}
	return protectedSharedWith, nil
}

/*-----END Helper functions for Protect Owner CC ------*/
func RecoverOwnerCCContents(protectedOwnerCC []byte, cCAprotectedKey []byte) (fileKey []byte, fileUUID uuid.UUID, sharedWith []byte, err error) {
	testDecryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", cCAprotectedKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	TestMacCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", cCAprotectedKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	ccPtr, err := RegenerateCC(protectedOwnerCC, TestMacCCStructKey, testDecryptionCCStructKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	sharedWith, err = RecoverSharedWith(ccPtr.SharedWith, cCAprotectedKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	fileKey, err = RecoverFileKey(ccPtr.FileKey, cCAprotectedKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	fileUUID, err = RecoverFileUUID(ccPtr.FileStruct, cCAprotectedKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	return fileKey, fileUUID, sharedWith, nil
}

/*--------Helper functions for Restore Owner CC  ------------- */
func RegenerateCC(protectedCC []byte, CCMacKey []byte, CCDecryptKey []byte) (ccPtr *CommunicationsChannel, err error) {
	byteCC, err := CheckAndDecrypt(protectedCC, CCMacKey, CCDecryptKey)
	if err != nil {
		return nil, err
	}
	var CC *CommunicationsChannel
	err = json.Unmarshal(byteCC, &CC)
	if err != nil {
		return nil, errors.New("could not unmarshal communications channel")
	}
	return CC, nil
}

func RecoverSharedWith(protectedSharedWith []byte, cCAprotectedKey []byte) (sharedWith []byte, err error) {
	decryptionShareWith, err := ConstructKey("encryption key for list of people file was shared with", "could not create sharedWith encryption", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	macSharedWith, err := ConstructKey("mac key for list of people file was shared with", "could not create sharedWith mac", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	sharedWith, err = CheckAndDecrypt(protectedSharedWith, macSharedWith, decryptionShareWith)
	if err != nil {
		return nil, err
	}
	return sharedWith, nil
}

func RecoverFileKey(protectedFileKey []byte, cCAprotectedKey []byte) (fileKey []byte, err error) {
	// recover the file key for the owners communication channel
	testEncryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	testMacFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", cCAprotectedKey)
	if err != nil {
		return nil, err
	}
	fileKey, err = CheckAndDecrypt(protectedFileKey, testMacFileKey, testEncryptionFileKey)
	if err != nil {
		return nil, err
	}
	return fileKey, nil
}
func RecoverFileUUID(protectedFileUUID []byte, cCAprotectedKey []byte) (fileUUID uuid.UUID, err error) {
	// recover the file uuid for the owners communication channel
	testEncryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", cCAprotectedKey)
	if err != nil {
		return uuid.Nil, err
	}
	testMacFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", cCAprotectedKey)
	if err != nil {
		return uuid.Nil, err
	}
	byteFileUUID, err := CheckAndDecrypt(protectedFileUUID, testMacFileUUID, testEncryptionFileUUID)
	if err != nil {
		return uuid.Nil, err
	}
	var tempfileUUID uuid.UUID
	err = json.Unmarshal(byteFileUUID, &tempfileUUID)
	if err != nil {
		return uuid.Nil, errors.New("could not unmarshal file uuid")
	}
	fileUUID = tempfileUUID
	return fileUUID, nil
}

/*-------- END Helper functions for Restore Owner CC ------------- */
/*-----------------END OWNER's Edition: Protecting and Restoring CC channel----------------------*/

/*-----------------ACTIVE RECIPIENT Edition: Protecting and Restoring CC channel----------------------*/
//Used after accepting invitation to create an accepted struct that points to the same comms channel as its parent
func ProtectAccepted(protectedAcceptedKey []byte, locationAcceptedStruct uuid.UUID, commsKey []byte, commsChannel uuid.UUID) (err error) {
	//create an accepted struct
	var accepted Accepted
	//use the helper function to fill the struct
	accepted.CommsChannel, err = ProtectCommsChannel(protectedAcceptedKey, commsChannel)
	if err != nil {
		return err
	}
	accepted.CommsKey, err = ProtectCommsKey(protectedAcceptedKey, commsKey)
	if err != nil {
		return err
	}
	// encrypt the struct
	acceptedStruct, err := json.Marshal(accepted)
	if err != nil {
		return errors.New("could not marshal the Accepted struct")
	}
	encryptionAcceptedStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return err
	}
	macAcceptedStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return err
	}
	protectedAcceptedStruct, err := EncThenMac(encryptionAcceptedStruct, macAcceptedStruct, acceptedStruct)
	if err != nil {
		return err
	}
	// put it at the uuid location passed in
	userlib.DatastoreSet(locationAcceptedStruct, protectedAcceptedStruct)
	return nil
}

/*----Helper Functions for Protect Accepted -----*/
func ProtectCommsChannel(protectedAcceptedKey []byte, commsChannel uuid.UUID) (protectedCommsChannel []byte, err error) {
	//inputs protectedAcceptedKey === from another step (technically same as argon2key of communications channel)
	byteCommsChannel, err := json.Marshal(commsChannel)
	if err != nil {
		return nil, errors.New("could not marshal commsChannel uuid")
	}
	encryptionCommsChannelKey, err := ConstructKey("encryption for CommsChannel in Accepted struct", "could not create encryption key for CommsChannel in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	macCommsChannelKey, err := ConstructKey("mac for CommsChannel in Accepted struct", "could not create mac key for CommsChannel in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	protectedCommsChannel, err = EncThenMac(encryptionCommsChannelKey, macCommsChannelKey, byteCommsChannel)
	if err != nil {
		return nil, err
	}
	return protectedCommsChannel, nil
}
func ProtectCommsKey(protectedAcceptedKey []byte, commsKey []byte) (protectedCommsKey []byte, err error) {
	encryptionCommsKey, err := ConstructKey("encryption for CommsKey in Accepted struct", "could not create encryption key for CommsKey in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	macCommsKey, err := ConstructKey("mac for CommsKey in Accepted struct", "could not create mac key for CommsKey in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	protectedCommsKey, err = EncThenMac(encryptionCommsKey, macCommsKey, commsKey)
	if err != nil {
		return nil, err
	}
	return protectedCommsKey, nil
}

/*----End Helper Functions for Protect Accepted -----*/

func RecoverAcceptedStructContents(protectedA []byte, protectedAcceptedKey []byte) (commsKey []byte, commsChannel uuid.UUID, err error) {
	decryptionAcceptedStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macAcceptedStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	byteAcceptedStruct, err := CheckAndDecrypt(protectedA, macAcceptedStruct, decryptionAcceptedStruct)
	if err != nil {
		return nil, uuid.Nil, err
	}
	var acceptedStruct Accepted
	err = json.Unmarshal(byteAcceptedStruct, &acceptedStruct)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not unmarshal the Accepted struct")
	}
	protectedCommsChannel := acceptedStruct.CommsChannel
	protectedCommsKey := acceptedStruct.CommsKey

	commsChannel, err = RecoverCommsChannel(protectedCommsChannel, protectedA)
	if err != nil {
		return nil, uuid.Nil, err
	}
	commsKey, err = RecoverCommsKey(protectedCommsKey, protectedA)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return commsKey, commsChannel, nil
}

/*----Helper Functions for RecoverAcceptStructContents-----*/
func RecoverCommsChannel(protectedCommsChannel []byte, protectedA []byte) (commsChannel uuid.UUID, err error) {
	decryptionCommsChannel, err := ConstructKey("encryption for CommsChannel in Accepted struct", "could not create encryption key for CommsChannel in Accepted struct", protectedA)
	if err != nil {
		return uuid.Nil, err
	}
	macCommsChannel, err := ConstructKey("mac for CommsChannel in Accepted struct", "could not create mac key for CommsChannel in Accepted struct", protectedA)
	if err != nil {
		return uuid.Nil, err
	}
	byteCommsChannel, err := CheckAndDecrypt(protectedCommsChannel, macCommsChannel, decryptionCommsChannel)
	if err != nil {
		return uuid.Nil, err
	}

	err = json.Unmarshal(byteCommsChannel, &commsChannel)
	if err != nil {
		return uuid.Nil, errors.New("could not unmarshal commschannel")
	}
	return commsChannel, nil
}
func RecoverCommsKey(protectedCommsKey []byte, protectedA []byte) (commsKey []byte, err error) {
	decryptionCommsKey, err := ConstructKey("encryption for CommsKey in Accepted struct", "could not create encryption key for CommsKey in Accepted struct", protectedA)
	if err != nil {
		return nil, err
	}
	macCommsKey, err := ConstructKey("mac for CommsKey in Accepted struct", "could not create mac key for CommsKey in Accepted struct", protectedA)
	if err != nil {
		return nil, err
	}
	byteCommsKey, err := CheckAndDecrypt(protectedCommsKey, macCommsKey, decryptionCommsKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(byteCommsKey, &commsKey)
	if err != nil {
		return nil, errors.New("could not unmarshal commschannel")
	}
	return commsKey, nil
}

/*----END Helper Functions for RecoverAcceptStructContents-----*/
/***------------------------------------------------------Step Two (for Active Recipients) In getting a file; Owner Creates Communication Nodes------------------------------***/
/*
type CommunicationsChannel struct {
	FileKey    []byte //randomly generated key which will change in revocation
	FileStruct []byte //randomly generated UUID which will change in revocation
	SharedWith []byte //random bytes recipients Username and argon2Key
}
	//essentially the owner copies their communications struct into generated nodes
*/
func generateRecCCKey(recipientsUsername string, ownerUsername string, filename string, sharedWith []byte) (protectedRecKey []byte, recCCUUID uuid.UUID, err error) {
	//recipient communicationschannel key owner is creating this file
	//marshal owner & recipient & filename
	byteRecipientUsername, err := json.Marshal(recipientsUsername)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal recipient's username")
	}
	byteOwnerUsername, err := json.Marshal(ownerUsername)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal owner's username")
	}
	byteFileName, err := json.Marshal(filename)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal filename")
	}
	//argon2key on owner, recipient, & filename
	byteCompilation := append(byteOwnerUsername, byteRecipientUsername...)
	byteCompilation = append(byteCompilation, byteFileName...)
	protectedRecKey = userlib.Argon2Key(byteCompilation, sharedWith, 16)
	//
	byteHardCoded, err := json.Marshal("UUID for recipients")
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal uuid for recipient")
	}
	recCCUUIDByte, err := userlib.HashKDF(protectedRecKey, byteHardCoded)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not hash uuid bytes for recipient")
	}
	recCCUUID, err = uuid.FromBytes(recCCUUIDByte[:16])
	if err != nil {
		return nil, uuid.Nil, errors.New("could not generate uuid from bytes")
	}
	return protectedRecKey, recCCUUID, nil // sent in invitation pointer use uuid in the revoke section
}
func copiedCC(protectedRecKey []byte, ownerCommunications *CommunicationsChannel) (protectedRecipientCC []byte, err error) {
	//get the items from the owner's CC
	//encrypt the items from the owners CC using the protected Rec key
	// create a new Communications node
	//fill those encrypted items into that NEW comunications node besides shared with item
	//marshal and encrypt
	//return the protected communication node meant for the recipient
	ownerCommunnic
}

//when owner creates an invitation theyll create a copied CC and data store set the uuid of generate RECcckey
//the invitation struct will be RSA encrypted, inside will be the UUID ^^ and the key to decrypt it

//when child creates an invitation to a grandchild theyll create a invitation struct with the communications struct information
// RSA encrypt the struct and the key

/***------------------------------------------------------ENDStep Two (for Active Recipients) In getting a file; Owner Creates Communication Nodes------------------------------***/
/*-----------------ACTIVE RECIPIENT Edition: Protecting and Restoring CC channel----------------------*/
/***------------------------------------------------------Step Two (for Owner) and Step Three (for active recipients) to Getting a File------------------------------***/

func ProtectFile(protectedFileKey []byte, content []byte) (protectedFileStruct []byte, err error) {
	//protectedFileKey is from the communications channel
	var fileStruct File
	protectedFileLength, err := ProtectFileLength(protectedFileKey, len(content))
	if err != nil {
		return nil, err
	}
	protectedContentUUID, err := ProtectedFrontPtr(protectedFileKey)
	if err != nil {
		return nil, err
	}
	fileStruct.FileContentFront = protectedContentUUID
	fileStruct.FileLength = protectedFileLength

	byteFileStruct, err := json.Marshal(fileStruct)
	if err != nil {
		return nil, errors.New("could not marshal the file struct accessible to everyone")
	}
	encryptionFileStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the file struct accessible to everyone", protectedFileKey)
	if err != nil {
		return nil, err
	}
	macFileStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the file struct accessible to everyone", protectedFileKey)
	if err != nil {
		return nil, err
	}
	protectedFileStruct, err = EncThenMac(encryptionFileStruct, macFileStruct, byteFileStruct)
	if err != nil {
		return nil, err
	}
	return protectedFileStruct, nil
}

/*-------Helper Functions for Protect File ----------*/
func ProtectFileLength(protectedFileKey []byte, fileLength int) (protectedFileLength []byte, err error) {
	byteFileLength, err := json.Marshal(fileLength)
	if err != nil {
		return nil, errors.New("could not marshal the file length to protect the file length")
	}
	encryptionFileLength, err := ConstructKey("encryption key for the file length", "could not create encryption key for the file length", protectedFileKey)
	if err != nil {
		return nil, err
	}
	macFileLength, err := ConstructKey("mac Key for the file length", "could not create mac key for the file length", protectedFileKey)
	if err != nil {
		return nil, err
	}
	protectedFileLength, err = EncThenMac(encryptionFileLength, macFileLength, byteFileLength)
	if err != nil {
		return nil, err
	}
	return protectedFileLength, nil
}
func ProtectedFrontPtr(protectedFileKey []byte) (protectedContentUUID []byte, err error) {
	randomUUID := uuid.New()
	byteRandomUUID, err := json.Marshal(randomUUID)
	if err != nil {
		return nil, errors.New("could not marshal the content point uuid")
	}
	encryptionContentPtr, err := ConstructKey("encryption for content pointer start", "could not create an encryption key for the content pointer", protectedFileKey)
	if err != nil {
		return nil, err
	}
	macContentPtr, err := ConstructKey("Mac key for content pointer start", "could not create a mac key for the content pointer", protectedFileKey)
	if err != nil {
		return nil, err
	}
	protectedContentUUID, err = EncThenMac(encryptionContentPtr, macContentPtr, byteRandomUUID)
	if err != nil {
		return nil, err
	}
	return protectedContentUUID, nil

}

/*------- END Helper Functions for Protect File ----------*/
func RecoverFileContents(protectedFileStruct []byte, protectedFileKey []byte) (frontPtr uuid.UUID, fileLength int, err error) {
	//protected fileKey will be found in the communications node if they are the owner AND if they are not the owner
	decryptionFileStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the file struct accessible to everyone", protectedFileKey)
	if err != nil {
		return uuid.Nil, 0, err
	}
	macFileStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the file struct accessible to everyone", protectedFileKey)
	if err != nil {
		return uuid.Nil, 0, err
	}
	byteFileStruct, err := CheckAndDecrypt(protectedFileStruct, macFileStruct, decryptionFileStruct)
	if err != nil {
		return uuid.Nil, 0, err
	}
	var tempFileStruct File
	err = json.Unmarshal(byteFileStruct, &tempFileStruct)
	if err != nil {
		return uuid.Nil, 0, errors.New("could not unmarshal the file struct")
	}
	protectedFileContentPtr := tempFileStruct.FileContentFront
	protectedFileLength := tempFileStruct.FileLength

	frontPtr, err = RecoverFileUUID(protectedFileContentPtr, protectedFileKey)
	if err != nil {
		return uuid.Nil, 0, err
	}
	fileLength, err = RecoverFileLength(protectedFileLength, protectedFileKey)
	if err != nil {
		return uuid.Nil, 0, err
	}
	return frontPtr, fileLength, nil
}

/*-----Helper Functions for RecoverFileContents ---------- */
func RecoverFileLength(protectedFileLength []byte, protectedFileKey []byte) (fileLength int, err error) {
	decryptionFileLength, err := ConstructKey("encryption key for the file length", "could not create encryption key for the file length", protectedFileKey)
	if err != nil {
		return 0, err
	}
	macFileLength, err := ConstructKey("mac Key for the file length", "could not create mac key for the file length", protectedFileKey)
	if err != nil {
		return 0, err
	}
	byteFileLength, err := CheckAndDecrypt(protectedFileLength, macFileLength, decryptionFileLength)
	if err != nil {
		return 0, err
	}
	var tempFileLength int
	err = json.Unmarshal(byteFileLength, &tempFileLength)
	if err != nil {
		return 0, errors.New("could not return the length of the file because of unmarshalling")
	}
	fileLength = tempFileLength
	return fileLength, nil
}
func RecoverFileContentUUID(protectedFileContentPtr []byte, protectedFileKey []byte) (fileUUID uuid.UUID, err error) {
	decryptionContentPtr, err := ConstructKey("encryption for content pointer start", "could not create an encryption key for the content pointer", protectedFileKey)
	if err != nil {
		return uuid.Nil, err
	}
	macContentPtr, err := ConstructKey("Mac key for content pointer start", "could not create a mac key for the content pointer", protectedFileKey)
	if err != nil {
		return uuid.Nil, err
	}
	byteFileUUID, err := CheckAndDecrypt(protectedFileContentPtr, macContentPtr, decryptionContentPtr)
	if err != nil {
		return uuid.Nil, err
	}
	var tempFileUUID uuid.UUID
	err = json.Unmarshal(byteFileUUID, &tempFileUUID)
	if err != nil {
		return uuid.Nil, errors.New("could not retreive file uuid because of unmarshalling")
	}
	fileUUID = tempFileUUID
	return fileUUID, nil
}

/*-----END Helper Functions for RecoverFileContents ---------- */
/***------------------------------------------------------END Step Two (for Owner) and Step Three (for active recipients) to Getting a File------------------------------***/
/*--------Helper Function to Fill File Content store file/ append --------*/
func generateNextUUID(contentStart uuid.UUID, blockNumber int64) (nextUUID uuid.UUID, err error) {
	//shouldn't matter what int data type as long as its 128 bits
	// block size of 64

	byteCurrentUUID, err := json.Marshal(contentStart)
	if err != nil {
		return uuid.Nil, errors.New("could not convert UUID to the byte UUID")
	}
	var intUUID int64
	err = json.Unmarshal(byteCurrentUUID, &intUUID)
	if err != nil {
		return uuid.Nil, errors.New("could not convert byte UUID to an int")
	}
	intUUID += blockNumber
	byteAddUUID, err := json.Marshal(intUUID)
	if err != nil {
		return uuid.Nil, errors.New("could not convert the uuid back to bytes")
	}
	var newUUID uuid.UUID
	err = json.Unmarshal(byteAddUUID, &newUUID)
	if err != nil {
		return uuid.Nil, errors.New("could not convert to uuid")
	}
	return newUUID, nil
}
func fileContentFilling(fileKey []byte, contentStart uuid.UUID, fileLength int, content []byte) (err error) {
	//64 block size
	tracker := 0
	currentUUID := contentStart
	var roundsEncryption int
	if fileLength%64 == 0 {
		roundsEncryption = fileLength / 64
	} else {
		roundsEncryption = (fileLength / 64) + 1
	}
	currentRound := 0
	for currentRound < roundsEncryption {
		var contentSplice []byte
		if (currentRound+1)*64 > fileLength {
			contentSplice = content[(currentRound * 64):]
		} else {
			contentSplice = content[(currentRound * 64) : (currentRound+1)*64]
		}
		var contentBlock FileContent
		hardCodedText := "content encryption salt" + strconv.Itoa(tracker)
		encryptionContentKey, err := ConstructKey(hardCodedText, "could not encrypt content block", fileKey)
		if err != nil {
			return err
		}
		hardCodedText = "content MAC salt" + strconv.Itoa(tracker)
		macContentKey, err := ConstructKey(hardCodedText, "could not MAC content block", fileKey)
		if err != nil {
			return err
		}
		protectedContent, err := EncThenMac(encryptionContentKey, macContentKey, contentSplice)
		if err != nil {
			return err
		}
		contentBlock.BlockEncrypted = protectedContent

		bytesContentBlock, err := json.Marshal(contentBlock)
		if err != nil {
			return errors.New("could not marshal content struct")
		}

		hardCodedText = "content struct encryption salt" + strconv.Itoa(tracker)
		encryptionContentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return err
		}
		hardCodedText = "content struct mac salt" + strconv.Itoa(tracker)
		macConstentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return err
		}
		protectedContentStruct, err := EncThenMac(encryptionContentStructKey, macConstentStructKey, bytesContentBlock)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(currentUUID, protectedContentStruct)
		currentRound += 1

	}
	return nil
}
func FileContentRestoring(fileKey []byte, fileLength []byte, fileContentFront []byte) (content []byte, err error) {
	return nil, nil
}
func RestoreSmallerFile(newFileLength int64, oldFileLength int64, ptrStart uuid.UUID) (err error) {
	//new file length is shorter than old file length
	longerFile := oldFileLength / 64
	shorterFile := newFileLength / 64
	for longerFile > shorterFile {
		deletableUUID, err := generateNextUUID(ptrStart, longerFile)
		if err != nil {
			return err
		}
		userlib.DatastoreDelete(deletableUUID)
		longerFile -= 1
	}
	return nil
}

/* ----------- END Helper Functions ---------*/
<<<<<<< HEAD
=======
/*---------Accepted Struct Helper Function ------- */
/*
type Accepted struct {
	CommsKey     []byte //User Choice of encryption but rederivable
	CommsChannel []byte //User choice of encryption but rederivable
}*/
/*
type Invitation struct {
	//this struct is DELETED after accept invitation
	CommsKey     []byte //key Argon2key(filename,owner,direct recipient) for the communications channel --> marshaled --> RSA Encrypted --> Rsa Signed
	CommsChannel []byte //UUID of the commschannel RSA encrypted and signed
}*/

func ProtectCommsChannel(protectedAcceptedKey []byte, commsChannel uuid.UUID) (protectedCommsChannel []byte, err error) {
	//inputs protectedAcceptedKey === from another step (technically same as argon2key of communications channel)
	byteCommsChannel, err := json.Marshal(commsChannel)
	if err != nil {
		return nil, errors.New("could not marshal commsChannel uuid")
	}
	encryptionCommsChannelKey, err := ConstructKey("encryption for CommsChannel in Accepted struct", "could not create encryption key for CommsChannel in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	macCommsChannelKey, err := ConstructKey("mac for CommsChannel in Accepted struct", "could not create mac key for CommsChannel in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	protectedCommsChannel, err = EncThenMac(encryptionCommsChannelKey, macCommsChannelKey, byteCommsChannel)
	if err != nil {
		return nil, err
	}
	return protectedCommsChannel, nil
}
func ProtectCommsKey(protectedAcceptedKey []byte, commsKey []byte) (protectedCommsKey []byte, err error) {
	encryptionCommsKey, err := ConstructKey("encryption for CommsKey in Accepted struct", "could not create encryption key for CommsKey in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	macCommsKey, err := ConstructKey("mac for CommsKey in Accepted struct", "could not create mac key for CommsKey in Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, err
	}
	protectedCommsKey, err = EncThenMac(encryptionCommsKey, macCommsKey, commsKey)
	if err != nil {
		return nil, err
	}
	return protectedCommsKey, nil
}
func ProtectAccepted(protectedAcceptedKey []byte, locationAcceptedStruct uuid.UUID, commsKey []byte, commsChannel uuid.UUID) (err error) {
	//create an accepted struct
	var accepted Accepted
	//use the helper function to fill the struct
	accepted.CommsChannel, err = ProtectCommsChannel(protectedAcceptedKey, commsChannel)
	if err != nil {
		return err
	}
	accepted.CommsKey, err = ProtectCommsKey(protectedAcceptedKey, commsKey)
	if err != nil {
		return err
	}
	// encrypt the struct
	acceptedStruct, err := json.Marshal(accepted)
	if err != nil {
		return errors.New("could not marshal the Accepted struct")
	}
	encryptionAcceptedStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return err
	}
	macAcceptedStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return err
	}
	protectedAcceptedStruct, err := EncThenMac(encryptionAcceptedStruct, macAcceptedStruct, acceptedStruct)
	if err != nil {
		return err
	}
	// put it at the uuid location passed in
	userlib.DatastoreSet(locationAcceptedStruct, protectedAcceptedStruct)
	return nil
}

/* ----------- Decrypting Your Accepted Struct ----------- */

func RecoverAcceptedStructContents(protectedA []byte, protectedAcceptedKey []byte) (commsKey []byte, commsChannel uuid.UUID, err error) {
	decryptionAcceptedStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macAcceptedStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the Accepted struct", protectedAcceptedKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	byteAcceptedStruct, err := CheckAndDecrypt(protectedA, macAcceptedStruct, decryptionAcceptedStruct)
	if err != nil {
		return nil, uuid.Nil, err
	}
	var acceptedStruct Accepted
	err = json.Unmarshal(byteAcceptedStruct, &acceptedStruct)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not unmarshal the Accepted struct")
	}
	protectedCommsChannel := acceptedStruct.CommsChannel
	protectedCommsKey := acceptedStruct.CommsKey

	commsChannel, err = RecoverCommsChannel(protectedCommsChannel, protectedA)
	if err != nil {
		return nil, uuid.Nil, err
	}
	commsKey, err = RecoverCommsKey(protectedCommsKey, protectedA)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return commsKey, commsChannel, nil
}
func RecoverCommsChannel(protectedCommsChannel []byte, protectedA []byte) (commsChannel uuid.UUID, err error) {
	decryptionCommsChannel, err := ConstructKey("encryption for CommsChannel in Accepted struct", "could not create encryption key for CommsChannel in Accepted struct", protectedA)
	if err != nil {
		return uuid.Nil, err
	}
	macCommsChannel, err := ConstructKey("mac for CommsChannel in Accepted struct", "could not create mac key for CommsChannel in Accepted struct", protectedA)
	if err != nil {
		return uuid.Nil, err
	}
	byteCommsChannel, err := CheckAndDecrypt(protectedCommsChannel, macCommsChannel, decryptionCommsChannel)
	if err != nil {
		return uuid.Nil, err
	}

	err = json.Unmarshal(byteCommsChannel, &commsChannel)
	if err != nil {
		return uuid.Nil, errors.New("could not unmarshal commschannel")
	}
	return commsChannel, nil
}
func RecoverCommsKey(protectedCommsKey []byte, protectedA []byte) (commsKey []byte, err error) {
	decryptionCommsKey, err := ConstructKey("encryption for CommsKey in Accepted struct", "could not create encryption key for CommsKey in Accepted struct", protectedA)
	if err != nil {
		return nil, err
	}
	macCommsKey, err := ConstructKey("mac for CommsKey in Accepted struct", "could not create mac key for CommsKey in Accepted struct", protectedA)
	if err != nil {
		return nil, err
	}
	byteCommsKey, err := CheckAndDecrypt(protectedCommsKey, macCommsKey, decryptionCommsKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(byteCommsKey, &commsKey)
	if err != nil {
		return nil, errors.New("could not unmarshal commschannel")
	}
	return commsKey, nil
}

/* -----------END Decrypting Your Accepted Struct ----------- */
>>>>>>> 3f55aaa6bee3611f9cd6f89a67438aadef5e188c

/* ----------- User Functions -------*/
func InitUser(username string, password string) (userdataptr *User, err error) {
	//creates user if they don't alr
	//checks username length minimum
	if len(username) < 1 {
		return nil, errors.New("cannot have a username that is that short")
	}
	//errors if user already exists
	exist, err := CheckUserExistenceString(username)
	if exist && err == nil {
		return nil, errors.New("username already exists in system")
	}

	//create the uuid, password, username, private and signature key in the user struct
	createdUUID, hashedPassword, byteUsername, err := ReconstructInitialize(username, password)
	if err != nil {
		return nil, err
	}
	_, protectedPrivateKey, err := MakeRSAKey(byteUsername, hashedPassword)
	if err != nil {
		return nil, err
	}
	_, protectedSignatureKey, err := MakeSignatureKey(byteUsername, hashedPassword)
	if err != nil {
		return nil, err
	}
	var user User
	user.hashedPasswordKDF = hashedPassword
	user.username = byteUsername
	user.PrivateRsaKey = protectedPrivateKey
	user.SignatureKey = protectedSignatureKey
	//
	byteUser, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("could not marshal the user struct")
	}
	structEncryptionKey, err := ConstructKey("encryption key for struct", "could not create encryption key to protect struct", hashedPassword)
	if err != nil {
		return nil, err
	}
	structMacKey, err := ConstructKey("mac key for struct", "could not create mac key to protext struct", hashedPassword)
	if err != nil {
		return nil, err
	}
	protectedStruct, err := EncThenMac(structEncryptionKey, structMacKey, byteUser)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(createdUUID, protectedStruct)

	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	if len(username) < 1 {
		return nil, errors.New("cannot have a username that is that short")
	}
	exist, err := CheckUserExistenceString(username)
	if err != nil && !exist {
		//user DOESNT exist
		return nil, err
	}

	if !exist {
		return nil, errors.New("user does not exist in the system")
	}
	createdUUID, hashedPassword, byteUsername, err := ReconstructInitialize(username, password)
	if err != nil {
		return nil, err
	}
	protectedStruct, ok := userlib.DatastoreGet(createdUUID)
	if !ok {
		return nil, errors.New("possible corruption, an adversary has overwritten your login")
	}
	testStructMacKey, err := ConstructKey("mac key for struct", "could not create mac key to protext struct", hashedPassword)
	if err != nil {
		return nil, err
	}
	testDecryptionKey, err := ConstructKey("encryption key for struct", "could not create encryption key to protect struct", hashedPassword)
	if err != nil {
		return nil, err
	}
	byteUser, err := CheckAndDecrypt(protectedStruct, testStructMacKey, testDecryptionKey)
	if err != nil {
		return nil, err
	}
	var originalUser User
	err = json.Unmarshal(byteUser, &originalUser)
	if err != nil {
		return nil, errors.New("could not return the original user because of unmarshalling")
	}
	var newUser User
	newUser.hashedPasswordKDF = hashedPassword
	newUser.username = byteUsername
	newUser.PrivateRsaKey = originalUser.PrivateRsaKey
	newUser.SignatureKey = originalUser.SignatureKey

	return &newUser, nil
}

// 1) returns the argon2key GetKeyFileName(filename string, hashedPasswordKDF []byte, username []byte)
//RecoverFileUUID(protectedFileUUID []byte, cCAprotectedKey []byte)

// 2) gets the UUID of the cc or A struct RegenerateUUIDCCA(cCAprotectedKey []byte) (CCAuuid uuid.UUID, err error)
// 3) func GetCCorA(CCAuuid uuid.UUID) (protectedCCA []byte, err error) data store gets the bytes
// 4) func IsCC(CCAuuid uuid.UUID, protectedCCA []byte, cCAprotectedKey []byte) checks if its a communications or a channel
// 5) if it is an accepted channel then use the decryption of the accepted ones
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	cCAProtectedKey, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return err
	}
	cCAUUID, err := RegenerateUUIDCCA(cCAProtectedKey)
	if err != nil {
		return nil
	}
	//Check data store if the filename exists in our name space
	protectedCCA, exists := GetCCorA(cCAUUID)
	if exists {
		// the file name is in the person name space (need to overwrite)
		owner, err := IsCC(protectedCCA, cCAProtectedKey)
		var protectedCC []byte
		var CCProtectedKey []byte
		if owner && err == nil {
			// you are the owner --> communications channel
			protectedCC, CCProtectedKey = protectedCCA, cCAProtectedKey
			fileKey, fileUUID, _, err := RecoverOwnerCCContents(protectedCC, CCProtectedKey)
			if err != nil {
				return err
			}
			byteFile, ok := userlib.DatastoreGet(fileUUID)
			if !ok {
				return errors.New("file does not exist in datastore")
			}
			frontPtr, fileLength, err := RecoverFileContents(byteFile, fileKey)
			if err != nil {
				return err
			}
			//divide len into blocks
			if int64(len(content)/64) > int64(fileLength/64) {
				err = fileContentFilling(fileKey, frontPtr, fileLength, content)
				if err != nil {
					return err
				}
			} else {
				err = RestoreSmallerFile(int64(len(content)/64), int64(fileLength/64), frontPtr)
				if err != nil {
					return err
				}
			}
			return nil
		}
		if !owner && err == nil {
			/*
				commsKey, commsChannel, err := RecoverAcceptedStructContents(protectedCCA, cCAProtectedKey)
				if err != nil {
					return err
				}
				protectedCC, CCProtectedKey */
			return nil
		} else {
			return err
		}

	} else {
		// the file name is not in the persons name space (create a new file) everything created is new
		protectedOwnerCCStruct, err := ProtectOwnerCC(cCAProtectedKey)
		if err != nil {
			return err
		}
		fileKey, fileUUID, _, err := RecoverOwnerCCContents(protectedOwnerCCStruct, cCAProtectedKey)
		if err != nil {
			return err
		}
		protectedFileStruct, err := ProtectFile(fileKey, content)
		if err != nil {
			return err
		}

		err = fileContentFilling(fileKey, fileUUID, len(content), content)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(fileUUID, protectedFileStruct)
		userlib.DatastoreSet(cCAUUID, protectedOwnerCCStruct)
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	/*byteFilename, err := json.Marshal(filename)
	if err != nil{
		return errors.New("could not marshal filename")
	}*/

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + string(userdata.username)))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

/* ----------- END Fill Section Functions -------*/
