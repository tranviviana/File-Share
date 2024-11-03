package client

// CS 161 Project 2

import (
	"encoding/json"
	"strconv"

	"strings"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	//"fmt"
	"errors"
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
/*-----------------USED FREQUENTLY--------------*/
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
}
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

/*-----------------USED FREQUENTLY--------------*/

/*--------------------Initialize User ------------------*/
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
	comboByte := append(hashedPasswordKDF, byteUsername...)
	userUUID := userlib.Argon2Key(comboByte, byteUsername, 16)
	userUUID, err = userlib.HashKDF(userUUID, hardCodedText)
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not hashKDF our password")
	}
	createdUUID, err = uuid.FromBytes(userUUID[:16])
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("could not create the userUUID")
	}
	return createdUUID, hashedPasswordKDF, byteUsername, nil
}

/*--------------------Initialize User ------------------*/

/*-------------------Store File Content ---------------*/

func FileContentFilling(fileKey []byte, contentStart uuid.UUID, fileLength int, content []byte) (err error) {
	//64 block size
	tracker := 0
	roundsEncryption := 0
	currentUUID := contentStart
	if fileLength%64 == 0 {
		roundsEncryption = fileLength / 64
	} else {
		roundsEncryption = (fileLength / 64) + 1
	}
	contentSplice := content
	for tracker < roundsEncryption {
		if (tracker+1)*64 > len(content) {
			contentSplice = content[tracker*64:]

		} else {
			contentSplice = content[tracker*64 : (tracker+1)*64]
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
		tracker += 1

	}
	return nil
}
func GenerateNextUUID(contentStart uuid.UUID, blockNumber int64) (nextUUID uuid.UUID, err error) {
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
func RestoreSmallerFile(newFileLength int64, oldFileLength int64, ptrStart uuid.UUID) (err error) {
	//new file length is shorter than old file length
	longerFile := oldFileLength / 64
	shorterFile := newFileLength / 64
	for longerFile > shorterFile {
		deletableUUID, err := GenerateNextUUID(ptrStart, longerFile)
		if err != nil {
			return err
		}
		userlib.DatastoreDelete(deletableUUID)
	}
	return nil
}

/*-------------------Store File Content ---------------*/

/*--------------File is new----------*/
/*--------------First Check Point (Owner == CC struct) (Recipient == A Struct)-----*/
func GetKeyFileName(filename string, hashedPasswordKDF []byte, username []byte) (personalFirstKey []byte, personalFirstUUID uuid.UUID, protectedFilename []byte, err error) {
	//returns the communications key of the owner OR the accepted key of the recipient
	byteFilename, err := json.Marshal(filename)
	if err != nil {
		return nil, uuid.Nil, nil, errors.New("could not marshal filename")
	}
	byteHardCodedText, err := json.Marshal("cc or a hard-coded text")
	if err != nil {
		return nil, uuid.Nil, nil, errors.New("could not marshal hard coded text")
	}
	//hash kdf the password for more "security"
	cCApasswordKey, err := userlib.HashKDF(hashedPasswordKDF, byteHardCodedText)
	if err != nil {
		return nil, uuid.Nil, nil, errors.New("could not hash kdf the filename")
	}
	cCAByteKey := append(byteFilename, cCApasswordKey...)
	cCAByteKey = append(cCAByteKey, username...)
	personalFirstKey = userlib.Argon2Key(cCAByteKey, username, 16) // hashKDF

	filenameEncryptionKey, err := ConstructKey("my filename encryption key", "could not create an encryption key for filename", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	filenameMacKey, err := ConstructKey("my filename mac key", "could not create a mac key for filename", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	protectedFilename, err = EncThenMac(filenameEncryptionKey, filenameMacKey, byteHardCodedText)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}

	//uuid of owners communication channel or recipients acceptance channel
	bytesUUID, err := ConstructKey("UUID of communications or acceptance struct", "could not create a key to convert to UUID", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	personalFirstUUID, err = uuid.FromBytes(bytesUUID)
	if err != nil {
		return nil, uuid.Nil, nil, errors.New("could not create a person first UUID")
	}
	return personalFirstKey, personalFirstUUID, protectedFilename, nil
}
func IsCC(protectedCCA []byte, personalFirstKey []byte) (owner bool, err error) {
	//BE CAREFUL USING THIS ONE
	//protectedCCA to minimize calls to datastorre
	cCaEncryptionKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", personalFirstKey)
	if err != nil {
		return false, err
	}
	cCaMacKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", personalFirstKey)
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
func CreateNewA(commsKey []byte, commsChannel []byte, personalFirstKey []byte) (protectedAStruct []byte, err error) {
	//used to create a personal acceptance struct
	/* given via invitation struct
	   type Accepted struct {
	   CommsKey     []byte //User Choice of encryption but rederivable
	   CommsChannel []byte //User choice of encryption but rederivable

	*/
	encryptionCommsKey, err := ConstructKey("New Accepted Invite Comms Key", "could not create encryption for commsKey", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macCommsKEY, err := ConstructKey("New Accepted Invite Comms Mac Key", "could not create Mac for commsKey", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedCommsKey, err := EncThenMac(encryptionCommsKey, macCommsKEY, commsKey)
	if err != nil {
		return nil, err
	}

	encryptionCommsChannel, err := ConstructKey("Accepted Comms Channel ", "could not create encryption for comms channel", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macCommsChannel, err := ConstructKey("New Accepted Invite Comms Channel Mac Key", "could not create Mac for comms channel", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedCommsChannel, err := EncThenMac(encryptionCommsChannel, macCommsChannel, commsChannel)
	if err != nil {
		return nil, err
	}

	var AStruct Accepted
	AStruct.CommsChannel = protectedCommsChannel
	AStruct.CommsKey = protectedCommsKey
	byteAstruct, err := json.Marshal(AStruct)
	if err != nil {
		return nil, errors.New("could not marshal the accepted struct")
	}
	encryptionAstruct, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macAstruct, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedAStruct, err = EncThenMac(encryptionAstruct, macAstruct, byteAstruct)
	if err != nil {
		return nil, err
	}
	return protectedAStruct, nil
}
func CreateNewCC(personalFirstKey []byte) (protectedNewCC []byte, err error) {
	/*
	   type CommunicationsChannel struct {
	       FileKey    []byte //randomly generated key which will change in revocation
	       FileStruct []byte //randomly generated UUID which will change in revocation
	   }
	*/
	var ownerCC CommunicationsChannel
	//filling Owner CC with the random generated File Key and File Struct UUID
	fileSourceKey := userlib.RandomBytes(128)
	fileSalt := userlib.RandomBytes(128)
	fileKey := userlib.Argon2Key(fileSourceKey, fileSalt, 16)
	encryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedFileKey, err := EncThenMac(encryptionFileKey, macFileKey, fileKey)
	if err != nil {
		return nil, err
	}
	randomUUID := uuid.New()
	byteRandomUUID, err := json.Marshal(randomUUID)
	if err != nil {
		return nil, errors.New("could not marshal random UUID to hide file")
	}
	encryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedFileUUID, err := EncThenMac(encryptionFileUUID, macFileUUID, byteRandomUUID)
	if err != nil {
		return nil, err
	}

	ownerCC.FileKey = protectedFileKey
	ownerCC.FileStruct = protectedFileUUID

	bytesOwnerCC, err := json.Marshal(ownerCC)
	if err != nil {
		return nil, errors.New("could not marshal the owner's communication node")
	}
	encryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", personalFirstKey)
	if err != nil {
		return nil, err
	}

	protectedOwnerCC, err := EncThenMac(encryptionCCStructKey, macCCStructKey, bytesOwnerCC)
	if err != nil {
		return nil, err
	}
	return protectedOwnerCC, nil
}
func AccessCC(ccKey []byte, protectedCC []byte) (FileKey []byte, FileStructUUID uuid.UUID, err error) {
	//ccKey for the owner is through getKeyFileName
	//ccKey for non-owners is through their accepted struct

	//unencrypt CC channel
	testEncryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	testMacCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	byteCC, err := CheckAndDecrypt(protectedCC, testMacCCStructKey, testEncryptionCCStructKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	var CC CommunicationsChannel
	err = json.Unmarshal(byteCC, &CC)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not unmarshal communications struct")
	}
	//unencrypt and return the contents of the CC channel File UUID
	protectedFileUUID := CC.FileStruct
	decryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	byteFileUUID, err := CheckAndDecrypt(protectedFileUUID, macFileUUID, decryptionFileUUID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	var tempFileStructUUID uuid.UUID
	err = json.Unmarshal(byteFileUUID, &tempFileStructUUID)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not unmarshal File uuid")
	}
	FileStructUUID = tempFileStructUUID
	//unencrypt and return the contents of the CC channel File Key
	protectedFileKey := CC.FileKey
	decryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	FileKey, err = CheckAndDecrypt(protectedFileKey, macFileKey, decryptionFileKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return FileKey, FileStructUUID, err
}
func AccessA(personalFirstKey []byte, protectedAstruct []byte) (CommsKey []byte, CommsChannel uuid.UUID, err error) {
	//getting the a struct
	decryptionAstruct, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macAstruct, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	byteAstruct, err := CheckAndDecrypt(protectedAstruct, macAstruct, decryptionAstruct)
	if err != nil {
		return nil, uuid.Nil, err
	}

	var AStruct Accepted
	err = json.Unmarshal(byteAstruct, &AStruct)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not unmarshal accepted struct")
	}

	//getting the comms channel
	protectedCommsChannel := AStruct.CommsChannel
	decryptionCommsChannel, err := ConstructKey("Accepted Comms Channel ", "could not create encryption for comms channel", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macCommsChannel, err := ConstructKey("New Accepted Invite Comms Channel Mac Key", "could not create Mac for comms channel", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	byteCommsChannel, err := CheckAndDecrypt(protectedCommsChannel, macCommsChannel, decryptionCommsChannel)
	if err != nil {
		return nil, uuid.Nil, err
	}
	var tempCommsChannel uuid.UUID
	err = json.Unmarshal(byteCommsChannel, &tempCommsChannel)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not unmarshal Comms Channel")
	}
	CommsChannel = tempCommsChannel

	protectedCommsKey := AStruct.CommsKey
	decryptionCommsKey, err := ConstructKey("New Accepted Invite Comms Key", "could not create encryption for commsKey", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macCommsKEY, err := ConstructKey("New Accepted Invite Comms Mac Key", "could not create Mac for commsKey", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	CommsKey, err = CheckAndDecrypt(protectedCommsKey, macCommsKEY, decryptionCommsKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return CommsKey, CommsChannel, nil
}
func CreateNewFile(fileKey []byte, fileLength int) (protectedFileStruct []byte, err error) {
	//enrypting file contents
	randomUUID := uuid.New()
	byteRandomUUID, err := json.Marshal(randomUUID)
	if err != nil {
		return nil, errors.New("could not marshal the content point uuid")
	}
	encryptionContentPtr, err := ConstructKey("encryption for content pointer start", "could not create an encryption key for the content pointer", fileKey)
	if err != nil {
		return nil, err
	}
	macContentPtr, err := ConstructKey("Mac key for content pointer start", "could not create a mac key for the content pointer", fileKey)
	if err != nil {
		return nil, err
	}
	protectedContentUUID, err := EncThenMac(encryptionContentPtr, macContentPtr, byteRandomUUID)
	if err != nil {
		return nil, err
	}
	byteFileLength, err := json.Marshal(fileLength)
	if err != nil {
		return nil, errors.New("could not marshal the file length to protect the file length")
	}
	encryptionFileLength, err := ConstructKey("encryption key for the file length", "could not create encryption key for the file length", fileKey)
	if err != nil {
		return nil, err
	}
	macFileLength, err := ConstructKey("mac Key for the file length", "could not create mac key for the file length", fileKey)
	if err != nil {
		return nil, err
	}
	protectedFileLength, err := EncThenMac(encryptionFileLength, macFileLength, byteFileLength)
	if err != nil {
		return nil, err
	}

	var fileStruct File
	fileStruct.FileContentFront = protectedContentUUID
	fileStruct.FileLength = protectedFileLength

	byteFileStruct, err := json.Marshal(fileStruct)
	if err != nil {
		return nil, errors.New("could not marshal the file struct accessible to everyone")
	}
	encryptionFileStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the file struct accessible to everyone", fileKey)
	if err != nil {
		return nil, err
	}
	macFileStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the file struct accessible to everyone", fileKey)
	if err != nil {
		return nil, err
	}
	protectedFileStruct, err = EncThenMac(encryptionFileStruct, macFileStruct, byteFileStruct)
	if err != nil {
		return nil, err
	}

	return protectedFileStruct, nil

}
func AccessFile(protectedFileStruct []byte, fileKey []byte) (fileLength int, contentPtr uuid.UUID, err error) {
	decryptionFileStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the file struct accessible to everyone", fileKey)
	if err != nil {
		return 0, uuid.Nil, err
	}
	macFileStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the file struct accessible to everyone", fileKey)
	if err != nil {
		return 0, uuid.Nil, err
	}
	byteFileStruct, err := CheckAndDecrypt(protectedFileStruct, macFileStruct, decryptionFileStruct)
	if err != nil {
		return 0, uuid.Nil, err
	}
	var tempFileStruct File
	err = json.Unmarshal(byteFileStruct, &tempFileStruct)
	if err != nil {
		return 0, uuid.Nil, errors.New("could not unmarshal the file struct")
	}
	protectedFileContentPtr := tempFileStruct.FileContentFront
	protectedFileLength := tempFileStruct.FileLength

	decryptionContentPtr, err := ConstructKey("encryption for content pointer start", "could not create an encryption key for the content pointer", fileKey)
	if err != nil {
		return 0, uuid.Nil, err
	}
	macContentPtr, err := ConstructKey("Mac key for content pointer start", "could not create a mac key for the content pointer", fileKey)
	if err != nil {
		return 0, uuid.Nil, err
	}
	byteFileUUID, err := CheckAndDecrypt(protectedFileContentPtr, macContentPtr, decryptionContentPtr)
	if err != nil {
		return 0, uuid.Nil, err
	}
	var tempFileUUID uuid.UUID
	err = json.Unmarshal(byteFileUUID, &tempFileUUID)
	if err != nil {
		return 0, uuid.Nil, errors.New("could not retreive file uuid because of unmarshalling")
	}
	contentPtr = tempFileUUID

	decryptionFileLength, err := ConstructKey("encryption key for the file length", "could not create encryption key for the file length", fileKey)
	if err != nil {
		return 0, uuid.Nil, err
	}
	macFileLength, err := ConstructKey("mac Key for the file length", "could not create mac key for the file length", fileKey)
	if err != nil {
		return 0, uuid.Nil, err
	}
	byteFileLength, err := CheckAndDecrypt(protectedFileLength, macFileLength, decryptionFileLength)
	if err != nil {
		return 0, uuid.Nil, err
	}
	var tempFileLength int
	err = json.Unmarshal(byteFileLength, &tempFileLength)
	if err != nil {
		return 0, uuid.Nil, errors.New("could not return the length of the file because of unmarshalling")
	}
	fileLength = tempFileLength
	return fileLength, contentPtr, nil
}

/*----------Create Invitation ----------*/
func CreateSharedCCKey(filename string, username []byte, recipient string) (sharedKey []byte, communicationLocation uuid.UUID, err error) {
	//used by sharer to create a shared key between them and the recipient
	byteFilename, err := json.Marshal(filename)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal filename")
	}
	byteRecipient, err := json.Marshal(recipient)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal recipient's name")
	}
	byteCollab := append(byteFilename, byteRecipient...)
	byteCollab = append(byteCollab, username...)
	sharedKey = userlib.Argon2Key(byteCollab, username, 16) //hashKDF off of this

	byteNewLocation, err := ConstructKey("UUID location for Communication", "could not generate a new uuid location", sharedKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	communicationLocation, err = uuid.FromBytes(byteNewLocation)
	if err != nil {
		return nil, uuid.Nil, errors.New("byte new location was not long enough")
	}
	return sharedKey, communicationLocation, nil
}
func CreateCopyCC(protectedCC []byte, personalFirstKey []byte, filename string, username []byte, recipient string) (communicationLocation uuid.UUID, protectedRecipientCC []byte, ccKey []byte, err error) {
	// used by owner to copy their CC struct to share with a new user
	fileKey, fileStructUUID, err := AccessCC(personalFirstKey, protectedCC)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	ccKey, communicationLocation, err = CreateSharedCCKey(filename, username, recipient)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	var recipientCC CommunicationsChannel

	//encrypting file key same way as owner CC so easier to decrypt
	encryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	protectedFileKey, err := EncThenMac(encryptionFileKey, macFileKey, fileKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	byteFileStruct, err := json.Marshal(fileStructUUID)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("could not marshale the file struct uuid")
	}
	encryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	protectedFileUUID, err := EncThenMac(encryptionFileUUID, macFileUUID, byteFileStruct)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	recipientCC.FileKey = protectedFileKey
	recipientCC.FileStruct = protectedFileUUID

	// hiding the struct and marshaling
	byteRecipientCC, err := json.Marshal(recipientCC)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("could not marshal CC for recipient")
	}
	encryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	macCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	protectedRecipientCC, err = EncThenMac(encryptionCCStructKey, macCCStructKey, byteRecipientCC)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	return communicationLocation, protectedRecipientCC, ccKey, nil
}

/*----------Create Invitation ----------*/
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
func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	personalFirstKey, personalFirstUUID, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return nil
	}
	protectedFirstEntrance, ok := userlib.DatastoreGet(personalFirstUUID)
	if ok {
		//exists already so we can over write
		owner, err := IsCC(protectedFirstEntrance, personalFirstKey)
		if err != nil {
			return err
		}
		var fileKey []byte
		var fileStructUUID uuid.UUID
		if owner {
			fileKey, fileStructUUID, err = AccessCC(personalFirstKey, protectedFirstEntrance)
			if err != nil {
				return err
			}
		} else {
			commsKey, commsUUID, err := AccessA(personalFirstKey, protectedFirstEntrance)
			if err != nil {
				return err
			}
			protectedRCC, ok := userlib.DatastoreGet(commsUUID)
			if !ok {
				return errors.New("File does not exist or you have been revoked, stop accessing me")
			}
			fileKey, fileStructUUID, err = AccessCC(commsKey, protectedRCC)
			if err != nil {
				return err
			}
		}
		protectedFile, ok := userlib.DatastoreGet(fileStructUUID)
		if !ok {
			return errors.New("error retrieving your file")
		}
		oldFileLength, contentStart, err := AccessFile(protectedFile, fileKey)
		if err != nil {
			return err
		}
		err = RestoreSmallerFile(int64(len(content)), int64(oldFileLength), contentStart)
		if err != nil {
			return err
		}
		err = FileContentFilling(fileKey, contentStart, len(content), content)
		if err != nil {
			return err
		}
		return nil
	}
	// doesnt exist yet
	protectedNewCC, err := CreateNewCC(personalFirstKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(personalFirstUUID, protectedNewCC)
	fileKey, fileStructUUID, err := AccessCC(personalFirstKey, protectedNewCC)
	if err != nil {
		return err
	}
	protectedFileStruct, err := CreateNewFile(fileKey, len(content))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStructUUID, protectedFileStruct)
	_, contentStart, err := AccessFile(protectedFileStruct, fileKey)
	if err != nil {
		return err
	}
	err = FileContentFilling(fileKey, contentStart, len(content), content)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
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
