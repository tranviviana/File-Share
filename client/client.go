package client

// CS 161 Project 2

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	//"strings"

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
	FileKey         []byte //randomly generated key which will change in revocation
	FileStruct      []byte //randomly generated UUID which will change in revocation
	SharingLocation []byte //randomly generated UUID for owner to place the communications channel or shared users
}
type Accepted struct {
	CommsKey     []byte //User Choice of encryption but rederivable
	CommsChannel []byte //User choice of encryption but rederivable
}
type File struct {
	FileLength   []byte //uint --> marshal --> enc with File key hashKDF filelength
	ContentStart []byte //uuid of the front filecontent struct --> marshal --> enc with File key hashKDF filecontentFront
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
func RestoreSignature(protectedSignatureKey []byte, hashedPassword []byte) (signatureKey userlib.DSSignKey, err error) {
	signatureKeyDecryption, err := ConstructKey("signature key encryption", "could not create encryption key for Signature and Verification key", hashedPassword)
	if err != nil {
		return userlib.DSSignKey{}, err
	}
	signatureKeyMac, err := ConstructKey("signature key MAC", "could not create mac key for Signature and Verification key", hashedPassword)
	if err != nil {
		return userlib.DSSignKey{}, err
	}

	byteSignatureKey, err := CheckAndDecrypt(protectedSignatureKey, signatureKeyMac, signatureKeyDecryption)
	if err != nil {
		return userlib.DSSignKey{}, err
	}
	var tempSignatureKey userlib.DSSignKey
	err = json.Unmarshal(byteSignatureKey, &tempSignatureKey)
	if err != nil {
		return userlib.DSSignKey{}, errors.New("could not unmarshal signature key")
	}
	signatureKey = tempSignatureKey
	return signatureKey, nil
}
func RestorePrivateKey(protectedPrivateKey []byte, hashedPassword []byte) (privateKey userlib.PKEDecKey, err error) {
	privateKeyDecryption, err := ConstructKey("rsa private key encryption", "could not create encryption key for RSA private key", hashedPassword)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	privateKeyMac, err := ConstructKey("rsa private key MAC", "could not create mac key for RSA private key", hashedPassword)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	bytePrivateKey, err := CheckAndDecrypt(protectedPrivateKey, privateKeyMac, privateKeyDecryption)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	var tempPrivateKey userlib.PKEDecKey
	err = json.Unmarshal(bytePrivateKey, &tempPrivateKey)
	if err != nil {
		return userlib.PrivateKeyType{}, errors.New("could not unmarshal private key")
	}
	privateKey = tempPrivateKey
	return privateKey, nil
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

func SetFileContent(fileKey []byte, contentUUID uuid.UUID, fileLength int, content []byte) (err error) {
	//64 block size

	currentUUID := contentUUID
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
		hardCodedText := "content encryption salt" + strconv.Itoa(currentRound)
		encryptionContentKey, err := ConstructKey(hardCodedText, "could not encrypt content block", fileKey)
		if err != nil {
			return err
		}
		hardCodedText = "content MAC salt" + strconv.Itoa(currentRound)
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

		hardCodedText = "content struct encryption salt" + strconv.Itoa(currentRound)
		encryptionContentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return err
		}
		hardCodedText = "content struct mac salt" + strconv.Itoa(currentRound)
		macContentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return err
		}
		protectedContentStruct, err := EncThenMac(encryptionContentStructKey, macContentStructKey, bytesContentBlock)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(currentUUID, protectedContentStruct)
		currentRound += 1
		currentUUID, err = GenerateNextUUID(contentUUID, int64(currentRound))
		if err != nil {
			return err
		}
	}
	return nil
}
func GenerateNextUUID(contentStart uuid.UUID, blockNumber int64) (nextUUID uuid.UUID, err error) {
	if blockNumber < 0 {
		return uuid.Nil, errors.New("GenerateNetUUID: block number must be non-negative")
	}

	// Create a length 16 byte slice from the UUID
	uuidBytes := contentStart[:]
	if len(uuidBytes) != 16 {
		return uuid.Nil, errors.New("GenerateNetUUID: UUID size incorrect")
	}

	// Create length 16 bytes from blockNumber
	blockBytes, err := json.Marshal(blockNumber)
	if err != nil {
		return uuid.Nil, errors.New("GenerateNetUUID: could not marshal block number")
	}
	hardCodedText, err := json.Marshal("sourcekey to hash the blockNumber into a unique length 16 []byte")
	if err != nil {
		return uuid.Nil, errors.New("GenerateNetUUID: could not marshal text")
	}
	hashedBlockBytes, err := userlib.HashKDF(hardCodedText[:16], blockBytes)
	if err != nil {
		return uuid.Nil, errors.New("GenerateNetUUID: could not hash blockBytes")
	}
	if len(hashedBlockBytes) != 64 {
		return uuid.Nil, errors.New("GenerateNetUUID: hashedBlockBytes incorrect size")
	}
	hashedBlockBytes = hashedBlockBytes[:16]

	//xor uuid & block bytes
	for i := 0; i < 16; i++ {
		uuidBytes[15-i] ^= hashedBlockBytes[15-i]
	}

	// Return the new UUID
	nextUUID, err = uuid.FromBytes(uuidBytes)
	if err != nil {
		return uuid.Nil, errors.New("GenerateNetUUID: could not convert bytes to uuid")
	}
	return nextUUID, nil
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
func GetFileContent(fileKey []byte, fileLength int, contentStart uuid.UUID) (content []byte, err error) {
	currentUUID := contentStart

	// Calculate the number of blocks needed
	var roundsDecryption int
	if fileLength%64 == 0 {
		roundsDecryption = fileLength / 64
	} else {
		roundsDecryption = (fileLength / 64) + 1
	}
	currentRound := 0

	for currentRound < roundsDecryption {
		// Retrieve encrypted block from datastore
		encryptedBlock, exists := userlib.DatastoreGet(currentUUID)
		if !exists {
			return nil, errors.New("file block missing from datastore")
		}

		// Reconstruct encryption and MAC keys for this block
		hardCodedText := "content struct encryption salt" + strconv.Itoa(currentRound)
		decryptionContentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return nil, err
		}
		hardCodedText = "content struct mac salt" + strconv.Itoa(currentRound)
		macContentStructKey, err := ConstructKey(hardCodedText, "could not create MAC key for content struct", fileKey)
		if err != nil {
			return nil, err
		}

		// Decrypt and authenticate block content
		byteContentBlock, err := CheckAndDecrypt(encryptedBlock, macContentStructKey, decryptionContentStructKey)
		if err != nil {
			return nil, errors.New("decryption or MAC validation failed for file block")
		}

		// Unmarshal the content block
		var contentBlock FileContent
		err = json.Unmarshal(byteContentBlock, &contentBlock)
		if err != nil {
			return nil, errors.New("could not unmarshal file content block")
		}

		// Generate encryption and MAC keys for the content itself
		hardCodedText = "content encryption salt" + strconv.Itoa(currentRound)
		decryptionContentKey, err := ConstructKey(hardCodedText, "could not create encryption key for content", fileKey)
		if err != nil {
			return nil, err
		}

		hardCodedText = "content MAC salt" + strconv.Itoa(currentRound)
		macContentKey, err := ConstructKey(hardCodedText, "could not create MAC key for content", fileKey)
		if err != nil {
			return nil, err
		}

		// Verify and decrypt the actual file content
		decryptedContent, err := CheckAndDecrypt(contentBlock.BlockEncrypted, macContentKey, decryptionContentKey)
		if err != nil {
			return nil, errors.New("GetFileContent: integrity check failed for file content")
		}

		// Append the decrypted content to the full content array
		content = append(content, decryptedContent...)

		// Generate the next UUID in the chain
		currentRound += 1
		currentUUID, err = GenerateNextUUID(contentStart, int64(currentRound))
		if err != nil {
			return nil, err
		}
	}

	// Trim content to the actual file length (in case of padding in the last block)
	if len(content) > fileLength {
		content = content[:fileLength]
	}

	return content, nil
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
	byteRandomCommsUUID := userlib.RandomBytes(16)
	stringRandomCommsUUID := hex.EncodeToString(byteRandomCommsUUID)
	byteStringRandomComms, err := json.Marshal(stringRandomCommsUUID)
	if err != nil {
		return nil, errors.New("could not marshal randomCommsUUID")
	}
	encryptionRandomCommsUUID, err := ConstructKey("encryption for random comms UUID", "could not create encryption key for the comms UUID", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macRandomCommsUUID, err := ConstructKey("mac for random comms", "could not create mac key for the comms UUID", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedBaseCommsUUID, err := EncThenMac(encryptionRandomCommsUUID, macRandomCommsUUID, byteStringRandomComms)
	if err != nil {
		return nil, err
	}

	ownerCC.FileKey = protectedFileKey
	ownerCC.FileStruct = protectedFileUUID
	ownerCC.SharingLocation = protectedBaseCommsUUID

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
func AccessCC(ccKey []byte, protectedCC []byte) (FileKey []byte, FileStructUUID uuid.UUID, randomCommsUUID string, err error) {
	//ccKey for the owner is through getKeyFileName
	//ccKey for non-owners is through their accepted struct

	//unencrypt CC channel
	testEncryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CCA struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	testMacCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CCA struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	byteCC, err := CheckAndDecrypt(protectedCC, testMacCCStructKey, testEncryptionCCStructKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	var CC CommunicationsChannel
	err = json.Unmarshal(byteCC, &CC)
	if err != nil {
		return nil, uuid.Nil, "", errors.New("could not unmarshal communications struct")
	}
	//unencrypt and return the contents of the CC channel File UUID
	protectedFileUUID := CC.FileStruct
	decryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	byteFileUUID, err := CheckAndDecrypt(protectedFileUUID, macFileUUID, decryptionFileUUID)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	var tempFileStructUUID uuid.UUID
	err = json.Unmarshal(byteFileUUID, &tempFileStructUUID)
	if err != nil {
		return nil, uuid.Nil, "", errors.New("could not unmarshal File uuid")
	}
	FileStructUUID = tempFileStructUUID
	protectedBaseCommsUUID := CC.SharingLocation
	decryptionRandomCommsUUID, err := ConstructKey("encryption for random comms UUID", "could not create encryption key for the comms UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	macRandomCommsUUID, err := ConstructKey("mac for random comms", "could not create mac key for the comms UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	byteRandomCommsUUID, err := CheckAndDecrypt(protectedBaseCommsUUID, macRandomCommsUUID, decryptionRandomCommsUUID)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	var tempRandomComms string
	err = json.Unmarshal(byteRandomCommsUUID, &tempRandomComms)
	if err != nil {
		return nil, uuid.Nil, "", errors.New("could not unmarshall comms uuid string")
	}
	randomCommsUUID = tempRandomComms

	//unencrypt and return the contents of the CC channel File Key
	protectedFileKey := CC.FileKey
	decryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	FileKey, err = CheckAndDecrypt(protectedFileKey, macFileKey, decryptionFileKey)
	if err != nil {
		return nil, uuid.Nil, "", err
	}
	return FileKey, FileStructUUID, randomCommsUUID, err
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
	fileStruct.ContentStart = protectedContentUUID
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
	protectedFileContentPtr := tempFileStruct.ContentStart
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
func setNewFileLength(newFileLength int, fileKey []byte, protectedFile []byte) (updatedProtectedFile []byte, err error) {
	decryptionFileStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the file struct accessible to everyone", fileKey)
	if err != nil {
		return nil, err
	}
	macFileStruct, err := ConstructKey("mac key for the file struct", "could not create a mac key for the file struct accessible to everyone", fileKey)
	if err != nil {
		return nil, err
	}
	byteFileStruct, err := CheckAndDecrypt(protectedFile, macFileStruct, decryptionFileStruct)
	if err != nil {
		return nil, err
	}
	var fileStruct File
	err = json.Unmarshal(byteFileStruct, &fileStruct)
	if err != nil {
		return nil, errors.New("could not unmarshal the file struct")
	}

	//update file length
	byteFileLength, err := json.Marshal(newFileLength)
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

	// getting fil struct and editing it
	fileStruct.FileLength = protectedFileLength

	byteFileStruct, err = json.Marshal(fileStruct)
	if err != nil {
		return nil, errors.New("could not marshal the file struct accessible to everyone")
	}
	encryptionFileStruct, err := ConstructKey("encryption key for the file struct", "could not encrypt the file struct accessible to everyone", fileKey)
	if err != nil {
		return nil, err
	}
	macFileStruct, err = ConstructKey("mac key for the file struct", "could not create a mac key for the file struct accessible to everyone", fileKey)
	if err != nil {
		return nil, err
	}
	updatedProtectedFile, err = EncThenMac(encryptionFileStruct, macFileStruct, byteFileStruct)
	if err != nil {
		return nil, err
	}
	return updatedProtectedFile, nil

}

/*----------Create Invitation ----------*/
func CreateSharedCCKey(filename string, username []byte, recipient string, randomCommsUUID string) (sharedKey []byte, communicationLocation uuid.UUID, err error) {
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
	byteRandomCommsUUID, err := json.Marshal(randomCommsUUID)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal key for recipient")
	}
	byteCollab = append(byteCollab, byteRandomCommsUUID...)
	sharedKey = userlib.Argon2Key(byteCollab, username, 16) //hashKDF off of this

	byteNewLocation, err := ConstructKey(randomCommsUUID, "could not generate a new uuid location", sharedKey)
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
	fileKey, fileStructUUID, randomCommsUUID, err := AccessCC(personalFirstKey, protectedCC)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	ccKey, communicationLocation, err = CreateSharedCCKey(filename, username, recipient, randomCommsUUID)
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
	//not actually gonna be used by recipients tho
	byteRandomCommsUUID := userlib.RandomBytes(16)
	stringRandomCommsUUID := hex.EncodeToString(byteRandomCommsUUID)
	byteStringRandomComms, err := json.Marshal(stringRandomCommsUUID)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("could not marshal randomCommsUUID")
	}
	encryptionRandomCommsUUID, err := ConstructKey("encryption for random comms UUID", "could not create encryption key for the comms UUID", personalFirstKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	macRandomCommsUUID, err := ConstructKey("mac for random comms", "could not create mac key for the comms UUID", personalFirstKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	protectedBaseCommsUUID, err := EncThenMac(encryptionRandomCommsUUID, macRandomCommsUUID, byteStringRandomComms)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	recipientCC.FileKey = protectedFileKey
	recipientCC.FileStruct = protectedFileUUID
	recipientCC.FileStruct = protectedBaseCommsUUID

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
<<<<<<< HEAD

//func CreateInvitation(commsKey []byte, CommunicationsChannel uuid.UUID)
=======
func Invite(signature userlib.PrivateKeyType, recipientPKE userlib.PKEEncKey, communicationLocation uuid.UUID, ccKey []byte) (protectedInvitation []byte, invitationUUID uuid.UUID, err error) {
	//(signatureKey, recipientPublicKey, recipientCClocation, ccKey)
	/*type Invitation struct {
		//this struct is DELETED after accept invitation
		CommsKey     []byte //key Argon2key(filename,owner,direct recipient) for the communications channel --> marshaled --> RSA Encrypted --> Rsa Signed
		CommsChannel []byte //UUID of the commschannel RSA encrypted and signed
	}*/
	//encrypting comms key and signing it
	encryptedCCKey, err := userlib.PKEEnc(recipientPKE, ccKey)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not encrypt ccKey")
	}
	protectedCCKey, err := userlib.DSSign(signature, encryptedCCKey)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not accurately sign message")
	}
	//encrypting comms channel uuid
	byteComms, err := json.Marshal(communicationLocation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal comms channel uuid")
	}
	encryptedComms, err := userlib.PKEEnc(recipientPKE, byteComms)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not encrypt the communications channel")
	}
	protectedComms, err := userlib.DSSign(signature, encryptedComms)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not sign the communicaton channel")
	}

	var invitation Invitation
	invitation.CommsChannel = protectedComms
	invitation.CommsKey = protectedCCKey

	byteInvitation, err := json.Marshal(invitation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshall invitation")
	}

	//encrypt the invitation
	encryptedByteInvitation, err := userlib.PKEEnc(recipientPKE, byteInvitation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not encrypt the invitation struct")
	}
	protectedInvitation, err = userlib.DSSign(signature, encryptedByteInvitation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not sign the invitation struct")
	}
	invitationUUID = uuid.New()
	return protectedInvitation, invitationUUID, nil
}

func DecryptInvitation(privateKey userlib.PrivateKeyType, invitationStruct []byte) (acceptedStruct []byte, err error)
>>>>>>> 3db123e61d05491fe073595bf6b21aa020791815

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
			fileKey, fileStructUUID, _, err = AccessCC(personalFirstKey, protectedFirstEntrance)
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
			fileKey, fileStructUUID, _, err = AccessCC(commsKey, protectedRCC)
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
		err = SetFileContent(fileKey, contentStart, len(content), content)
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
	fileKey, fileStructUUID, _, err := AccessCC(personalFirstKey, protectedNewCC)
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
	err = SetFileContent(fileKey, contentStart, len(content), content)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	personalFirstKey, personalFirstUUID, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return nil
	}
	protectedFirstEntrance, ok := userlib.DatastoreGet(personalFirstUUID)
	if !ok {
		return errors.New("file is not in file space")
	}
	owner, err := IsCC(protectedFirstEntrance, personalFirstKey)
	if err != nil {
		return err
	}
	var fileKey []byte
	var fileStructUUID uuid.UUID
	if owner {
		//first entrance is then the CC channel
		fileKey, fileStructUUID, _, err = AccessCC(personalFirstKey, protectedFirstEntrance)
		if err != nil {
			return err
		}
	} else {
		// not the owner so accepted channel -> cc channel -> file struct
		commsKey, commsChannelUUID, err := AccessA(personalFirstKey, protectedFirstEntrance)
		if err != nil {
			return err
		}
		protectedCommsStruct, ok := userlib.DatastoreGet(commsChannelUUID)
		if !ok {
			return errors.New("access has been revoked or file does not exist in namespace")
		}
		fileKey, fileStructUUID, _, err = AccessCC(commsKey, protectedCommsStruct)
		if err != nil {
			return err
		}
	}
	protectedFile, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return errors.New("file does not exist")
	}
	fileLength, contentPtr, err := AccessFile(protectedFile, fileKey)
	if err != nil {
		return err
	}
	// add to content stuff
	var currentBlock int
	var overFlowStartingPt uuid.UUID
	newFileLength := fileLength + len(content)
	if fileLength%64 == 0 {
		//filled that last block completely
		currentBlock = (fileLength / 64) + 1 //currentBlock is 1 less the rounds of decryption because we use < instead of <=
	} else {
		//last block filled
		//ex 65 bytes of previous content, curr block = 1
		currentBlock = (fileLength / 64)
	}
	if currentBlock == 0 {
		overFlowStartingPt = contentPtr
	} else {
		overFlowStartingPt, err = GenerateNextUUID(contentPtr, int64(currentBlock))
		if err != nil {
			return err
		}
	}
	oldContent, err := GetFileContent(fileKey, fileLength, overFlowStartingPt)
	if err != nil {
		return err
	}
	content = append(oldContent, content...)

	err = SetFileContent(fileKey, overFlowStartingPt, len(content), content)
	if err != nil {
		return err
	}
	//update file length
	updatedProtectedFile, err := setNewFileLength(newFileLength, fileKey, protectedFile)
	if err != nil {
		return err
	}

	//reset new file struct with the updated length
	userlib.DatastoreSet(fileStructUUID, updatedProtectedFile)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	personalFirstKey, personalFirstUUID, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return nil, err
	}
	protectedFirstEntrance, ok := userlib.DatastoreGet(personalFirstUUID)
	if !ok {
		return nil, errors.New("file does not exist in your name space or you have been revoked")
	}
	owner, err := IsCC(protectedFirstEntrance, personalFirstKey)
	if err != nil {
		return nil, err
	}
	var fileKey []byte
	var fileStructUUID uuid.UUID
	if owner {
		//you are the owner result is a comms channel
		fileKey, fileStructUUID, _, err = AccessCC(personalFirstKey, protectedFirstEntrance)
		if err != nil {
			return nil, err
		}

	} else {
		// you are not the owner result is accepted struct
		ccKey, commsChannelUUID, err := AccessA(personalFirstKey, protectedFirstEntrance)
		if err != nil {
			return nil, err
		}
		protectedCC, ok := userlib.DatastoreGet(commsChannelUUID)
		if !ok {
			return nil, errors.New("access has been revoked or comms channel no loner exists")
		}
		fileKey, fileStructUUID, _, err = AccessCC(ccKey, protectedCC)
		if err != nil {
			return nil, err
		}
	}
	protectedFileStruct, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return nil, errors.New("could not access file")
	}
	fileLength, contentStart, err := AccessFile(protectedFileStruct, fileKey)
	if err != nil {
		return nil, err
	}
	content, err = GetFileContent(fileKey, fileLength, contentStart)
	if err != nil {
		return nil, err
	}
	return content, nil

}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	exist, err := CheckUserExistenceString(recipientUsername)
	if err != nil {
		return uuid.Nil, err
	}
	if !exist {
		return uuid.Nil, errors.New("that user doesn't exist")
	}
	// check existence in your name space
	personalFirstKey, personalFirstUUID, protectedFirst, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return uuid.Nil, errors.New("File does not exist in your name space")
	}
	_, recipientPublicKey, err := RestoreRSAPublic(recipientUsername)
	if err != nil {
		return uuid.Nil, err
	}
	protectedFirst, ok := userlib.DatastoreGet(personalFirstUUID)
	if !ok {
		return uuid.Nil, errors.New("File does not exist in your name round 2")
	}
	owner, err := IsCC(protectedFirst, personalFirstKey)
	if err != nil {
		return uuid.Nil, err
	}
	signatureKey, err := RestoreSignature(userdata.SignatureKey, userdata.hashedPasswordKDF)
	if err != nil {
		return uuid.Nil, err
	}
	var ccKey []byte
	var recipientCClocation uuid.UUID
	if owner {
		//within file space?
		CommunicationsChannelUUID := personalFirstUUID
		protectedCC, ok := userlib.DatastoreGet(CommunicationsChannelUUID)
		if !ok {
			return uuid.Nil, errors.New("Owner's CC issue")
		}
		//create a new copy of CC for the recipient
		recipientCClocation, protectedRecipientCC, tempccKey, err := CreateCopyCC(protectedCC, personalFirstKey, filename, userdata.username, recipientUsername)
		if err != nil {
			return uuid.Nil, err
		}
		ccKey = tempccKey
		//putting in the communications channel for the recipient
		userlib.DatastoreSet(recipientCClocation, protectedRecipientCC)
	} else {
		acceptedUUID := personalFirstUUID
		protectedA, ok := userlib.DatastoreGet(acceptedUUID)
		if !ok {
			return uuid.Nil, errors.New("You can't be sharing this it doesnt exist")
		}
		ccKey, recipientCClocation, err = AccessA(personalFirstKey, protectedA)
		if err != nil {
			return uuid.Nil, err
		}
	}
	protectedInvitation, InvitationUUID, err := Invite(signatureKey, recipientPublicKey, recipientCClocation, ccKey)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(InvitationUUID, protectedInvitation)

	return InvitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
