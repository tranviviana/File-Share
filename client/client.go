package client

// CS 161 Project 2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

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
	FileKey      []byte //randomly generated key which will change in revocation
	FileStruct   []byte //randomly generated UUID which will change in revocation
	SharingBytes []byte //random bytes to randomize comms locations and store shared username
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
	if err != nil {
		return nil, err
	}
	key = wholeKey[0:16]
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

func SetFileContent(fileKey []byte, contentUUID uuid.UUID, fileLength int, content []byte, currentRound int) (err error) {
	//64 block size
	start := currentRound
	currentUUID := contentUUID
	var roundsEncryption int
	if fileLength%64 == 0 {
		roundsEncryption = (fileLength / 64) + currentRound
	} else {
		roundsEncryption = (fileLength / 64) + 1 + currentRound
	}
	for currentRound < roundsEncryption {
		var contentSplice []byte
		if (currentRound+1)*64 > fileLength {
			contentSplice = content[((currentRound - start) * 64):]
		} else {
			contentSplice = content[((currentRound - start) * 64) : ((currentRound-start)+1)*64]
		}
		var contentBlock FileContent
		hardCodedText := "content encryption salt"
		encryptionContentKey, err := ConstructKey(hardCodedText, "could not encrypt content block", fileKey)
		if err != nil {
			return err
		}
		hardCodedText = "content MAC salt"
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

		hardCodedText = "content struct encryption salt"
		encryptionContentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return err
		}
		hardCodedText = "content struct mac salt"
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
		longerFile -= 1
	}
	return nil
}
func UpdateFileLength(newFileLength int64, oldFileLength int64, ptrStart uuid.UUID, fileKey []byte, protectedFile []byte) (updated int, new_protectedFile []byte, err error) {
	//new file length is shorter than old file length
	longerFile := oldFileLength / 64
	shorterFile := newFileLength / 64
	new_protectedFile = protectedFile
	if longerFile != shorterFile {
		updated = 1
		new_protectedFile, err = setNewFileLength(int(shorterFile), fileKey, protectedFile)
		if err != nil {
			return 2, nil, err
		}
	}
	for longerFile > shorterFile {
		deletableUUID, err := GenerateNextUUID(ptrStart, longerFile)
		if err != nil {
			return 2, nil, err
		}
		userlib.DatastoreDelete(deletableUUID)
		longerFile -= 1
	}
	return updated, new_protectedFile, nil
}
func GetFileContent(fileKey []byte, fileLength int, contentStart uuid.UUID, currentRound int) (content []byte, err error) {
	currentUUID := contentStart
	start := currentRound
	// Calculate the number of blocks needed
	var roundsDecryption int
	if fileLength%64 == 0 {
		roundsDecryption = fileLength / 64
	} else {
		roundsDecryption = (fileLength / 64) + 1
	}

	for currentRound < roundsDecryption {
		// Retrieve encrypted block from datastore
		encryptedBlock, exists := userlib.DatastoreGet(currentUUID)
		if !exists {
			return nil, errors.New("file block missing from datastore")
		}

		// Reconstruct encryption and MAC keys for this block
		hardCodedText := "content struct encryption salt"
		decryptionContentStructKey, err := ConstructKey(hardCodedText, "could not create encryption key for content struct", fileKey)
		if err != nil {
			return nil, err
		}
		hardCodedText = "content struct mac salt"
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
		hardCodedText = "content encryption salt"
		decryptionContentKey, err := ConstructKey(hardCodedText, "could not create encryption key for content", fileKey)
		if err != nil {
			return nil, err
		}

		hardCodedText = "content MAC salt"
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
	if start != 0 {
		//the case where we are appending
		content = content[:(fileLength - (fileLength/64)*64)]
	}

	return content, nil
}

/*-------------------Store File Content ---------------*/

/*--------------File is new----------*/
/*--------------First Check Point (Owner == CC struct) (Recipient == A Struct)-----*/
func GetKeyFileName(filename string, hashedPasswordKDF []byte, username []byte) (personalFirstKey []byte, personalFirstUUID uuid.UUID, protectedFilename []byte, err error) {
	//returns the communications key of the owner OR the accepted key of the recipient along with its uuid
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

	if len(personalFirstKey) != 16 {
		return nil, uuid.Nil, nil, errors.New("personalFirstKey wrong length")
	}
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
		return false, err
	}
	if CCAddress.FileKey != nil && CCAddress.FileStruct != nil && CCAddress.SharingBytes != nil {
		return true, nil
	}
	return false, nil
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
	encryptionAstruct, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for A struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macAstruct, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for A struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedAStruct, err = EncThenMac(encryptionAstruct, macAstruct, byteAstruct)
	if err != nil {
		return nil, err
	}
	return protectedAStruct, nil
}
func CreateNewCC(personalFirstKey []byte, randomCommsUUID []byte) (protectedNewCC []byte, RecipientUsernamesUUID uuid.UUID, err error) {
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
		return nil, uuid.Nil, err
	}

	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	protectedFileKey, err := EncThenMac(encryptionFileKey, macFileKey, fileKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	fileStructUUID := uuid.New()
	byteFileUUID, err := json.Marshal(fileStructUUID)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal random UUID to hide file")
	}
	encryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	protectedFileUUID, err := EncThenMac(encryptionFileUUID, macFileUUID, byteFileUUID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	usernameUUID, err := RestoreUsernamesUUID(personalFirstKey, randomCommsUUID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	RecipientUsernamesUUID = usernameUUID
	encryptionRandomCommsUUID, err := ConstructKey("encryption for random comms UUID", "could not create encryption key for the comms UUID", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macRandomCommsUUID, err := ConstructKey("mac for random comms", "could not create mac key for the comms UUID", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	protectedBaseCommsUUID, err := EncThenMac(encryptionRandomCommsUUID, macRandomCommsUUID, randomCommsUUID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	ownerCC.FileKey = protectedFileKey
	ownerCC.FileStruct = protectedFileUUID
	ownerCC.SharingBytes = protectedBaseCommsUUID //where the users comms channel will be but will be salted with their username and file name and stuff

	byteCC, err := json.Marshal(ownerCC)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal the owner's communication node")
	}
	encryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CC struct", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CC struct", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}

	protectedNewCC, err = EncThenMac(encryptionCCStructKey, macCCStructKey, byteCC)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return protectedNewCC, RecipientUsernamesUUID, nil
}
func UpdateCC(personalFirstKey []byte, fileKey []byte, fileUUID []byte, oldCC []byte) (protectedUpdatedCC []byte, err error) {
	decryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CC struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CC struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	byteCC, err := CheckAndDecrypt(oldCC, macCCStructKey, decryptionCCStructKey)
	if err != nil {
		return nil, err
	}
	var recipientCC CommunicationsChannel
	err = json.Unmarshal(byteCC, &recipientCC)
	if err != nil {
		return nil, errors.New("could not unmarshal communications struct")
	}
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
	encryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", personalFirstKey)
	if err != nil {
		return nil, err
	}
	protectedFileUUID, err := EncThenMac(encryptionFileUUID, macFileUUID, fileUUID)
	if err != nil {
		return nil, err
	}
	recipientCC.FileKey = protectedFileKey
	recipientCC.FileStruct = protectedFileUUID

	byteCC, err = json.Marshal(recipientCC)
	if err != nil {
		return nil, errors.New("could not marshal the owner's communication node")
	}
	encryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CC struct", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macCCStructKey, err = ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CC struct", personalFirstKey)
	if err != nil {
		return nil, err
	}

	protectedNewCC, err := EncThenMac(encryptionCCStructKey, macCCStructKey, byteCC)
	if err != nil {
		return nil, err
	}
	return protectedNewCC, nil

}
func AccessCC(ccKey []byte, protectedNewCC []byte) (fileKey []byte, fileStructUUID uuid.UUID, randomCommsUUID []byte, err error) {
	//ccKey for the owner is through getKeyFileName
	//ccKey for non-owners is through their accepted struct

	//unencrypt CC channel
	decryptionCCStructKey, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for CC struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	macCCStructKey, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for CC struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	byteCC, err := CheckAndDecrypt(protectedNewCC, macCCStructKey, decryptionCCStructKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	var ownerCC CommunicationsChannel
	err = json.Unmarshal(byteCC, &ownerCC)
	if err != nil {
		return nil, uuid.Nil, nil, errors.New("could not unmarshal communications struct")
	}
	//unencrypt and return the contents of the CC channel File UUID
	protectedFileUUID := ownerCC.FileStruct
	decryptionFileUUID, err := ConstructKey("encryption for file UUID", "could not created encryption key for the file UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	macFileUUID, err := ConstructKey("mac for file UUID", "could not create mac key for the fille UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	byteFileUUID, err := CheckAndDecrypt(protectedFileUUID, macFileUUID, decryptionFileUUID)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}

	err = json.Unmarshal(byteFileUUID, &fileStructUUID)
	if err != nil {
		return nil, uuid.Nil, nil, errors.New("could not unmarshal File uuid")
	}
	protectedBaseCommsUUID := ownerCC.SharingBytes
	decryptionRandomCommsUUID, err := ConstructKey("encryption for random comms UUID", "could not create encryption key for the comms UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	macRandomCommsUUID, err := ConstructKey("mac for random comms", "could not create mac key for the comms UUID", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	randomCommsUUID, err = CheckAndDecrypt(protectedBaseCommsUUID, macRandomCommsUUID, decryptionRandomCommsUUID)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	protectedFileKey := ownerCC.FileKey
	decryptionFileKey, err := ConstructKey("encryption for fileStruct", "could not create encryption key for file struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	macFileKey, err := ConstructKey("mac for fileStruct", "could not create mac key for file struct", ccKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	fileKey, err = CheckAndDecrypt(protectedFileKey, macFileKey, decryptionFileKey)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	return fileKey, fileStructUUID, randomCommsUUID, err
}

func AccessA(personalFirstKey []byte, protectedAstruct []byte) (CommsKey []byte, CommsChannel uuid.UUID, err error) {
	//getting the a struct
	decryptionAstruct, err := ConstructKey("communications channel/accept struct encryption key", "could not create encryption key for A struct", personalFirstKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	macAstruct, err := ConstructKey("communications channel/accept struct MAC key", "could not create MAC key for A struct", personalFirstKey)
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
	//error here with unmarshaling
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
func CreateSharedCCKey(filename string, username []byte, recipient string, randomCommsUUID []byte) (ccKey []byte, communicationLocation uuid.UUID, err error) {
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
	byteCollab = append(byteCollab, randomCommsUUID...)
	ccKey = userlib.Argon2Key(byteCollab, username, 16) //hashKDF off of this

	stringRandomCommsUUID := hex.EncodeToString(randomCommsUUID)
	byteNewLocation, err := ConstructKey(stringRandomCommsUUID, "could not generate a new uuid location", ccKey) //unique location for each user off of owners random bytes, and recipient info
	if err != nil {
		return nil, uuid.Nil, err
	}
	communicationLocation, err = uuid.FromBytes(byteNewLocation)
	if err != nil {
		return nil, uuid.Nil, errors.New("byte new location was not long enough")
	}
	return ccKey, communicationLocation, nil //reconstruct communicationLocation when revoking
}
func CreateCopyCC(protectedCC []byte, personalFirstKey []byte, filename string, username []byte, recipient string) (communicationLocation uuid.UUID, protectedRecipientCC []byte, ccKey []byte, err error) {
	// used by owner to copy their CC struct to share with a new user
	protectedCopied := make([]byte, len(protectedCC))
	_ = copy(protectedCopied, protectedCC)
	oGFileKey, oGfileStructUUID, oGRandomCommsUUID, err := AccessCC(personalFirstKey, protectedCopied)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	fileKey := make([]byte, len(oGFileKey))
	_ = copy(fileKey, oGFileKey)
	randomCommsUUID := make([]byte, len(oGRandomCommsUUID))
	_ = copy(randomCommsUUID, oGRandomCommsUUID)
	byteoGfileStructUUID, err := json.Marshal(oGfileStructUUID)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("file struct uuid marshalling")
	}
	byteFileStruct := make([]byte, len(byteoGfileStructUUID))
	_ = copy(byteFileStruct, byteoGfileStructUUID)
	var tempFileStruct uuid.UUID
	err = json.Unmarshal(byteFileStruct, &tempFileStruct)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("unmarshal file struct")
	}
	fileStructUUID := tempFileStruct
	oGccKey, oGcommunicationLocation, err := CreateSharedCCKey(filename, username, recipient, randomCommsUUID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	ccKey = make([]byte, len(oGccKey))
	_ = copy(ccKey, oGccKey)
	byteOgComm, err := json.Marshal(oGcommunicationLocation)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("marshal of comm location")
	}
	byteCommunicationLocation := make([]byte, len(byteOgComm))
	_ = copy(byteCommunicationLocation, byteOgComm)
	var tempCommLocation uuid.UUID
	err = json.Unmarshal(byteCommunicationLocation, &tempCommLocation)
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("unmarshal recipient uuid")
	}
	communicationLocation = tempCommLocation

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

	byteFileStruct, err = json.Marshal(fileStructUUID)
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
	byteRandomCommsUUID := make([]byte, 0)

	encryptionRandomCommsUUID, err := ConstructKey("encryption for random comms UUID", "could not create encryption key for the comms UUID", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	macRandomCommsUUID, err := ConstructKey("mac for random comms", "could not create mac key for the comms UUID", ccKey)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	protectedBaseCommsUUID, err := EncThenMac(encryptionRandomCommsUUID, macRandomCommsUUID, byteRandomCommsUUID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	//putting into the recipient's CC struct
	recipientCC.FileKey = protectedFileKey
	recipientCC.FileStruct = protectedFileUUID
	recipientCC.SharingBytes = protectedBaseCommsUUID

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
	return communicationLocation, protectedRecipientCC, ccKey, nil //communication location will be reconstructed when revoking users
}

func Invite(signature userlib.PrivateKeyType, recipientPKE userlib.PKEEncKey, communicationLocation uuid.UUID, ccKey []byte) (protectedInvitation []byte, invitationUUID uuid.UUID, err error) {
	//(signatureKey, recipientPublicKey, recipientCClocation, ccKey)
	/*type Invitation struct {
		//this struct is DELETED after accept invitation
		CommsKey     []byte //key Argon2key(filename,owner,direct recipient) for the communications channel --> marshaled --> RSA Encrypted --> Rsa Signed
		CommsChannel []byte //UUID of the commschannel RSA encrypted and signed
	}*/
	//encrypting comms key and signing it len ?
	encryptedCCKey, err := userlib.PKEEnc(recipientPKE, ccKey)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not encrypt ccKey")
	}
	//signature len 256
	signatureCCKey, err := userlib.DSSign(signature, encryptedCCKey)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not accurately sign message")
	}
	protectedCCKey := append(encryptedCCKey, signatureCCKey...)
	//encrypting comms channel uuid
	byteCC, err := json.Marshal(communicationLocation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshal comms channel uuid")
	}
	encryptedCC, err := userlib.PKEEnc(recipientPKE, byteCC)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not encrypt the communications channel")
	}
	signatureCC, err := userlib.DSSign(signature, encryptedCC)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not sign the communicaton channel")
	}
	protectedCommsChannel := append(encryptedCC, signatureCC...)

	var invitation Invitation
	invitation.CommsChannel = protectedCommsChannel
	invitation.CommsKey = protectedCCKey

	byteInvitation, err := json.Marshal(invitation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not marshall invitation")
	}

	//hybrid encryption (encrypt random symmetric key to encrypt actual data)
	//generate random aes key and iv to encrypt invitation struct
	aesKey := userlib.RandomBytes(16)
	macAESKey, err := ConstructKey("mac key for byte invitation", "could not create a mac key for the byte invitation", aesKey)
	if err != nil {
		return nil, uuid.Nil, err
	}
	symProtectedInvitation, err := EncThenMac(aesKey, macAESKey, byteInvitation)
	if err != nil {
		return nil, uuid.Nil, err
	}

	//rsa generates public key pair, encrypting aeskey with recipient public key
	encryptedAESKey, err := userlib.PKEEnc(recipientPKE, aesKey)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not encrypt the AES key with RSA")
	}

	//add aes and invitation together for final protected invitation symEncryptedinvitation (length ?) + encryptedAESKey (length 256)
	encryptedByteInvitation := append(symProtectedInvitation, encryptedAESKey...)

	//encrypt the invitation
	signatureInvitation, err := userlib.DSSign(signature, encryptedByteInvitation)
	if err != nil {
		return nil, uuid.Nil, errors.New("could not sign the invitation struct")
	}
	//add final protected invitation symEncryptedinvitation (length ?) + encryptedAESKey (length 256) + signatureInvitation (length 256)
	protectedInvitation = append(encryptedByteInvitation, signatureInvitation...)

	invitationUUID = uuid.New()
	return protectedInvitation, invitationUUID, nil
}

func DecryptInvitation(privateKey userlib.PrivateKeyType, protectedInvitation []byte, senderUsername string, personalFirstKey []byte) (protectedAStruct []byte, err error) {
	//delete invitation!!!
	//decrypt invitation
	_, verificationKey, err := RestoreVERIFICATIONPublic(senderUsername)
	if err != nil {
		return nil, err
	}

	//check size to prepare for slicing into symEncryptedinvitation (length ?) + encryptedAESKey (length 256) + signatureInvitation (length 256)
	if len(protectedInvitation) < 512 {
		return nil, errors.New("invitation struct too small ")
	}
	//slice out signature from protected invitation [-256:]
	signatureInvitation := protectedInvitation[len(protectedInvitation)-256:]
	//slice out aes key from protected invitation [-512:-256]
	encryptedAESKey := protectedInvitation[len(protectedInvitation)-512 : len(protectedInvitation)-256]
	//slice out encyrpted invitation from protected invtation[:-512]
	symProtectedInvitation := protectedInvitation[:len(protectedInvitation)-512]
	encryptedByteInvitation := append(symProtectedInvitation, encryptedAESKey...)

	//verify signatureInvitation on the message encryptedByteInvitation (AES + encrypted Invitation) using verification key
	err = userlib.DSVerify(verificationKey, encryptedByteInvitation, signatureInvitation)
	if err != nil {
		return nil, errors.New("verification failed, cannot trust that this is the right info")
	}

	//symenc & rsa hybrid decryption
	//uses rsa private key to decrypt aes
	aesKey, err := userlib.PKEDec(privateKey, encryptedAESKey)
	if err != nil {
		return nil, errors.New("could not decrypt the AES key with RSA")
	}
	//uses decrypted aes to symmetric decrypt encryptedByteInvitation
	macAESKey, err := ConstructKey("mac key for byte invitation", "could not create a mac key for the byte invitation", aesKey)
	if err != nil {
		return nil, err
	}
	byteInvitation, err := CheckAndDecrypt(symProtectedInvitation, macAESKey, aesKey)
	if err != nil {
		return nil, err
	}

	var invitation Invitation
	err = json.Unmarshal(byteInvitation, &invitation)
	if err != nil {
		return nil, errors.New("could not unmarshal byte invitation ")
	}
	//decrypting the componenets
	protectedCommsChannel := invitation.CommsChannel
	//cc location
	if len(protectedCommsChannel) < 512 {
		return nil, errors.New("comms channel struct too small ")
	}
	encryptedCC := protectedCommsChannel[:256]
	signatureCC := protectedCommsChannel[256:]
	err = userlib.DSVerify(verificationKey, encryptedCC, signatureCC)
	if err != nil {
		return nil, errors.New("verification failed in retrieving location, cannot trust")
	}
	byteCC, err := userlib.PKEDec(privateKey, encryptedCC)
	if err != nil {
		return nil, errors.New("problem with decrypting CC location")
	}
	var communicationLocation uuid.UUID
	err = json.Unmarshal(byteCC, &communicationLocation)
	if err != nil {
		return nil, errors.New("could not unmarshal CC location")
	}
	//cc key
	protectedCCKey := invitation.CommsKey
	if len(protectedCCKey) < 256 {
		return nil, errors.New("protected CC key too small ")
	}
	encryptedCCKey := protectedCCKey[:len(protectedCCKey)-256]
	signatureCCKey := protectedCCKey[len(protectedCCKey)-256:]
	err = userlib.DSVerify(verificationKey, encryptedCCKey, signatureCCKey)
	if err != nil {
		return nil, errors.New("verification failed in retrieving key, cannot trust")
	}
	ccKey, err := userlib.PKEDec(privateKey, encryptedCCKey)
	if err != nil {
		return nil, errors.New("could not decrypt CC key")
	}
	if len(ccKey) != 16 {
		return nil, errors.New("recovered cckey wrong length")
	}
	//type problem here? jk cuz ACCESS A decrypts the byte cc and unmarshals it for us
	protectedAStruct, err = CreateNewA(ccKey, byteCC, personalFirstKey)
	if err != nil {
		return nil, err
	}

	return protectedAStruct, nil
}
func ProtectUsernamesEmpty(usernames [][]byte, personalFirstKey []byte) (protectedUsernames []byte, err error) {
	byteUsername, err := json.Marshal(usernames)
	if err != nil {
		return nil, errors.New("could not marshal changed usernames")
	}
	encryptionKeyUsernames, err := ConstructKey("encryption key username list in data store", "could not create a unique encryption key usernames", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macKeyUsernames, err := ConstructKey("mac key username list in DS", "could not create a unique mac key usernames", personalFirstKey)
	if err != nil {
		return nil, err

	}
	protectedUsernames, err = EncThenMac(encryptionKeyUsernames, macKeyUsernames, byteUsername)
	if err != nil {
		return nil, err
	}
	return protectedUsernames, err
}
func ProtectUsernames(protectedUsernames []byte, addedUsername string, personalFirstKey []byte) (protectedAddedUsernames []byte, err error) {
	//add username to protected list of users this file is shared to
	//marshal username string
	byteAddedUsername, err := json.Marshal(addedUsername)
	if err != nil {
		return nil, errors.New("ProtectUsernames: could not marshal addedUsername")
	}
	//decrypts usernames list from protected usernames list and add marshalled username
	usernames, err := RestoreUsernames(protectedUsernames, personalFirstKey)
	if err != nil {
		return nil, err
	}
	usernames = append(usernames, [][]byte{byteAddedUsername}...)

	byteUsername, err := json.Marshal(usernames)
	if err != nil {
		return nil, errors.New("could not marshal usernames")
	}
	//encrypt & mac list of username []byte again
	encryptionKeyUsernames, err := ConstructKey("encryption key username list in data store", "could not create a unique encryption key usernames", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macKeyUsernames, err := ConstructKey("mac key username list in DS", "could not create a unique mac key usernames", personalFirstKey)
	if err != nil {
		return nil, err

	}
	protectedAddedUsernames, err = EncThenMac(encryptionKeyUsernames, macKeyUsernames, byteUsername)
	if err != nil {
		return nil, err
	}
	return protectedAddedUsernames, err
}
func RestoreUsernames(protectedUsernames []byte, personalFirstKey []byte) (usernames [][]byte, err error) {
	//decrypts usernames list from protectedUsernames
	decryptionKeyUsernames, err := ConstructKey("encryption key username list in data store", "could not create a unique encryption key usernames", personalFirstKey)
	if err != nil {
		return nil, err
	}
	macKeyUsernames, err := ConstructKey("mac key username list in DS", "could not create a unique mac key usernames", personalFirstKey)
	if err != nil {
		return nil, err
	}
	byteUsername, err := CheckAndDecrypt(protectedUsernames, macKeyUsernames, decryptionKeyUsernames)
	if err != nil {
		return nil, err
	}
	var doubleUsernames [][]byte
	err = json.Unmarshal(byteUsername, &doubleUsernames)
	if err != nil {
		return nil, errors.New("could not unmarshal list")
	}
	usernames = doubleUsernames
	return usernames, nil
}
func RestoreUsernamesUUID(personalFirstKey []byte, sharingBytes []byte) (usernamesUUID uuid.UUID, err error) {
	byteRandomCommsUUIDKey, err := ConstructKey("sharedUser uuidKey", "could not create key for storing usernames", personalFirstKey)
	if err != nil {
		return uuid.Nil, err
	}
	byteUsernameUUID := userlib.Argon2Key(byteRandomCommsUUIDKey, sharingBytes, 16) //create uuid here that maps to usernames
	usernameUUID, err := uuid.FromBytes(byteUsernameUUID)
	if err != nil {
		return uuid.Nil, errors.New("could not convert the fancy randoms to a username uuid")
	}

	return usernameUUID, nil
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
	if len(personalFirstKey) < 16 {
		return errors.New("personalFirstKey too short")
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
			// owner's file and already exists
			tempFileKey, tempFileStructUUID, _, err := AccessCC(personalFirstKey, protectedFirstEntrance)
			if err != nil {
				return err
			}
			fileKey = tempFileKey
			fileStructUUID = tempFileStructUUID
		} else {
			// not owners file but already exists
			commsKey, commsUUID, err := AccessA(personalFirstKey, protectedFirstEntrance)
			if err != nil {
				return err
			}
			protectedRCC, ok := userlib.DatastoreGet(commsUUID)
			if !ok {
				return errors.New("File does not exist or you have been revoked, stop accessing me")
			}
			tempFileKey, tempFileStructUUID, _, err := AccessCC(commsKey, protectedRCC)
			if err != nil {
				return err
			}
			fileKey = tempFileKey
			fileStructUUID = tempFileStructUUID
		}
		protectedFile, ok := userlib.DatastoreGet(fileStructUUID)
		if !ok {
			return errors.New("error retrieving your file")
		}
		oldFileLength, contentStart, err := AccessFile(protectedFile, fileKey)
		if err != nil {
			return err
		}
		updated, updateProtectedFile, err := UpdateFileLength(int64(len(content)), int64(oldFileLength), contentStart, fileKey, protectedFile)
		if err != nil {
			return err
		}
		if updated == 1 {
			userlib.DatastoreSet(fileStructUUID, updateProtectedFile)
		}
		err = SetFileContent(fileKey, contentStart, len(content), content, 0)
		if err != nil {
			return err
		}
		return nil
	}
	// doesnt exist yet
	//put an empty array into data store to represent all the usernames
	//new CC is the OWNERS cc
	randomCommsUUID := userlib.RandomBytes(16)
	protectedNewCC, recipientsUsernameUUID, err := CreateNewCC(personalFirstKey, randomCommsUUID)
	if err != nil {
		return err
	}
	//putting the created recipients Usernames into datastore
	usernameList := make([][]byte, 0)
	encryptionKeyUsernames, err := ConstructKey("encryption key username list in data store", "could not create a unique encryption key usernames", personalFirstKey)
	if err != nil {
		return err
	}
	singleByteUsername, err := json.Marshal(usernameList)
	if err != nil {
		return errors.New("could not marshal username list")
	}
	macKeyUsernames, err := ConstructKey("mac key username list in DS", "could not create a unique mac key usernames", personalFirstKey)
	if err != nil {
		return err

	}
	protectedUsernames, err := EncThenMac(encryptionKeyUsernames, macKeyUsernames, singleByteUsername)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(recipientsUsernameUUID, protectedUsernames)
	//putting the owner's CC into data store for future access
	userlib.DatastoreSet(personalFirstUUID, protectedNewCC)
	fileKey, fileStructUUID, _, err := AccessCC(personalFirstKey, protectedNewCC)
	if err != nil {
		return err
	}
	protectedFileStruct, err := CreateNewFile(fileKey, len(content))
	if err != nil {
		return err
	}
	//putting the file into data store with the file struct and file uuid
	userlib.DatastoreSet(fileStructUUID, protectedFileStruct)
	_, contentStart, err := AccessFile(protectedFileStruct, fileKey)
	if err != nil {
		return err
	}
	err = SetFileContent(fileKey, contentStart, len(content), content, 0)
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
	if len(personalFirstKey) < 16 {
		return errors.New("personalFirstKey too short")
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
		tempFileKey, tempFileStructUUID, _, err := AccessCC(personalFirstKey, protectedFirstEntrance)
		if err != nil {
			return err
		}
		fileKey = tempFileKey
		fileStructUUID = tempFileStructUUID
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
		tempFileKey, tempFileStructUUID, _, err := AccessCC(commsKey, protectedCommsStruct)
		if err != nil {
			return err
		}
		fileKey = tempFileKey
		fileStructUUID = tempFileStructUUID
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
	//var overFlowStartingPt uuid.UUID
	newFileLength := fileLength + len(content)
	if fileLength%64 == 0 {
		//filled that last block completely
		currentBlock = (fileLength / 64) + 1 //currentBlock is 1 less the rounds of decryption because we use < instead of <=
	} else {
		//last block filled
		//ex 65 bytes of previous content, curr block = 1
		currentBlock = (fileLength / 64)
		oldContent, err := GetFileContent(fileKey, fileLength, contentPtr, currentBlock)
		if err != nil {
			return err
		}
		content = append(oldContent, content...)
	}
	err = SetFileContent(fileKey, contentPtr, len(content), content, currentBlock)
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
	if len(personalFirstKey) < 16 {
		return nil, errors.New("personalFirstKey too short")
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
		tempFileKey, tempFileStructUUID, _, err := AccessCC(personalFirstKey, protectedFirstEntrance)
		if err != nil {
			return nil, err
		}
		fileKey = tempFileKey
		fileStructUUID = tempFileStructUUID

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
		tempFileKey, tempFileStructUUID, _, err := AccessCC(ccKey, protectedCC)
		if err != nil {
			return nil, err
		}
		fileKey = tempFileKey
		fileStructUUID = tempFileStructUUID
	}
	protectedFileStruct, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return nil, errors.New("could not access file")
	}
	fileLength, contentStart, err := AccessFile(protectedFileStruct, fileKey)
	if err != nil {
		return nil, err
	}
	content, err = GetFileContent(fileKey, fileLength, contentStart, 0)
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
	personalFirstKey, personalFirstUUID, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return uuid.Nil, errors.New("File does not exist in your name space")
	}
	if len(personalFirstKey) < 16 {
		return uuid.Nil, errors.New("personalFirstKey too short")
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
		protectedCC := make([]byte, len(protectedFirst))
		_ = copy(protectedCC, protectedFirst)
		//used to access username list in datasotre
		_, _, byteSharingBytes, err := AccessCC(personalFirstKey, protectedCC)
		if err != nil {
			return uuid.Nil, err
		}
		//create a new copy of CC for the recipient
		tempRecipientCClocation, protectedRecipientCC, tempccKey, err := CreateCopyCC(protectedCC, personalFirstKey, filename, userdata.username, recipientUsername)
		if err != nil {
			return uuid.Nil, err
		}
		_ = copy(protectedFirst, protectedCC)
		recipientCClocation = tempRecipientCClocation
		ccKey = tempccKey
		//userlib.DatastoreGet(recipientCClocation) dont have to check create invitation on someone that already has access/ has had access in past
		//putting new communications channel in datastore
		userlib.DatastoreSet(recipientCClocation, protectedRecipientCC)
		//adding the username into datastore
		usernameUUID, err := RestoreUsernamesUUID(personalFirstKey, byteSharingBytes)
		if err != nil {
			return uuid.Nil, err
		}
		protectedUsernameList, ok := userlib.DatastoreGet(usernameUUID)
		if !ok {
			return uuid.Nil, errors.New("could not retrieve username list")
		}
		reprotectedUsername, err := ProtectUsernames(protectedUsernameList, recipientUsername, personalFirstKey)
		if err != nil {
			return uuid.Nil, err
		}
		// added the username back in
		userlib.DatastoreSet(usernameUUID, reprotectedUsername)
		//reversible invitation UUID
		invitationKey, err := ConstructKey("invitation variation"+recipientUsername, "could not construct key for invitation ", byteSharingBytes)
		if err != nil {
			return uuid.Nil, err
		}
		invitationUUID, err := uuid.FromBytes(invitationKey)
		if err != nil {
			return uuid.Nil, errors.New("could not make invitation uuid")
		}
		protectedInvitation, _, err := Invite(signatureKey, recipientPublicKey, recipientCClocation, ccKey)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(invitationUUID, protectedInvitation)
		return invitationUUID, nil

	} else {
		acceptedUUID := personalFirstUUID
		protectedA, ok := userlib.DatastoreGet(acceptedUUID)
		if !ok {
			return uuid.Nil, errors.New("you can't be sharing this it doesnt exist")
		}
		tempccKey, tempRecipientCClocation, err := AccessA(personalFirstKey, protectedA)
		if err != nil {
			return uuid.Nil, err
		}
		ccKey = tempccKey
		//create new invitation not from the owner
		//putting that invitation into name space and returning that for the person to use
		recipientCClocation = tempRecipientCClocation
		protectedInvitation, invitationUUID, err := Invite(signatureKey, recipientPublicKey, recipientCClocation, ccKey)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(invitationUUID, protectedInvitation)
		return invitationUUID, nil
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if invitationPtr == uuid.Nil {
		return errors.New("damaged uuid")
	}
	exist, err := CheckUserExistenceString(senderUsername)
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("user does not exist")
	}
	protectedInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation no longer exists")
	}
	privateKey, err := RestorePrivateKey(userdata.PrivateRsaKey, userdata.hashedPasswordKDF)
	if err != nil {
		return err
	}
	personalFirstKey, personalFirstUUID, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return err
	}
	//checking that file name does not already exist in name space
	_, ok = userlib.DatastoreGet(personalFirstUUID)
	if ok {
		return errors.New("a file already exists in that name space")
	}
	if len(personalFirstKey) < 16 {
		return errors.New("personalFirstKey too short")
	}
	protectedAStruct, err := DecryptInvitation(privateKey, protectedInvitation, senderUsername, personalFirstKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(personalFirstUUID, protectedAStruct)
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	exist, err := CheckUserExistenceString(recipientUsername)
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("that user does not even exist")
	}
	personalFirstKey, personalFirstUUID, _, err := GetKeyFileName(filename, userdata.hashedPasswordKDF, userdata.username)
	if err != nil {
		return err
	}
	if len(personalFirstKey) < 16 {
		return errors.New("personalFirstKey too short")
	}
	protectedCCA, ok := userlib.DatastoreGet(personalFirstUUID)
	if !ok {
		return errors.New("file not in name space")
	}
	owner, err := IsCC(protectedCCA, personalFirstKey)
	if err != nil {
		return err
	}
	if !owner {
		return errors.New("cannot revoke if you are not the owner you silly butt")
	}
	_, _, randomCommsUUID, err := AccessCC(personalFirstKey, protectedCCA)
	if err != nil {
		return err
	}
	usernamesUUID, err := RestoreUsernamesUUID(personalFirstKey, randomCommsUUID)
	if err != nil {
		return err
	}
	protectedUsernames, ok := userlib.DatastoreGet(usernamesUUID)
	if !ok {
		return errors.New("problem retrieving shared users")
	}
	usernames, err := RestoreUsernames(protectedUsernames, personalFirstKey)
	if err != nil {
		return err
	}
	//converting username to bytes to check its existence in shared people
	revokedUser, err := json.Marshal(recipientUsername)
	if err != nil {
		return errors.New("could not marshal revoked user")
	}
	var index = -1
	for i, username := range usernames {
		if bytes.Equal(username, revokedUser) {
			// Return the index when the user is found
			index = 1
			if (i + 1) < len(usernames) {
				usernames = append(usernames[:i], usernames[i+1:]...)
			} else {
				usernames = usernames[:i]
			}
			_, revokedUsersUUID, err := CreateSharedCCKey(filename, userdata.username, recipientUsername, randomCommsUUID)
			if err != nil {
				return err
			}
			//removing the revoked user's node and everyone that follows it ...
			userlib.DatastoreDelete(revokedUsersUUID)
		} else {
			i++
		}
	}
	if index == -1 {
		return errors.New("file wasn't shared with user")
	}
	//case where the person was given an invitation and hasnt accepted yet

	invitationKey, err := ConstructKey("invitation variation"+recipientUsername, "could not construct key for invitation ", randomCommsUUID)
	if err != nil {
		return err
	}
	invitationUUID, err := uuid.FromBytes(invitationKey)
	if err != nil {
		return errors.New("could not make invitation uuid")
	}
	userlib.DatastoreDelete(invitationUUID)

	// updating the usernames list
	//put the usernames back in
	protectedDoubleUsernames, err := ProtectUsernamesEmpty(usernames, personalFirstKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(usernamesUUID, protectedDoubleUsernames)

	//construct get all of the old content and delete all of the old uuid
	ownerCC := protectedCCA
	fileKey, fileStructUUID, randomCommsUUID, err := AccessCC(personalFirstKey, ownerCC)
	if err != nil {
		return err
	}
	// getting content pointer
	protectedFileStruct, ok := userlib.DatastoreGet(fileStructUUID)
	if !ok {
		return errors.New("filestruct doesnt exist")
	}
	fileLength, contentPtr, err := AccessFile(protectedFileStruct, fileKey)
	if err != nil {
		return err
	}
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	//deleting old content blocks
	err = RestoreSmallerFile(0, int64(fileLength), contentPtr)
	if err != nil {
		return err
	}
	//easier to just reset the owners CC then to go into it, change it, and then load it in again
	// creates a new file uuid
	//gonna overwrite the one in datastore
	protectedNewCC, _, err := CreateNewCC(personalFirstKey, randomCommsUUID)
	if err != nil {
		return err
	}
	newFileKey, newFileUUID, _, err := AccessCC(personalFirstKey, protectedNewCC)
	if err != nil {
		return err
	}
	protectedNewFile, err := CreateNewFile(newFileKey, len(content))
	if err != nil {
		return err
	}

	_, newContentPtr, err := AccessFile(protectedNewFile, newFileKey)
	if err != nil {
		return err
	}
	//putting the file contents in
	err = SetFileContent(newFileKey, newContentPtr, len(content), content, 0)
	if err != nil {
		return err
	}
	//putting new owner cc in
	userlib.DatastoreSet(personalFirstUUID, protectedNewCC)
	// putting the new file in
	userlib.DatastoreSet(newFileUUID, protectedNewFile)
	// deleting old file location
	userlib.DatastoreDelete(fileStructUUID)

	// update the new comms channels
	for _, username := range usernames {
		var stringUsername string
		err := json.Unmarshal(username, &stringUsername)
		if err != nil {
			return errors.New("could not unmarshal username")
		}
		sharedKey, recipientUUID, err := CreateSharedCCKey(filename, userdata.username, stringUsername, randomCommsUUID)
		if err != nil {
			return err
		}
		protectedRecipientCC, ok := userlib.DatastoreGet(recipientUUID)
		if !ok {
			return errors.New("recipient no exist")
		}
		byteNewFileUUID, err := json.Marshal(newFileUUID)
		if err != nil {
			return errors.New("could not marshal new file uuid")
		}
		newRecipientCC, err := UpdateCC(sharedKey, newFileKey, byteNewFileUUID, protectedRecipientCC)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(recipientUUID, newRecipientCC)
	}

	return nil
}
