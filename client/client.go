package client

// CS 161 Project 2

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	//"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
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
	Owner      bool   //value for owner to know they are owner 1 means they are owner 0 if they are not the owner
	FileKey    []byte //randomly generated key which will change in revocation
	FileStruct []byte //randomly generated UUID which will change in revocation
	SharedWith []byte //recipients Username
}
type Accepted struct {
	Owner        bool   //value for owner to know they are owner 1 means they are owner 0 if they are not the owner
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
func RestoreRSAPublic(username string) (PkeyOnKeystore string, publicKey userlib.PublicKeyType, err error) {
	//returns the user's RSA key value pair in key store
	//marshal the username and hashkdf inut text
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return PkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not marshal username")
	}
	hardCodedText, err := json.Marshal("KeyStore RSA public key")
	if err != nil {
		return PkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not marshal hard coded text for RSA")
	}
	keyStoreKeyBytes, err := userlib.HashKDF(hardCodedText[:16], byteUsername)
	if err != nil {
		return PkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not hash username")
	}
	jsonKeyStoreBytes, err := json.Marshal(keyStoreKeyBytes)
	if err != nil {
		return PkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not marshal keyStoreByte to a json readable")
	}
	var keyStoreKey string
	err = json.Unmarshal(jsonKeyStoreBytes, &keyStoreKey)
	if err != nil {
		return PkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not unmarshal to convert bytes to a string")
	}
	//find unique hash corresponding RSA key value pair
	RSAPublicKey, ok := userlib.KeystoreGet(keyStoreKey)
	if !ok {
		return PkeyOnKeystore, userlib.PublicKeyType{}, errors.New("no RSA Public key found for username")
	}
	return keyStoreKey, RSAPublicKey, nil
}
func RestoreVERIFICATIONPublic(username string) (VkeyOnKeystore string, verificationKey userlib.PublicKeyType, err error) {
	//returns key value pair of user's public verification key
	//marshal the username and hashkdf input text
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not marshal username")
	}
	hardCodedText, err := json.Marshal("KeyStore Signature and Verification")
	if err != nil {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not marshal hard coded text for Signature and Verification")
	}
	tempKeyStoreBytes, err := userlib.HashKDF(hardCodedText[:16], byteUsername)
	if err != nil {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not hashKDF once for Signature and Verification")
	}
	//hash again for the verification key
	keyStoreKeyBytes, err := userlib.HashKDF(tempKeyStoreBytes[:16], byteUsername)
	if err != nil {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not hashKDF twice for Signature and Verification")
	}
	//marshal and unmarshal the double hashed user
	jsonKeyStoreKey, err := json.Marshal(keyStoreKeyBytes)
	if err != nil {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not marshal keyStoreByte to a json readable")
	}
	var keyStoreKey string
	err = json.Unmarshal(jsonKeyStoreKey, &keyStoreKey)
	if err != nil {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("could not unmarshal to convert bytes to a string")
	}
	//find its corresponding unique verification key in keystore
	verificationKey, ok := userlib.KeystoreGet(keyStoreKey)
	if !ok {
		return VkeyOnKeystore, userlib.PublicKeyType{}, errors.New("no verification key found for username")
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

/* ----------- END Helper Functions ---------*/
/* ----------- Fill Section Functions -------*/
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
	/*storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(storageKey, contentBytes) */
	return
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

/* ----------- END Fill Section Functions -------*/
