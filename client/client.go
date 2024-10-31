package client

//Default to the marshaled version of object

// CS 161 Project 2

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	"errors"

	// Optional.
	_ "strconv"
)

/*------------------------STRUCT SECTION ---------------------------*/
type User struct {
	//simply hashed
	username       []byte
	hashedpassword []byte
	PublicKey      userlib.PKEEncKey
	Verification   userlib.DSVerifyKey

	//HashKDF Protected
	PrivateKey   []byte
	SignatureKey []byte
	Files        map[string]uuid.UUID
	FileToUsers  map[string]uuid.UUID //file to Communicationstree struct this and ^ should have same filenames ultimately
	SharedFiles  map[string]uuid.UUID //filename to uuid of communications channel (when they are revoked they wont see any thing they can use in the comms channel --> can't access)
}

type CommunicationsTree struct {
	//only owner has access to this
	CurrentKey      []byte //file key hidden again because of argon2key of user specifically
	AccessibleUsers []byte
}
type File struct {
	CommChannel        userlib.UUID
	FileContentPointer userlib.UUID //randomized and then do counter to hashKDF and get fileContentStruct
	FileLength         uint
}
type FileContent struct {
	BlockEncrypted string
}
type CommunicationsChannel struct {
	FileAddress []userlib.UUID //RSA Encrypted with user symmetric key in it when a user shares, they share with same symmetric key so you can revoke thorugh finding all those keys and removing
	SharedWith  []userlib.UUID // each person that accepts can edit this tree?
}

/*need to flush store and share file revocation situation*/

/*---------------------------Helper Functions-------------------------*/
func UserRSAKeys(hashedUsername []byte, hashedPassword []byte) (publicKey userlib.PKEEncKey, structRSAPrivateKey []byte, err error) {
	//generates RSA keys -> puts into key store -> and returns encrypted and maced private key
	//KEY STORE TYPE DEFINITION
	//input marshaled hashedUsername and hashed Password, output public and private key

	var stringHashedUsername string

	err = json.Unmarshal(hashedUsername, &stringHashedUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not unmarshal hashed username")
	}

	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not generate RSA keys")
	}

	//putting RSA public key into keystore to prevent tampering
	err = userlib.KeystoreSet(stringHashedUsername, publicKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not keystore set the public key")
	}

	//setting up enc and mac keys
	encryptionKeyPrivateEncryption, err := ConstructKey("RSA Private Key Encryption Key", "could not create key for RSA key encryption", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("encryption key for RSA private could not be made")
	}

	macKeyPrivate, err := ConstructKey("RSA MAC Key", "could not create key for RSA MAC Tag", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("mac key for RSA private key could not be made")
	}

	bytePrivateKey, err := json.Marshal(privateKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not marshal private key properly")
	}

	structRSAPrivateKey, err = EncThenMac(encryptionKeyPrivateEncryption, macKeyPrivate, bytePrivateKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not concatenate both mac to encryption in RSA PRIVATE KEY ")
	}

	return publicKey, structRSAPrivateKey, nil
}
func EncThenMac(encryptionKey []byte, macKey []byte, objectHidden []byte) (macEncryptedObject []byte, err error) {
	//could return error if the original object are ///////////////////////
	//pass in the MARSHALED objects get back an encrypted and mac object

	IV := userlib.RandomBytes(16)
	//MAC(ENC(RSAprivateKey))
	//convert to byte
	encryptedObject := userlib.SymEnc(encryptionKey, IV, objectHidden)

	//error userlib.Hash(macKey) need to be 16 bytes
	tagEncryptedObject, err := userlib.HMACEval(macKey, encryptedObject)
	if err != nil {
		return nil, errors.New("could not generate MAC tag over hidden object")
	}
	//full encrypted and mac tagged RSA private key
	macEncryptedObject = append(tagEncryptedObject, encryptedObject...)
	return macEncryptedObject, nil
}
func UserSignatureKeys(hashedUsername []byte, hashedPassword []byte) (verificationKey userlib.DSVerifyKey, structSignatureKey []byte, err error) {
	//generates signature keys -> puts into key store -> and returns encrypted and maced private key

	//since keystore takes in unique hashes, this section up to ** is double hashing the original stuff to put into key store
	var hashedOnceByteUsername []byte

	err = json.Unmarshal(hashedUsername, &hashedOnceByteUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not unmarshal hashed username")
	}
	//hashing the unmarshaled byte first
	hashedTwiceByteUsername := userlib.Hash(hashedOnceByteUsername)
	doubleHashedUsername, err := json.Marshal(hashedTwiceByteUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not marshal double hash")
	}
	//*
	//convert to string to put into public key
	var stringDoubleHashUsername string
	err = json.Unmarshal(doubleHashedUsername, &stringDoubleHashUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not unmarshal hashed username")
	}

	signingKey, verificationKey, err := userlib.DSKeyGen()
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not generate signature Keys")
	}
	err = userlib.KeystoreSet(stringDoubleHashUsername, verificationKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not keystore set the signature public key")
	}

	encryptionKeySignature, err := ConstructKey("RSA Digital Signature Encryption Key", "could not HASHKDF key for Signature encryption", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not create encryption key for signature")
	}

	macKeySignature, err := ConstructKey("RSA Digital Signature Mac Key", "could not HASHKDF mac for Signature Tag", hashedPassword)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not create MAC key for signature")
	}

	byteSigningKey, err := json.Marshal(signingKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("coult not marshal signature key before mac and enc")
	}
	structSignatureKey, err = EncThenMac(encryptionKeySignature, macKeySignature, byteSigningKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not concatenate both mac to encryption in SIGNING")
	}
	return verificationKey, structSignatureKey, nil
}
func OriginalStruct(hashedUsername []byte, hashedPassword []byte) (originalUser *User, err error) {
	//since each getuser creates a local User struct, this function obtains a pointer to the original user struct
	//getting orginal struct
	byteHardCodedText, err := json.Marshal("Hard-coded temp fix to hash length")
	if err != nil {
		return nil, errors.New("couldn't marshal the hashed username ")
	}
	uuidUsername := userlib.Argon2Key(userlib.Hash(hashedUsername), byteHardCodedText, 16)
	createdUUID, err := uuid.FromBytes(uuidUsername)
	if err != nil {
		return nil, errors.New("could not reconstruct uuid to update changes")
	}
	macEncByteStruct, ok := userlib.DatastoreGet(createdUUID)
	if !ok {
		return nil, errors.New("created UUID not in datastore to update changes")
	}
	//checking for tampering on original file
	//slicing current bytes
	tagEncryptedStruct := macEncByteStruct[:64]
	encryptedStruct := macEncByteStruct[64:]
	//regenerating mac tag to check
	encryptionKeyStruct, err := ConstructKey("Encryption Hard-Code for User Struct", "could not create key for struct encryption", hashedPassword)
	if err != nil {
		return nil, errors.New("encryption key for struct cannot be made (init user)")
	}
	macKeyStruct, err := ConstructKey("Mac Tag Hard-Code for User Struct", "could not create mac key for struct", hashedPassword)
	if err != nil {
		return nil, errors.New("mac key for struct cannot be made (init user)")
	}
	testTagEncryptedStruct, err := userlib.HMACEval(macKeyStruct, encryptedStruct)
	if err != nil {
		return nil, errors.New("could not create tag for user struct in OriginalStruct")
	}

	//integrity check
	equal := userlib.HMACEqual(tagEncryptedStruct, testTagEncryptedStruct)
	if !equal {
		return nil, errors.New("mac tag of original struct was changed! integrity error in OriginalStruct")
	}
	//checking length before decryption
	if len(encryptedStruct) < userlib.AESBlockSizeBytes {
		return nil, errors.New("resulting encrypted struct is TOOOO short to be decrypted")
	}
	byteUser := userlib.SymDec(encryptionKeyStruct, encryptedStruct)
	var OGUser User
	err = json.Unmarshal(byteUser, &OGUser)
	if err != nil {
		return nil, errors.New("could not unmarshal original struct in OriginalStruct function")
	}
	return &OGUser, nil
}

/*
	func UpdateChanges(user User) (err error) {
		//any changes locally reflexted on datastore

		//decrypt original struct
		return nil
	}
*/
func ConstructKey(hardCodedText string, errorMessage string, hashedPassword []byte) (key []byte, err error) {
	byteHardCodedText, err := json.Marshal(hardCodedText)
	if err != nil {
		return nil, errors.New(errorMessage + "specifically marshalling")
	}
	wholeKey, err := userlib.HashKDF(hashedPassword[:16], byteHardCodedText)
	key = wholeKey[0:16]
	if err != nil {
		return nil, errors.New(errorMessage)
	}
	return key, nil
}
func GetRSAPublicKey(personsUsername string) (RSAKey userlib.PublicKeyType, err error) {
	//given a personsUsername (share or initialize) gets the users RSA public Key
	if len(personsUsername) == 0 {
		return userlib.PublicKeyType{}, errors.New("username cannot be empty") //error statement for empty username
	}

	byteUsername, err := json.Marshal(personsUsername)
	if err != nil {
		return userlib.PublicKeyType{}, errors.New("could not marshal string username in GetRSAPublicKey")
	}
	byteHashedUsername := userlib.Hash(byteUsername)
	hashedPersonsUsername, err := json.Marshal(byteHashedUsername)
	if err != nil {
		return userlib.PublicKeyType{}, errors.New("could not marshal hashed recipient username in GetRSAPublicKey")
	}

	var stringHashedUsername string

	err = json.Unmarshal(hashedPersonsUsername, &stringHashedUsername)
	if err != nil {
		return userlib.PublicKeyType{}, errors.New("could not unmarshal the recipients username to a string version")
	}
	personsPublicKey, ok := userlib.KeystoreGet(stringHashedUsername)
	if !ok {
		return userlib.PublicKeyType{}, errors.New("recipient does not exist")
	}

	return personsPublicKey, nil
}
func GetVerificationKey(personsUsername string) (verificationKey userlib.PublicKeyType, err error) {
	//like getRSA key but has the double hashing for verification!
	if len(personsUsername) == 0 {
		return userlib.PublicKeyType{}, errors.New("persons username cannot be empty") //error statement for empty username
	}
	///convert to byte
	byteUsername, err := json.Marshal(personsUsername)
	if err != nil {
		return userlib.PublicKeyType{}, errors.New("could not convert persons username to bytes")
	}
	hashedOnceByteUsername := userlib.Hash(byteUsername)

	hashedTwiceByteUsername := userlib.Hash(hashedOnceByteUsername) //can do direct because signature generation unmarshals
	doubleHashedUsername, err := json.Marshal(hashedTwiceByteUsername)
	if err != nil {
		return userlib.PublicKeyType{}, errors.New("could not marshal the second hashing of the byte version(not marshaled version of username)")
	}
	//*
	//convert to string to put into public key
	var stringDoubleHashUsername string
	err = json.Unmarshal(doubleHashedUsername, &stringDoubleHashUsername)
	if err != nil {
		return userlib.PublicKeyType{}, errors.New("could not convert double hashed username to string")
	}
	verificationKey, ok := userlib.KeystoreGet(stringDoubleHashUsername)
	if !ok {
		return userlib.PublicKeyType{}, errors.New("recipient does not exist")
	}
	return verificationKey, nil

}
func getuserUUID(username string) (hashedUsername []byte, UUID userlib.UUID, err error) {
	if len(username) == 0 {
		return nil, userlib.UUID{}, errors.New("username cannot be empty") //error statement for empty username
	}
	///convert to byte
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return nil, userlib.UUID{}, errors.New("could not convert username to bytes")
	}
	byteHashedUsername := userlib.Hash(byteUsername)
	hashedUsername, err = json.Marshal(byteHashedUsername) //when unmarshaled gives you the hashed byte version of the username
	if err != nil {
		return nil, userlib.UUID{}, errors.New("could not marshal username in initUser")
	}
	byteHardCodedText, err := json.Marshal("Hard-coded temp fix to hash length")
	if err != nil {
		return nil, userlib.UUID{}, errors.New("couldn't marshal the hashed username ")
	}
	//has to be 16 bytes because from bytes requires a slice of 16 bytes
	uuidUsername := userlib.Argon2Key(userlib.Hash(hashedUsername), byteHardCodedText, 16)
	createdUUID, err := uuid.FromBytes(uuidUsername)
	if err != nil {
		return nil, userlib.UUID{}, errors.New("couldn't convert user log in into a UUID")
	}

	return hashedUsername, createdUUID, nil
}

// NOTE: The following methods have toy (insecure!) implementations.
func encryptFileName(userdataptr *User, filename string) (fileKey []byte, protectedFilename []byte, err error) {
	hashedUsername := userdataptr.username
	hashedPassword := userdataptr.hashedpassword

	byteFilename, err := json.Marshal(filename)
	if err != nil {
		return nil, nil, errors.New("could not retrieve hashed username from struct in encrypting the file name")
	}
	uniqueUsernameAndFile := append(hashedUsername, byteFilename...)
	fileKey = userlib.Argon2Key(hashedPassword, uniqueUsernameAndFile, 16)                                                                   //hashkdf off of this
	encryptionKeyFilename, err := ConstructKey("encryption key for the filenames", "could not create encryption for the file name", fileKey) //might need to change
	if err != nil {
		return nil, nil, err
	}
	macKeyFilename, err := ConstructKey("mac key for the filenames", "could not create mac key for the filename", fileKey) //might need to change
	if err != nil {
		return nil, nil, err
	}
	protectedFilename, err = EncThenMac(encryptionKeyFilename, macKeyFilename, byteFilename)
	if err != nil {
		return nil, nil, err
	}
	return fileKey, protectedFilename, nil
}
func sharingFileAddress(userdataptr *User, key [byte], recipientName string) (err error){
	/*take the key and then RSA encrypt it with the recipients public key, sign it with your private key*/
	hashedRecipientName, recipientUUID, err = getuserUUID(recipientName)
	if err != nil {
		return err
	}
	recipient, ok = userlib.DatastoreGet(recipientUUID)
	if !ok {
		return errors.New("recipient does not exist")
	}
	encryptedKey, err := userlib.PKEEnc(recipient.PublicKey, key)
	if err != nil {
		return errors.New("failed to encrypt")
	}
	signature, err := userlib.DSSignKey(userdataptr.PrivateKey, encryptedKey)
	if err != nil {
		return errors.New("failed to sign")
	}
	//share across ?
	return nil
} 
func containsFile(filename string, userdata *User) (result bool, err error) {
	//returns whether a filename exists in a person's namespace
	fileKey, protectedFilename, err := encryptFileName(userdata, filename)
	if err != nil {
		return false, err
	}
	ownedFiles := userdata.Files
	sharedFiles := userdata.SharedFiles
	protectedFilenameStr := string(protectedFilename)

    // Check if the protected filename exists in owned files
    if _, exists := userdata.Files[protectedFilenameStr]; exists {
        return true, nil
    }

    // Check if the protected filename exists in shared files
    if _, exists := userdata.SharedFiles[protectedFilenameStr]; exists {
        return true, nil
    }

    // If not found in both, return false
    return false, nil
}
func InitUser(username string, password string) (userdataptr *User, err error) {
	//convert to byte
	hashedUsername, createdUUID, err := getuserUUID(username)
	if err != nil {
		return nil, err
	}
	bytePassword, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("could not convert password to bytes")
	}
	//basis keys
	byteHashedPassword := userlib.Argon2Key(userlib.Hash(bytePassword), hashedUsername, 128) //hashKDF off of this
	hashedPassword, err := json.Marshal(byteHashedPassword)                                  //when unmarshaled give you the argon2key of the password (marshaled password and marshaled username)
	if err != nil {
		return nil, errors.New("could not marshal username in initUser")
	}

	//check for existing UUID
	_, ok := userlib.DatastoreGet(createdUUID)
	if ok {
		//if value exists
		return nil, errors.New("username already exists")
	}

	publicKey, structRSAPrivateKey, err := UserRSAKeys(hashedUsername, hashedPassword)
	if err != nil {
		return nil, err
	}

	verificationKey, structSignatureKey, err := UserSignatureKeys(hashedUsername, hashedPassword)
	if err != nil {
		return nil, err // errors.New("signature key generation error")
	}

	//creating new User Struct
	var user User
	//fill struct
	user.username = hashedUsername       //already marshaled
	user.hashedpassword = hashedPassword //already marshaled
	user.PublicKey = publicKey
	user.Verification = verificationKey
	user.PrivateKey = structRSAPrivateKey
	user.SignatureKey = structSignatureKey
	user.Files = make(map[string]uuid.UUID)       //might be wrong
	user.FileToUsers = make(map[string]uuid.UUID) //might be wrong
	user.SharedFiles = make(map[string]uuid.UUID)

	//Put struct into data store
	encryptionKeyStruct, err := ConstructKey("Encryption Hard-Code for User Struct", "could not create key for struct encryption", hashedPassword)
	if err != nil {
		return nil, errors.New("encryption key for struct cannot be made (init user)")
	}
	macKeyStruct, err := ConstructKey("Mac Tag Hard-Code for User Struct", "could not create mac key for struct", hashedPassword)
	if err != nil {
		return nil, errors.New("mac key for struct cannot be made (init user)")
	}

	byteUser, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("did not marshal byteUser init User")
	}

	structUserValue, err := EncThenMac(encryptionKeyStruct, macKeyStruct, byteUser)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(createdUUID, structUserValue)

	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	hashedUsername, createdUUID, err := getuserUUID(username)
	if err != nil {
		return nil, err
	}
	//convert to byte
	bytePassword, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("could not convert password to bytes")
	}
	byteHashedPassword := userlib.Argon2Key(userlib.Hash(bytePassword), hashedUsername, 128) //hashKDF off of this
	hashedPassword, err := json.Marshal(byteHashedPassword)
	if err != nil {
		return nil, errors.New("could not marshal username in getUser")
	}
	//check for existing UUID
	_, ok := userlib.DatastoreGet(createdUUID)
	if !ok {
		//if value exists
		return nil, errors.New("username doesn't exist in database")
	}
	originalUser, err := OriginalStruct(hashedUsername, hashedPassword)
	if err != nil {
		return nil, err
	}

	var userdata User
	userdata.username = hashedUsername
	userdata.hashedpassword = hashedPassword
	userdata.PublicKey = originalUser.PublicKey
	userdata.Verification = originalUser.Verification
	userdata.PrivateKey = originalUser.PrivateKey
	userdata.SignatureKey = originalUser.SignatureKey
	userdata.Files = originalUser.Files             //might be wrong
	userdata.FileToUsers = originalUser.FileToUsers //might be wrong
	userdata.SharedFiles = originalUser.SharedFiles

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//	randomUUID := uuid.New()
	// randombyte

	//check if filename already exists

	//storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	/*if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes) */
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	/*storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content) */
	return nil, nil
	//return content, err
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
