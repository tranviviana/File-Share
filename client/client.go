package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
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

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
/*func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}*/

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
/*------------------------STRUCT SECTION ---------------------------*/
/*
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
	FileToUsers  map[string]uuid.UUID //file to tree struct
}
*/

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).

/*
type CommunicationsTree struct {
	UsernameMap []byte //hashKDF and MAC only owner can change
}
type File struct {
	CommChannel        userlib.UUID
	fileContentPointer userlib.UUID //randomized and then do counter to hashKDF and get fileContentStruct
	FileLength         uint
}
type FileContent struct {
	BlockEncrypted string
}
type CommunicationsChannel struct {
	FileAddress []userlib.UUID //RSA Encrypted

}
*/

/*need to flush store and share file revocation situation*/

/*---------------------------Helper Functions-------------------------*/

/*
func UserRSAKeys(hashedUsername []byte, hashedPassword []byte) (publicKey userlib.PKEEncKey, structRSAPrivateKey []byte, err error) {
	//generates RSA keys -> puts into key store -> and returns encrypted and maced private key
	//KEY STORE TYPE DEFINITION
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
	structRSAPrivateKey, err = EncThenMac(encryptionKeyPrivateEncryption, macKeyPrivate, privateKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not concatenate both mac to encryption in RSA PRIVATE KEY ")
	}

	return publicKey, structRSAPrivateKey, nil
}
func EncThenMac(encryptionKey []byte, macKey []byte, objectHidden any) (macEncryptedObject []byte, err error) {
	//could return error if the original object are ///////////////////////

	IV := userlib.RandomBytes(16)
	//MAC(ENC(RSAprivateKey))
	//convert to byte
	objectHiddenBytes, err := json.Marshal(objectHidden)
	if err != nil {
		return nil, errors.New("could not convert objectHidden into bytes")
	}
	encryptedObject := userlib.SymEnc(encryptionKey, IV, objectHiddenBytes)
	tagEncryptedObject, err := userlib.HMACEval(userlib.Hash(macKey), encryptedObject)
	if err != nil {
		return nil, errors.New("could not generate MAC tag over hidden object")
	}
	//full encrypted and mac tagged RSA private key
	macEncryptedObject = append(tagEncryptedObject, encryptedObject...)
	return macEncryptedObject, nil
}
func UserSignatureKeys(hashedUsername []byte, hashedPassword []byte) (verificationKey userlib.DSVerifyKey, structSignatureKey []byte, err error) {
	//generates signature keys -> puts into key store -> and returns encrypted and maced private key
	var stringDoubleHashUsername string
	err = json.Unmarshal(userlib.Hash(hashedUsername), &stringDoubleHashUsername)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not unmarshal hashed username")
	}

	signingKey, verificationKey, err := userlib.DSKeyGen()
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could no generate signature Keys")
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

	structSignatureKey, err = EncThenMac(encryptionKeySignature, macKeySignature, signingKey)
	if err != nil {
		return userlib.PublicKeyType{}, nil, errors.New("could not concatenate both mac to encryption in SIGNING")
	}
	return verificationKey, structSignatureKey, nil
}
func OriginalStruct(hashedUsername []byte, hashedPassword []byte) (originalUser *User, err error) {
	//since each getuser creates a local User struct, this function obtains a pointer to the original user struct
	//getting orginal struct
	createdUUID, err := uuid.FromBytes(hashedUsername)
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
	err = json.Unmarshal(byteUser, originalUser)
	if err != nil {
		return nil, errors.New("could not unmarshal original struct in OriginalStruct function")
	}
	return originalUser, nil
}
*/
/*
	func UpdateChanges(user User) (err error) {
		//any changes locally reflexted on datastore

		//decrypt original struct
		return nil
	}
*/

/*
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

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	if len(username) == 0 {
		return nil, errors.New("username cannot be empty") //error statement for empty username
	}
	///convert to byte
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("could not convert username to bytes")
	}
	//convert to byte
	bytePassword, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("could not convert password to bytes")
	}
	byteHardCodedText, err := json.Marshal("Hard-coded temp fix to hash length")
	if err != nil {
		return nil, errors.New("couldn't marshal the hashed username ")
	}
	//basis keys
	hashedUsername := userlib.Hash(byteUsername)
	uuidUsername := userlib.Argon2Key(userlib.Hash(hashedUsername), byteHardCodedText, 16)
	hashedPassword := userlib.Argon2Key(userlib.Hash(bytePassword), hashedUsername, 128) //hashKDF off of this
	//check for existing UUID
	createdUUID, err := uuid.FromBytes(uuidUsername)
	if err != nil {
		return nil, errors.New("couldn't convert user log in into a UUID")
	}
	_, ok := userlib.DatastoreGet(uuid.UUID(userlib.Hash(createdUUID[:])))
	if ok {
		//if value exists
		return nil, errors.New("username already exists")
	}

		publicKey, structRSAPrivateKey, err := UserRSAKeys(hashedUsername, hashedPassword)
		if err != nil {
			return nil, errors.New("RSA key generation error")
		}

		verificationKey, structSignatureKey, err := UserSignatureKeys(hashedUsername, hashedPassword)
		if err != nil {
			return nil, errors.New("signature key generation error")
		}

	//creating new User Struct
	var user User
	//fill struct
	user.username = hashedUsername
	user.hashedpassword = hashedPassword
	user.PublicKey = publicKey
	user.Verification = verificationKey
	user.PrivateKey = structRSAPrivateKey
	user.SignatureKey = structSignatureKey
	user.Files = make(map[string]uuid.UUID)       //might be wrong
	user.FileToUsers = make(map[string]uuid.UUID) //might be wrong

	//Put struct into data store
	encryptionKeyStruct, err := ConstructKey("Encryption Hard-Code for User Struct", "could not create key for struct encryption", hashedPassword)
	if err != nil {
		return nil, errors.New("encryption key for struct cannot be made (init user)")
	}
	macKeyStruct, err := ConstructKey("Mac Tag Hard-Code for User Struct", "could not create mac key for struct", hashedPassword)
	if err != nil {
		return nil, errors.New("mac key for struct cannot be made (init user)")
	}

	//hide that user struct!!!!
	//hashedpassword disappears in marshaling
	byteUser, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("could not marshal user struct")
	}
	structUserValue, err := EncThenMac(encryptionKeyStruct, macKeyStruct, byteUser)
	if err != nil {
		return nil, errors.New("could not concatenate encryption to mac key init user")
	}

	userlib.DatastoreSet(createdUUID, structUserValue)

	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("invalid credentials DUH")
	}
	byteUsername, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("could not convert username to bytes")
	}

	byteHardCodedText, err := json.Marshal("Hard-coded temp fix to hash length")
	if err != nil {
		return nil, errors.New("couldn't marshal the hashed username ")
	}
	//convert to byte
	bytePassword, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("could not convert password to bytes")
	}
	//basis keys
	hashedUsername := userlib.Hash(byteUsername)
	uuidUsername := userlib.Argon2Key(userlib.Hash(hashedUsername), byteHardCodedText, 16)
	hashedPassword := userlib.Argon2Key(userlib.Hash(bytePassword), hashedUsername, 128)

	//check for existing UUID
	createdUUID, err := uuid.FromBytes(uuidUsername)
	if err != nil {
		return nil, errors.New("couldn't convert user log in into a UUID")
	}

	_, ok := userlib.DatastoreGet(createdUUID)
	if !ok {
		return nil, errors.New("username does not exist in the database")
	}
	originalUser, err := OriginalStruct(hashedUsername, hashedPassword)
	if err != nil {
		return nil, errors.New("couldn't replenish original user (invalid password/ integrity err)")
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

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	/*if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
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
	err = json.Unmarshal(dataJSON, &content)
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
*/
