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
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

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
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
/*------------------------STRUCT SECTION ---------------------------*/
type User struct {
	//simply hashed
	Username     string
	PublicKey    userlib.PKEEncKey
	Verification userlib.DSVerifyKey

	//HashKDF Protected
	PrivateKey   []byte
	SignatureKey []byte
	Files        map[string]uuid.UUID
	FileToUsers  map[string]uuid.UUID //file to tree struct
}

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).
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

/*need to flush store and share file revocation situation*/

/*---------------------------Helper Functions-------------------------*/
func UserRSAKeys(stringHashedUsername string, hashedPassword []byte) (publicKey userlib.PKEEncKey, structRSAPrivateKey []byte, err error) {
	//generates RSA keys -> puts into key store -> and returns encrypted and maced private key
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not generate RSA keys")
	}
	//setting RSA Encryption Keys
	//putting RSA public key into keystore to prevent tampering
	err = userlib.KeystoreSet(stringHashedUsername, publicKey)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not keystore set the public key")
	}
	//convert to byte
	byteHardCodedText, err := json.Marshal("RSA Private Key Encryption Key")
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not marshal for private key")
	}
	//handling private key case
	keyForPrivateEncryption, err := userlib.HashKDF(hashedPassword, byteHardCodedText)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not create key for RSA key encryption")
	}
	encryptionKeyPrivateEncryption := keyForPrivateEncryption[:16]

	byteHardCodedText, err = json.Marshal("RSA MAC Key")
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not marshal for RSA Mac Key")
	}
	keyForPrivateMAC, err := userlib.HashKDF(hashedPassword, byteHardCodedText)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not create key for RSA MAC Tag")
	}
	macKeyPrivate := keyForPrivateMAC[0:16]
	RSAIV := userlib.RandomBytes(16)
	//MAC(ENC(RSAprivateKey))
	//convert to byte
	privateKeyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not convert private key into bytes")
	}
	encryptedRSAPrivateKey := userlib.SymEnc(encryptionKeyPrivateEncryption, RSAIV, privateKeyBytes)
	tagEncryptedRSAPrivateKey, err := userlib.HMACEval(userlib.Hash(macKeyPrivate), encryptedRSAPrivateKey)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not generate MAC tag for encrypted RSA private Key")
	}
	//full encrypted and mac tagged RSA private key
	structRSAPrivateKey = append(tagEncryptedRSAPrivateKey, encryptedRSAPrivateKey...)
	return publicKey, structRSAPrivateKey, nil
}
func UserSignatureKeys(stringDoubleHashUsername string, hashedPassword []byte) (verificationKey userlib.DSVerifyKey, structSignatureKey []byte, err error) {
	//generates signature keys -> puts into key store -> and returns encrypted and maced private key
	signingKey, verificationKey, err := userlib.DSKeyGen()
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could no generate signature Keys")
	}
	err = userlib.KeystoreSet(stringDoubleHashUsername, verificationKey)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not keystore set the signature public key")
	}

	//convert to byte
	byteHardCodedText, err := json.Marshal("RSA Digital Signature Encryption Key")
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not marshal for Signature Key")
	}
	keyForSignature, err := userlib.HashKDF(hashedPassword, byteHardCodedText)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not HASHKDF key for Signature encryption")
	}
	encryptionKeySignature := keyForSignature[0:16]
	//convert to byte
	byteHardCodedText, err = json.Marshal("RSA Digital Signature Mac Key")
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not marshal for Signature Key")
	}
	keyForSignatureMac, err := userlib.HashKDF(hashedPassword, byteHardCodedText)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not HASHKDF mac for Signature Tag")
	}
	macKeySignature := keyForSignatureMac[0:16]
	SignatureIV := userlib.RandomBytes(16)
	signingKeyBytes, err := json.Marshal(signingKey)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not convert signing key into bytes")
	}
	encryptedSignatureKey := userlib.SymEnc(encryptionKeySignature, SignatureIV, signingKeyBytes)
	tagEncryptedSignatureKey, err := userlib.HMACEval(userlib.Hash(macKeySignature), encryptedSignatureKey)
	if err != nil {
		return userlib.PKEEncKey{}, nil, errors.New("could not generate MAC tag for encrypted Signature Key")
	}
	//full encrypted and mac tagged signature key
	structSignatureKey = append(tagEncryptedSignatureKey, encryptedSignatureKey...)
	return verificationKey, structSignatureKey, nil
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
	//basis keys
	hashedUsername := userlib.Hash(byteUsername)
	hashedPassword := userlib.Argon2Key(userlib.Hash(bytePassword), hashedUsername, 128) //hashKDF off of this
	comboUserandPass := append(hashedUsername, userlib.Hash(bytePassword)...)
	hashedUserPass := userlib.Argon2Key((comboUserandPass), hashedUsername, 128) //for createdUUID

	//check for existing UUID
	createdUUID, err := uuid.FromBytes(hashedUserPass) // connect to the struct but struct needs to be encrypted with reliance to username and password
	if err != nil {
		return nil, errors.New("xouldn't convert user log in into a UUID")
	}
	_, ok := userlib.DatastoreGet(uuid.UUID(userlib.Hash(createdUUID[:])))
	if ok {
		//if value exists
		return nil, errors.New("username already exists")
	}
	//convert from byte BACK
	var stringHashedUsername string
	err = json.Unmarshal(hashedUsername, &stringHashedUsername)
	if err != nil {
		return nil, errors.New("could not unmarshal hashed username")
	}

	publicKey, structRSAPrivateKey, err := UserRSAKeys(stringHashedUsername, hashedPassword)
	if err != nil {
		return nil, errors.New("RSA key generation error")
	}

	//convert from byte BACK
	var stringDoubleHashUsername string
	err = json.Unmarshal(userlib.Hash(hashedUsername), &stringDoubleHashUsername)
	if err != nil {
		return nil, errors.New("could not unmarshal hashed username")
	}

	verificationKey, structSignatureKey, err := UserSignatureKeys(stringDoubleHashUsername, hashedPassword)
	if err != nil {
		return nil, errors.New("Signature key generation error")
	}
	//setting RSA Signature Keys

	//delete this line... just for error case
	//print(structRSAPrivateKey, structSignatureKey)
	//creating new User Struct
	var user User
	//fill struct
	user.Username = stringHashedUsername
	user.PublicKey = publicKey
	user.Verification = verificationKey
	user.PrivateKey = structRSAPrivateKey
	user.SignatureKey = structSignatureKey
	user.Files = make(map[string]uuid.UUID)       //might be wrong
	user.FileToUsers = make(map[string]uuid.UUID) //might be wrong

	//Put struct into data store
	byteHardCodedText, err := json.Marshal("Encryption Hard-Code for User Struct")
	if err != nil {
		return nil, errors.New("could not convert encryption hard-code to bytes")
	}
	keyForEncStruct, err := userlib.HashKDF(hashedPassword, byteHardCodedText)
	encryptionKeyStruct := keyForEncStruct[0:16]
	if err != nil {
		return nil, errors.New("could not create key for struct encryption")
	}
	byteHardCodedText, err = json.Marshal("Mac Tag Hard-Code for User Struct")
	if err != nil {
		return nil, errors.New("could not convert Mac Tag hard-code to bytes")
	}
	keyForMacStruct, err := userlib.HashKDF(hashedPassword, byteHardCodedText)
	macKeyStruct := keyForMacStruct[0:16]
	if err != nil {
		return nil, errors.New("could not create mac key for struct")
	}

	//hide that user struct!!!!
	byteUser, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("could not marshal user struct")
	}
	structIV := userlib.RandomBytes(16)
	encryptedStruct := userlib.SymEnc(encryptionKeyStruct, structIV, byteUser)
	tagEncryptedStruct, err := userlib.HMACEval(macKeyStruct, encryptedStruct)
	if err != nil {
		return nil, errors.New("could not create tag for user struct")
	}
	structUserValue := append(tagEncryptedStruct, encryptedStruct...)

	userlib.DatastoreSet(createdUUID, structUserValue)

	return &user, nil
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
