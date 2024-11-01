package client

//Default to the marshaled version of object

// CS 161 Project 2

import (
	"encoding/hex"
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
	FileToUsers  map[string]uuid.UUID //file to Communications Tree struct this and ^ should have same filenames ultimately
	SharedFiles  map[string]uuid.UUID //to uuid of communications channel (when they are revoked they wont see any thing they can use in the comms channel --> can't access)
}

type CommunicationsTree struct {
	//only owner has access to this
	CommsChan       userlib.UUID
	CurrentKey      []byte //file key hidden again because of argon2key of user specifically
	AccessibleUsers []byte
}
type File struct {
	FileContentPointer userlib.UUID //randomized and then do counter to hashKDF and get fileContentStruct
	FileLength         uint
}
type FileContent struct {
	BlockEncrypted string
}

// when revoked still have invitation pointer but wont be able to decrypt file adress or content
// datastore adversary could change invitation but the recipient would know bc they stored key
// if they changed adress it would throw a revoked or integrity error
type Invitation struct {
	DoubleHashedOwner    string //use to get verification key
	HashedOwner          string //in keystore RSA public key. shared with is encrypted with owner's public key
	DoubleHashedSharer   string
	HashedSharer         string
	communicationChannel userlib.UUID
}
type CommunicationsChannel struct {
	FileAddress map[string][]byte //RSA Encrypted with user symmetric key in it when a user shares, they share with same symmetric key so you can revoke thorugh finding all those keys and removing
	SharedWith  []userlib.UUID    // each person that accepts can edit this tree? rsa enc w owners public key & w inviter's signature.
}

/*need to flush store and share file revocation situation*/

/*--------------------------- Helper Functions -------------------------*/
/*--------------------------- Used Frequently --------------------------*/
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
func CheckAndDecrypt(protectedObject []byte, macKey []byte, decryptionKey []byte) (decryptedObject []byte, err error) {
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
func CheckMac(protectedObject []byte, macKey []byte) (ok bool, err error) {
	macTag := protectedObject[:64]
	encryptedObject := protectedObject[64:]
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
	encryptedObject := protectedObject[64:]
	if len(encryptedObject) < userlib.AESBlockSizeBytes {
		return nil, errors.New("object length is too short to decrypt")
	}
	decryptedObject = userlib.SymDec(decryptionKey, encryptedObject)
	return decryptedObject, nil
}
func GetUserUUID(username string) (hashedUsername []byte, UUID userlib.UUID, err error) {
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

func GetFileUUID(userdata *User, filename string) (fileExists bool, structUUID uuid.UUID, err error) {
	protectedFilename, err := EncryptFileName(userdata.username, userdata.hashedpassword, filename)
	if err != nil {
		return false, uuid.UUID{}, err
	}
	protectedFilenameStr := string(protectedFilename)

	if fileUUID, exists := userdata.Files[protectedFilenameStr]; exists {
		return true, fileUUID, nil
	}
	if invitationUUID, exists := userdata.SharedFiles[protectedFilenameStr]; exists {
		invitation, err := GetInvitation(invitationUUID)
		if err != nil {
			return false, uuid.UUID{}, err
		}
		commChannel, err := GetCommunicationChannel(invitation.communicationChannel)
		if err != nil {
			return false, uuid.UUID{}, err
		}
		if encryptedFileStruct, exists := commChannel.FileAddress[string(userdata.username)]; exists {
			var privateKey userlib.PKEDecKey
			err := json.Unmarshal(userdata.PrivateKey, &privateKey)
			if err != nil {
				return false, userlib.UUID{}, errors.New("unable to convert private key for decryption")
			}

			fileUUIDBytes, err := userlib.PKEDec(privateKey, encryptedFileStruct)
			if err != nil {
				return false, userlib.UUID{}, errors.New("failed to decrypt file address: access may have been revoked")
			}
			fileUUID, err := uuid.FromBytes(fileUUIDBytes)
			if err != nil {
				return false, userlib.UUID{}, errors.New("invalid UUID format after decryption")
			}

			return true, fileUUID, nil
		}
	}

	return false, uuid.UUID{}, errors.New("file does not exist in filespace")
}
func GetInvitation(invitationUUID uuid.UUID) (invitation Invitation, err error) {
	invitationBytes, ok := userlib.DatastoreGet(invitationUUID)
	if !ok {
		return Invitation{}, errors.New("invitation does not exist in datastore")
	}

	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return Invitation{}, errors.New("could not unmarshal invitation data")
	}

	return invitation, nil
}
func GetCommunicationChannel(communicationChannelUUID uuid.UUID) (communicationChannel CommunicationsChannel, err error) {
	commChannelBytes, ok := userlib.DatastoreGet(communicationChannelUUID)
	if !ok {
		return CommunicationsChannel{}, errors.New("communication channel does not exist in datastore")
	}

	err = json.Unmarshal(commChannelBytes, &communicationChannel)
	if err != nil {
		return CommunicationsChannel{}, errors.New("could not unmarshal invitation data")
	}

	return communicationChannel, nil
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
	//regenerating mac tag to check
	encryptionKeyStruct, err := ConstructKey("Encryption Hard-Code for User Struct", "could not create key for struct encryption", hashedPassword)
	if err != nil {
		return nil, errors.New("encryption key for struct cannot be made (init user)")
	}
	macKeyStruct, err := ConstructKey("Mac Tag Hard-Code for User Struct", "could not create mac key for struct", hashedPassword)
	if err != nil {
		return nil, errors.New("mac key for struct cannot be made (init user)")
	}
	byteUser, err := CheckAndDecrypt(macEncByteStruct, macKeyStruct, encryptionKeyStruct)
	if err != nil {
		return nil, err
	}
	var OGUser User
	err = json.Unmarshal(byteUser, &OGUser)
	if err != nil {
		return nil, errors.New("could not unmarshal original struct in OriginalStruct function")
	}
	return &OGUser, nil
}
func EncryptFileName(hashedUsername []byte, hashedPassword []byte, filename string) (protectedFilename []byte, err error) {
	byteFilename, err := json.Marshal(filename)
	if err != nil {
		return nil, errors.New("could not retrieve hashed username from struct in encrypting the file name")
	}
	uniqueUsernameAndFile := append(hashedUsername, byteFilename...)
	fileKey := userlib.Argon2Key(hashedPassword, uniqueUsernameAndFile, 16)                                                                  //hashkdf off of this
	encryptionKeyFilename, err := ConstructKey("encryption key for the filenames", "could not create encryption for the file name", fileKey) //might need to change
	if err != nil {
		return nil, err
	}
	macKeyFilename, err := ConstructKey("mac key for the filenames", "could not create mac key for the filename", fileKey) //might need to change
	if err != nil {
		return nil, err
	}
	protectedFilename, err = EncThenMac(encryptionKeyFilename, macKeyFilename, byteFilename)
	if err != nil {
		return nil, err
	}
	return protectedFilename, nil

}
func randomKeyGenerator() (randomKey []byte, err error) {
	salt := userlib.RandomBytes(128)
	generatedPassword := userlib.RandomBytes(128)
	randomKey, err = ConstructKey(hex.EncodeToString(salt), "Could not create a shared Encryption Key", generatedPassword)
	if err != nil {
		return nil, err
	}
	return randomKey, err
}

/*
	func UpdateChanges(user User) (err error) {
		//any changes locally reflexted on datastore

		//decrypt original struct
		return nil
	}
*/
/* ------------------------------ Initialize User Helpers ----------------------*/
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

/*------------------------------ Obtaining Struct Data -------------------------*/
/*------------------------------ Public Data -------------------------*/

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

/*------------------------------ Private Data -------------------------*/

func GetSignatureKey(hashedPassword []byte, byteSigningKey []byte) (signatureKey userlib.PrivateKeyType, err error) {
	decryptionKeySignature, err := ConstructKey("RSA Digital Signature Encryption Key", "could not HASHKDF key for Signature encryption", hashedPassword)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	macKeySignature, err := ConstructKey("RSA Digital Signature Mac Key", "could not HASHKDF mac for Signature Tag", hashedPassword)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	decryptedSignatureKey, err := CheckAndDecrypt(byteSigningKey, macKeySignature, decryptionKeySignature)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	var signingKeyPointer userlib.PKEDecKey
	err = json.Unmarshal(decryptedSignatureKey, &signingKeyPointer)
	if err != nil {
		return userlib.PrivateKeyType{}, errors.New("could not unmarshal the private key")
	}
	signatureKey = signingKeyPointer
	return signatureKey, nil
}

func GetPrivateKey(hashedPassword []byte, bytePrivateKey []byte) (privateKey userlib.PrivateKeyType, err error) {
	decryptionKeyPrivateEncryption, err := ConstructKey("RSA Private Key Encryption Key", "could not create key for RSA key encryption", hashedPassword)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	macKeyPrivate, err := ConstructKey("RSA MAC Key", "could not create key for RSA MAC Tag", hashedPassword)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	decryptedPrivateKey, err := CheckAndDecrypt(bytePrivateKey, macKeyPrivate, decryptionKeyPrivateEncryption)
	if err != nil {
		return userlib.PrivateKeyType{}, err
	}
	var privateKeyPointer userlib.PKEDecKey
	err = json.Unmarshal(decryptedPrivateKey, &privateKeyPointer)
	if err != nil {
		return userlib.PrivateKeyType{}, errors.New("could not unmarshal the private key")
	}
	privateKey = privateKeyPointer
	return privateKey, nil

}

/*----------------------------------- File Sharing Helpers ------------------------*/
/*
func SharingFileAddress(signatureKey userlib.PrivateKeyType, key []byte, recipientName string, fileName string) (err error) {
	//check recipient exists
	_, recipientUUID, err := GetUserUUID(recipientName)
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(recipientUUID)
	if !ok {
		return errors.New("recipient does not exist")
	}
	//key is the argon key shared to everyone when they've accepted their offer
	recipientEncryption, err := ConstructKey("sharingFileAddress recipient encryption", "could not create the encryption key to hide recipient", key) //regenerated by owner to check
	if err != nil {
		return err
	}
	recipientMac, err := ConstructKey("sharingFileAddress recipient mac", "could not create the mac key to ensure recipient", key) //regenerated by owner to check
	if err != nil {
		return err
	}
	protectedRecipientName, err := EncThenMac(recipientEncryption, recipientMac, recipientUUID[:]) //recipient UUID is associated with the recipients username so use this to revoke
	if err != nil {
		return err
	}
	//delete this in a little
	print(protectedRecipientName)
	//signingKey := userdataptr.SignatureKey
	return nil
}*/
/*
func BecomeAParent(userdataptr *User, recipientName string, sharingKey string) (err error) {
	/*this will be used in create invititation
	1) check that recipient exists
	2) encrypt and mac the recipients name
	3) sign it
	4) add it to the communications channel shared with list

	//check recipient exists

	_, recipientUUID, err := GetUserUUID(recipientName)
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(recipientUUID)
	if !ok {
		return errors.New("recipient does not exist")
	}
	//encrypt & mac recipient's name
	recipientEncryption, err := ConstructKey("becomeAParent recipient encryption", "could not create the encryption key to hide recipient", []byte(sharingKey))
	if err != nil {
		return err
	}
	recipientMac, err := ConstructKey("becomeAParent recipient mac", "could not create the mac key to ensure recipient", []byte(sharingKey))
	if err != nil {
		return err
	}
	protectedRecipientName, err := EncThenMac(recipientEncryption, recipientMac, recipientUUID[:])
	if err != nil {
		return err
	}

} */

/* --------------------------------------------TO DO FUNCTIONS ---------------------------------------*/
func InitUser(username string, password string) (userdataptr *User, err error) {
	//convert to byte
	hashedUsername, createdUUID, err := GetUserUUID(username)
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
	hashedUsername, createdUUID, err := GetUserUUID(username)
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
	fileExists, fileUUID, err := GetFileUUID(userdata, filename)
	if err != nil {
		return err
	}
	var file File
	if fileExists {
		fileData, ok := userlib.DatastoreGet(fileUUID)
		if !ok {
			return errors.New("file does not exist in datastore")
		}
		err = json.Unmarshal(fileData, &file)
		if err != nil {
			return errors.New("could not unmarshal existing file")
		}
		if uint(len(content)) < file.FileLength {
			//delete content
		}

	}
	//count from uuid to hashkdf to get filecontent struct
	//modify file struct enrypted content
	//if file length > content length: delete existing content
	//file content = hashkdf content
	//file length = encrypted content.length

	/*THIS IS FOR ONLY IF THE FILE IS NEW
	var fileCommsChannelStruct CommunicationsChannel
	var fileStruct File
	var contentStruct FileContent
	var sharingTreeStruct CommunicationsTree

	//generating a random key

	fileKeys, err := randomKeyGenerator()
	if err != nil {
		return err
	}
	encryptionCTCK, err := ConstructKey("communications tree current key encryption key", "could not construct a key to encrypt the key in the struct", hashedPassword)
	if err != nil {
		return err
	}
	macCTCK, err := ConstructKey("communications tree current key mac key", "could not construct a key to mac", hashedPassword)
	if err != nil {
		return err
	}
	protectedsharedFileEKey, err := EncThenMac(encryptionCTCK, macCTCK, fileKeys)
	if err != nil {
		return err
	}
	sharingTreeStruct.CurrentKey = protectedsharedFileEKey
	sharingTreeStruct.AccessibleUsers = make([]byte, 0)

	communicationsTreeUUID := uuid.New()
	sharingTreeStruct.CommsChan = communicationsTreeUUID

	//storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
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
	//filecontent + length
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
	/*move file struct to location. gen new keys
	change accessible users
	update file addresses for accessing people
	delete

	front as random place. next places +1
	*/
}
