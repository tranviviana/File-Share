package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

/*
Types of tests
1) assertion test
*/

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"strconv"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const defaultPassword2 = "password123"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var EvanBot *client.User
	var CodaBot *client.User
	var A *client.User
	var B *client.User
	var C *client.User
	var D *client.User
	var E *client.User
	var F *client.User
	var G *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})
	Describe("Basic Tests", func() {
		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
	/*---------------------------Tests Created Via Design Questions --------------------------------*/
	Describe("Stateless Design", func() {
		Specify("Stateless Design: One Person wrong log in  [Design Question: User Authentication]", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			alice, err = client.GetUser("alice", "deeeeee")
			//Expect(err).To(BeNil())
		})

		Specify("Multiple Device Store File[Design Question: StoreFile Across]", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice Laptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice Phone")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			aliceFileTest, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking File Equivalence for one loaded file")
			Expect(aliceFileTest).To(BeEquivalentTo(contentOne))
		})
		Specify("Multiple Device Append File[Design Question: Append Across]", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice Laptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice Phone")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Appending to Alice's File Via phone")
			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			aliceFileTestLaptop, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			aliceFileTestPhone, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking File Equivalence accross phone and laptop")
			Expect(aliceFileTestPhone).To(BeEquivalentTo(aliceFileTestLaptop))
			userlib.DebugMsg("Checking File Equivalence for correct content")
			Expect(aliceFileTestPhone).To(BeEquivalentTo([]byte(contentOne + contentTwo)))

		})
		Specify("Multiple Device DOUBLE Store File[Design Question: Multiple Devices]", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice Laptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice Phone")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			aliceFileTest, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking File Equivalence for one loaded file")
			Expect(aliceFileTest).To(BeEquivalentTo(contentOne))

			err = aliceLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			err = alicePhone.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			aliceFileTest, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(aliceFileTest).To(BeEquivalentTo(contentThree))

		})
	})
	/*----------------------------Security Tests Tampering with different pieces of data -------------*/
	Describe("Being Malicious", func() {
		Specify("Tampering and then making sure we can't do any file functions after that ", func() {
			userlib.DebugMsg("Datastore mess ups!!!")
			_, err = client.InitUser("testtest", defaultPassword)
			Expect(err).To(BeNil())
			var startUUID uuid.UUID
			var startByteValue ([]byte)
			for uuid, byteValues := range userlib.DatastoreGetMap() {
				startUUID = uuid
				startByteValue = byteValues
			}
			Expect(startByteValue).NotTo(BeNil())
			userlib.DatastoreSet(startUUID, userlib.RandomBytes((100)))
			/*User struct should be all messed up now*/
			alice, err = client.GetUser("testtest", defaultPassword)
			Expect(err).NotTo(BeNil())

		})
	})
	/*---------------------------Tests Created Via Example Scenarios --------------------------------*/
	Describe("Example Scenarios", func() {
		Specify("User Authentication", func() {

			userlib.DebugMsg("Initializing user alice")
			alice, err = client.InitUser("alice", defaultPassword2)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting alice with the wrong password")
			alice, err = client.GetUser("alice", "not the right password")
			Expect(err).To(BeNil())
			bob, err = client.GetUser("alice", defaultPassword2)
			Expect(bob).To(Equal(alice))

			userlib.DebugMsg("Initializing user bob with the same password")
			bob, err = client.InitUser("bob", defaultPassword2)
			Expect(err).To(BeNil())
			bob, err = client.GetUser("bob", defaultPassword2)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword2)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword2)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Generated Structs on multiple devices are different")
			Expect(aliceLaptop).To(Equal(aliceLaptop))

			userlib.DebugMsg("aliceLaptop store file showing on phone")
			err = aliceLaptop.StoreFile("toppings.txt", []byte("syrup"))
			Expect(err).To(BeNil())
			loadedFile, err := alicePhone.LoadFile("toppings.txt")
			Expect(err).To(BeNil())
			Expect(loadedFile).To(BeEquivalentTo([]byte("syrup")))
			err = aliceLaptop.StoreFile("toppings.txt", []byte("syrup"))
			Expect(err).To(BeNil())

			err = aliceLaptop.AppendToFile("toppings.txt", []byte("butter"))
			Expect(err).To(BeNil())
			newLoadedFile, err := alicePhone.LoadFile("toppings.txt")
			Expect(err).To(BeNil())
			Expect(newLoadedFile).To(BeEquivalentTo([]byte("syrupbutter")))

		})
		Specify("File Operations", func() {

			userlib.DebugMsg("Initializing user Evanbot")
			userlib.DebugMsg("NameSpacing example")
			EvanBot, err = client.InitUser("EvanBot", defaultPassword2)
			Expect(err).To(BeNil())
			err = EvanBot.StoreFile("foods.txt", []byte("pancakes"))
			Expect(err).To(BeNil())
			EvanBotLoadFile, err := EvanBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(EvanBotLoadFile).To(BeEquivalentTo([]byte("pancakes")))

			err = EvanBot.StoreFile("foods.txt", []byte("cookies"))
			Expect(err).To(BeNil())
			EvanBotLoadFile, err = EvanBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(EvanBotLoadFile).To(BeEquivalentTo([]byte("cookies")))

			EvanBotLoadFile, err = EvanBot.LoadFile("drinks.txt")
			Expect(err).ToNot(BeNil())

			err = EvanBot.AppendToFile("foods.txt", []byte("and pancakes"))
			Expect(err).To(BeNil())
			EvanBotLoadFile, err = EvanBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(EvanBotLoadFile).To(BeEquivalentTo([]byte("cookies and pancakes")))

			err = EvanBot.AppendToFile("foods.txt", []byte("and hash browns"))
			Expect(err).To(BeNil())
			EvanBotLoadFile, err = EvanBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(EvanBotLoadFile).To(BeEquivalentTo([]byte("cookies and pancakes and hash browns")))

			err = EvanBot.StoreFile("foods.txt", []byte("pancakes"))
			Expect(err).To(BeNil())
			EvanBotLoadFile, err = EvanBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(EvanBotLoadFile).To(BeEquivalentTo([]byte("pancakes")))

			err = EvanBot.AppendToFile("drinks.txt", []byte("and cookies"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user CodaBot")
			CodaBot, err = client.InitUser("CodaBot", defaultPassword2)
			Expect(err).To(BeNil())
			err = CodaBot.StoreFile("foods.txt", []byte("waffles"))
			Expect(err).To(BeNil())
			CodaBotLoaded, err := CodaBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(CodaBotLoaded).ToNot(BeEquivalentTo(EvanBotLoadFile))
			Expect(CodaBotLoaded).To(BeEquivalentTo([]byte("waffles")))
			Expect(EvanBotLoadFile).To(BeEquivalentTo([]byte("pancakes")))

		})

		Specify("Sharing and Revocation", func() {
			userlib.DebugMsg("Initializing user Evanbot")
			userlib.DebugMsg("filesharing example")
			EvanBot, err = client.InitUser("EvanBot", defaultPassword2)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Evanbot")
			CodaBot, err = client.InitUser("CodaBot", defaultPassword2)
			Expect(err).To(BeNil())
			err = EvanBot.StoreFile("foods.txt", []byte("eggs"))
			Expect(err).To(BeNil())
			invitationPtr, err := EvanBot.CreateInvitation("foods.txt", "CodaBot")
			Expect(err).To(BeNil())

			err = CodaBot.AcceptInvitation("EvanBot", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())
			CodaBotLoadFile, err := CodaBot.LoadFile("snacks.txt")
			Expect(CodaBotLoadFile).To(BeEquivalentTo("eggs"))

			EvanBotLoadFile, err := EvanBot.LoadFile("foods.txt")
			Expect(err).To(BeNil())
			Expect(EvanBotLoadFile).To(BeEquivalentTo("eggs"))

			err = EvanBot.AppendToFile("foods.txt", []byte("and bacon"))
			Expect(err).To(BeNil())
			CodaBotLoadFile, err = CodaBot.LoadFile("snacks.txt")
			Expect(err).To(BeNil())
			Expect(CodaBotLoadFile).To(BeEquivalentTo("eggs and bacon"))

			/*

				EvanBot (the file owner) wants to share the file with CodaBot. What is stored in
				Datastore when creating the invitation, and what is the UUID returned? What values on
				Datastore are changed when CodaBot accepts the invitation? How does CodaBot access the file
				in the future?

				CodaBot (not the file owner) wants to share the file with PintoBot. What is the sharing process like when a
				non-owner shares? (Same questions as above; your answers might be the same or different depending on your design.)
			*/
			userlib.DebugMsg("Revocation Behavior ")
			userlib.DebugMsg("Initializing Revocation Tree Users")

			A, err = client.InitUser("A", defaultPassword2)
			Expect(err).To(BeNil())
			B, err = client.InitUser("B", defaultPassword2)
			Expect(err).To(BeNil())
			C, err = client.InitUser("C", defaultPassword2)
			Expect(err).To(BeNil())
			D, err = client.InitUser("D", defaultPassword2)
			Expect(err).To(BeNil())
			E, err = client.InitUser("E", defaultPassword2)
			Expect(err).To(BeNil())
			F, err = client.InitUser("F", defaultPassword2)
			Expect(err).To(BeNil())
			G, err = client.InitUser("G", defaultPassword2)
			Expect(err).To(BeNil())

			err = A.StoreFile("foods.txt", []byte("eggs"))
			Expect(err).To(BeNil())

			invitationPtr, err = A.CreateInvitation("foods.txt", "B")
			Expect(err).To(BeNil())
			err = B.AcceptInvitation("A", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())

			invitationPtr, err = A.CreateInvitation("foods.txt", "C")
			Expect(err).To(BeNil())
			err = B.AcceptInvitation("C", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())

			invitationPtr, err = C.CreateInvitation("foods.txt", "G")
			Expect(err).To(BeNil())
			err = G.AcceptInvitation("C", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())

			invitationPtr, err = B.CreateInvitation("foods.txt", "D")
			Expect(err).To(BeNil())
			err = D.AcceptInvitation("B", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())

			invitationPtr, err = B.CreateInvitation("foods.txt", "E")
			Expect(err).To(BeNil())
			err = E.AcceptInvitation("B", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())

			invitationPtr, err = D.CreateInvitation("foods.txt", "F")
			Expect(err).To(BeNil())
			err = F.AcceptInvitation("D", invitationPtr, "snacks.txt")
			Expect(err).To(BeNil())

			err = A.RevokeAccess("foods.txt", "B")
			Expect(err).To(BeNil())
			err = A.RevokeAccess("foods.txt", "C")

			loadedFile, err := B.LoadFile("snacks.txt")
			Expect(err).ToNot(BeNil())
			//possible error here, it should just error out and not return anything
			Expect(loadedFile).To(BeFalse())

			err = D.AppendToFile("snacks.txt", []byte("this is a mistake"))
			Expect(err).ToNot(BeNil())
			E.CreateInvitation("snacks.txt", "B")
			Expect(err).ToNot(BeNil())
		})

	})
	/*---------------------------Bandwidth Test ---------------------------------*/
	Describe("Bandwidth/Efficiency Test", func() {
		/*
		   The total bandwidth should not scale with (including but not limited to):
		       Total file size
		       Number of files
		       Length of the filename
		       Number of appends
		       Size of previous append
		       Length of username
		       Length of password
		       Number of users the file is shared with
		*/
		//helper function
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}
		/*ADD testing for file adding, and for length of the file name and scaling with the size of a previous append and the number of users the file is shared with */
		Specify("Append shouldn't scale with the quantity of files", func() {
			userlib.DebugMsg("Append should not scale with the number of files")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("")
		})

		Specify("Append shouldn't scale with size of file but by what is added", func() {
			userlib.DebugMsg("The total bandwidth should only scale with the size of the append and not number of appends either")
			userlib.DebugMsg("Creating a 10k byte and a 1 byte file")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bigBandwidth := measureBandwidth(func() {
				err = alice.StoreFile(aliceFile, userlib.RandomBytes(10000))
				Expect(err).To(BeNil())
			})
			userlib.DebugMsg("bandwidth of 10000 byte file", bigBandwidth)
			smallBandwidth := measureBandwidth(func() {
				err = bob.StoreFile(bobFile, []byte(("A")))
				Expect(err).To(BeNil())
			})
			userlib.DebugMsg("bandwidth of 1 byte file", smallBandwidth)
			userlib.DebugMsg("Adding bytes to each file to check bandwidth")
			//10000 growth
			err = alice.StoreFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())
			var newAdded [10000]int
			for i := 0; i < 10000; i++ {
				newAdded[i] = measureBandwidth(func() {
					err = alice.AppendToFile(aliceFile, []byte("V"))
					Expect(err).To(BeNil())
				})
			}
			userlib.DebugMsg("Difference from the 0th and 9999th append: " + strconv.Itoa(newAdded[0]-newAdded[9999]))

		})
	})

	/*---------------------------Failure Cases --------------------------------*/
	Describe("Failure Cases", func() {
		Specify("InitUser existing username error", func() {
			userlib.DebugMsg("Testing InitUser where there is no existing username")
			userlib.DebugMsg("Initializing user with a new username")
			EvanBot, err = client.InitUser("EvanBot", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with an existing username and new password")
			CodaBot, err = client.InitUser("EvanBot", defaultPassword2)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Initializing user with an existing username and existing password")
			CodaBot, err = client.InitUser("EvanBot", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("InitUser empty username error", func() {
			userlib.DebugMsg("Testing InitUser where there is no initialized user for the given username")
			userlib.DebugMsg("Initializing user with an empty username")
			EvanBot, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("GetUser user does not exist error", func() {
			userlib.DebugMsg("Testing GetUser where there is no initialized user for the given username")
			userlib.DebugMsg("Initializing user")
			EvanBot, err = client.GetUser("Garbage Username", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("GetUser credentials invalid error", func() {
			userlib.DebugMsg("Testing GetUser invalid credentials")
			userlib.DebugMsg("Initializing user")
			EvanBot, err = client.InitUser("Evanbot", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user with incorrect password")
			EvanBot, err = client.GetUser("Evanbot", defaultPassword2)
			Expect(err).ToNot(BeNil())
		})
		Specify("GetUser integrity error", func() {
			userlib.DebugMsg("Testing GetUser where the User struct cannot be obtained due to malicious action, or the integrity of the user struct has been compromised")
			userlib.DebugMsg("Initializing user")
			EvanBot, err = client.InitUser("EvanBot", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Corrupting user data")
			userUUID := EvanBot.UserUUID
			data, err := userlib.DatastoreGet(userUUID)
			Expect(err).To(BeNil())

			// Modify the data to simulate corruption
			corruptedData := append(data, []byte("corruption")...)
			userlib.DatastoreSet(userUUID, corruptedData)

			userlib.DebugMsg("Getting corrupted user")
			EvanBot, err = client.GetUser("EvanBot", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("LoadFile filename does not exist error", func() {
			userlib.DebugMsg("Testing LoadFile where the given filename does not exist in the personal file namespace of the caller")
			userlib.DebugMsg("Initializing user")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting file name")
			content, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
		Specify("LoadFile tampering error", func() {
			userlib.DebugMsg("Testing LoadFile where the integrity of the downloaded content cannot be verified")
			userlib.DebugMsg("Initializing user")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//corrupt alicefile here
		})

		Specify("AppendToFile filename does not exist error", func() {
			userlib.DebugMsg("Testing AppendToFile where the given filename does not exist in the personal file namespace of the caller")
			userlib.DebugMsg("Initializing user")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Appending to nonexistent file")
			 err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})
		//Append to File with corruption error testing
		Specify("CreateInvitation filename does not exist error", func() {
			userlib.DebugMsg("Testing CreateInvitation where the given filename does not exist in the personal file namespace of the caller")
			userlib.DebugMsg("Initializing user")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Creating Invitation to nonexistent file")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
		Specify("CreateInvitation file recipient does not exist error", func() {
			userlib.DebugMsg("Testing CreateInvitation where the given recipientUsername does not exist")
			userlib.DebugMsg("Initializing user")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing File")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Creating Invitation with nonexistent recipient")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "dummy recipient")
			Expect(err).ToNot(BeNil())
		})
		//CreateInvitiation with corruption error testing
		Specify("AcceptInvitation filename already exists error", func() {
			userlib.DebugMsg("Testing AcceptInvitation where the user already has a file with the chosen filename in their personal file namespace")
			userlib.DebugMsg("Initializing user 1")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user")
			bob, err = client.InitUser("Bob", defaultPassword2)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Creating invitatation")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			bob.StoreFile(aliceFile, []byte(contentOne))
			//create existing file, and invitation from external user
	})

})
