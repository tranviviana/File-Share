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
	_ "strconv"
	_ "strings"
	"testing"

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

			userlib.DebugMsg("Bandwidth Efficiency Testing")
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

			EvanBotLoadFile, err := EvanBot.LoadFile("foods.txt.txt")
			Expect(EvanBotLoadFile).To(BeEquivalentTo("eggs"))

			err = EvanBot.AppendToFile("foods.txt", []byte("and bacon"))
			Expect(err).To(BeNil())
			CodaBotLoadFile, err = CodaBot.LoadFile("snacks.txt")
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
		})

	})
	/*---------------------------Failure Cases --------------------------------*/
})
