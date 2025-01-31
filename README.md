# File Share
Authors: Viviana Tran and Cameron Leung
Changes Made in client/client.go, client_test/client_test.go

Context: 
Design a system that allows users to securely store and share files in the presence of attackers.
Problems to Solve: The system must be able to create a new user, let the user log in, store files with a filename and file contents, load the file, add to the existing file maintaining bandwidth, generate a unique invitation for target users, allow users to accept the invitation and relabel it with a new filename, and the ability to revoke access from the owner to direct descendents. In addition to this, the program must be able to detect changes in its database BEFORE information is stored and alert the user.

Givens: 
* A set of given functions can be found here https://fa24.cs161.org/proj2/library/
* Datastore: a vulnerable database that must be used to store user information and file information
* Keystore: a permanent databse used to store key value pairs
* There is a secure third party to send shared invitations
* There are no concurrency issues
* Adversaries like the ones that attack the database or try to get access to a revoked file do not collude
* All Users must be unique

Design Doc:
https://docs.google.com/document/d/1ccsrBrP9gO5fllXj4q7VFRRKE6NkKiEtW3IKCTI1Y9Y/edit?tab=t.0#heading=h.ltxemz5n3xbn

Code Explanation:
https://tinyurl.com/capella-space

Growth:
This final design is our third iteration to solve this problem. Some improvements include us growing from directly storing all information in the datastore to algorithmically rederiving keys, from storing all shared users in a list to creating a tree-like structure of users and their filenames, and from creating nodes of the tree each time a user shares to one pointer that directs to all the descendants if you are the owner or a pointer to your shared node if you are a user.


Key Learning Points:
* K.I.S.S (keep it simple, stupid)
* Design before you code and as you code, communicate for feedback
