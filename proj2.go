package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type FileInfo struct {
	FileMeta_UUID uuid.UUID
	Seed []byte
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	PKE_Sk userlib.PKEDecKey
	DS_Sk userlib.DSSignKey
	UserFile map[string]FileInfo

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileMetaData struct {
	Owner map[string][]string
	FileUUIDs []uuid.UUID
}

type CypherText struct {
	Message []byte
	Extra []byte // mac or signature
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// initialize userdata
	userdata.Username = username
	userdata.Password = password
	userdata.UserFile = make(map[string]FileInfo)
	var PKE_Pk userlib.PKEEncKey
	PKE_Pk, userdata.PKE_Sk, err = userlib.PKEKeyGen()
	if err != nil {
		userlib.DebugMsg("unable to generate a RSA key pair for public-key encryption")
		return nil, err
	}
	err = userlib.KeystoreSet(username + "PKEEnc", PKE_Pk)
	if err != nil {
		userlib.DebugMsg("unable to store a key for public-key encryption in KeyStore")
		return nil, err
	}
	var DS_Pk userlib.DSVerifyKey
	userdata.DS_Sk, DS_Pk, err = userlib.DSKeyGen()
	if err != nil {
		userlib.DebugMsg("unable to generate a RSA key pair for digital signatures")
		return nil, err
	}
	err = userlib.KeystoreSet(username + "DSVerify", DS_Pk)
	if err != nil {
		userlib.DebugMsg("unable to store a key for digital signatures")
		return nil, err
	}

	// upload userdata to DataStore
	if uploadUserData(&userdata) != nil {
		return nil, err
	}

	return &userdata, nil
}

func uploadUserData(userdata *User) (err error) {
	if (userdata == nil) {
		return errors.New("no user")
	}

	// user uuid
	key_userUUID := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	userUUID, err := uuid.FromBytes(key_userUUID[:16])
	if err != nil {
		userlib.DebugMsg("error in uploadUserData")
		return err
	}

	// encrypt userdata
	keyEnc, err := userlib.HMACEval(userUUID[:], []byte(userdata.Username + userdata.Password + "ENC"))
	keyEnc = keyEnc[:16]
	if err != nil {
		userlib.DebugMsg("error in uploadUserData")
		return err
	}
	keyMac, err := userlib.HMACEval(userUUID[:], []byte(userdata.Username + userdata.Password + "MAC"))
	keyMac = keyMac[:16]
	if err != nil {
		userlib.DebugMsg("error in uploadUserData")
		return err
	}
	iv := userlib.RandomBytes(userlib.AESBlockSize) // len(iv) == aesblocksize => no count? CTR?
	text_userdata, err := json.Marshal(*userdata)
	if err != nil {
		userlib.DebugMsg("error in uploadUserData")
		return err
	}
	C := userlib.SymEnc(keyEnc, iv, text_userdata)
	T, err := userlib.HMACEval(keyMac, C)
	if err != nil {
		userlib.DebugMsg("error in uploadUserData")
		return err
	}
	cypher := CypherText{C, T}
	cypher_serialized, _ := json.Marshal(cypher)

	// store encrypted userdata to DataStore
	userlib.DatastoreSet(userUUID, cypher_serialized)

	return nil

}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// user uuid
	key_userUUID := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userUUID, err := uuid.FromBytes(key_userUUID[:16])
	if err != nil {
		userlib.DebugMsg("error in GetUser")
		return nil, err
	}

	// fetch userdata from DataStore
	encryptedUserData, ok := userlib.DatastoreGet(userUUID)
	if ok == false {
		userlib.DebugMsg("user can't be found")
		return nil, errors.New("can not find user")
	}

	// check integrity
	keyEnc, err := userlib.HMACEval(userUUID[:], []byte(username + password + "ENC"))
	keyEnc = keyEnc[:16]
	if err != nil {
		userlib.DebugMsg("error in GetUser")
		return nil, err
	}
	keyMac, err := userlib.HMACEval(userUUID[:], []byte(username + password + "MAC"))
	keyMac = keyMac[:16]
	if err != nil {
		userlib.DebugMsg("error in GetUser")
		return nil, err
	}
	var cypher CypherText
	_ = json.Unmarshal(encryptedUserData, &cypher)
	C := cypher.Message
	T := cypher.Extra
	newT, err := userlib.HMACEval(keyMac, C)
	if err != nil {
		userlib.DebugMsg("error in GetUser")
		return nil, err
	}
	if !userlib.HMACEqual(T, newT) {
		userlib.DebugMsg("the integrity was violated, the userdata was corrupted")
		return nil, errors.New("the integrity was violated, the userdata was corrupted")

	}

	// decrypt userdata
	plaintext := userlib.SymDec(keyEnc, C)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		userlib.DebugMsg("error in GetUser")
		return nil, err
	}
	if userdata.Username != username || userdata.Password != password { // possible?
		userlib.DebugMsg("user/password is invalid")
		return nil, errors.New("user/password is invalid")
	}



	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	if (userdata == nil) {
		return
	}
	// update userdata
	userdata.UserFile[filename] = FileInfo{ // what if file not exists?
		uuid.New(),
		userlib.RandomBytes(8)} //length?
	_ = uploadUserData(userdata)

	// initialize fileMetaData
	var fileMeta FileMetaData
	fileMeta.Owner = make(map[string][]string)
	fileMeta.Owner[userdata.Username] = make([]string, 0, 2)
	fileMeta.FileUUIDs = make([]uuid.UUID, 0, 3)
	fileMeta.FileUUIDs = append(fileMeta.FileUUIDs, uuid.New())

	// upload fileMetaData
	uploadFileMetaData(&fileMeta, userdata.UserFile[filename].FileMeta_UUID, userdata.UserFile[filename].Seed)

	// upload file
	uploadFile(data, fileMeta.FileUUIDs[0], userdata.UserFile[filename].Seed)


	return
}

func uploadFileMetaData(fileMeta *FileMetaData, fileMetaUUID uuid.UUID, seed []byte) {
	// encrypt fileMeta
	keyEnc, err := userlib.HMACEval(fileMetaUUID[:], []byte(string(seed) + "ENC"))
	keyEnc = keyEnc[:16]
	if err != nil {
		userlib.DebugMsg("error in uploadfileMetaData")
	}
	keyMac, err := userlib.HMACEval(fileMetaUUID[:], []byte(string(seed) + "MAC"))
	keyMac = keyMac[:16]
	if err != nil {
		userlib.DebugMsg("error in uploadfileMetaData")
	}
	iv := userlib.RandomBytes(userlib.AESBlockSize) // len(iv) == aesblocksize => no count? CTR?
	text_fileMeta, err := json.Marshal(*fileMeta)
	if err != nil {
		userlib.DebugMsg("error in uploadfileMetaData")
	}
	C := userlib.SymEnc(keyEnc, iv, text_fileMeta)
	T, err := userlib.HMACEval(keyMac, C)
	if err != nil {
		userlib.DebugMsg("error in uploadfileMetaData")
	}
	cypher := CypherText{C, T}
	cypher_serialized, _ := json.Marshal(cypher)

	// store encrypted fileMetaData to DataStore
	userlib.DatastoreSet(fileMetaUUID, cypher_serialized)

}

func uploadFile(data []byte, fileUUID uuid.UUID, seed []byte) {
	// encrypt file
	keyEnc, err := userlib.HMACEval(fileUUID[:], []byte(string(seed) + "ENC")) // same seed?
	keyEnc = keyEnc[:16]
	if err != nil {
		userlib.DebugMsg("error in uploadfile")
	}
	keyMac, err := userlib.HMACEval(fileUUID[:], []byte(string(seed) + "MAC"))
	keyMac = keyMac[:16]
	if err != nil {
		userlib.DebugMsg("error in uploadfile")
	}
	iv := userlib.RandomBytes(userlib.AESBlockSize) // len(iv) == aesblocksize => no count? CTR?
	C := userlib.SymEnc(keyEnc, iv, data)
	T, err := userlib.HMACEval(keyMac, C)
	if err != nil {
		userlib.DebugMsg("error in uploadfile")
	}
	cypher := CypherText{C, T}
	cypher_serialized, _ := json.Marshal(cypher)

	// store encrypted file to DataStore
	userlib.DatastoreSet(fileUUID, cypher_serialized)


}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	if (userdata == nil) {
		return errors.New("no user")
	}
	// download fileMetaData
	fileInfo, ok := userdata.UserFile[filename]
	if ok == false {
		userlib.DebugMsg("can not find the file")
		return errors.New("can not find the file")
	}
	fileMeta, err := downloadFileMetaData(fileInfo.FileMeta_UUID, fileInfo.Seed)
	if err != nil {
		return errors.New("error in AppendFile")
	}
	_, ok = fileMeta.Owner[userdata.Username]
	if !ok {
		userlib.DebugMsg("the user is not allowed to append the file")
		return errors.New("the user is not allowed to append the file")
	}

	// update file metadata
	newFileUUID := uuid.New()
	fileMeta.FileUUIDs = append(fileMeta.FileUUIDs, newFileUUID)
	uploadFileMetaData(fileMeta, fileInfo.FileMeta_UUID, fileInfo.Seed)

	// add new file
	uploadFile(data, newFileUUID, fileInfo.Seed)

	return
}

func downloadFileMetaData(fileMetaUUID uuid.UUID, seed []byte) (fileMetaPtr *FileMetaData, err error) {
	var fileMeta FileMetaData
	fileMetaPtr = &fileMeta

	// fetch metadata from DataStore
	encryptedFileMeta, ok := userlib.DatastoreGet(fileMetaUUID)
	if ok == false {
		userlib.DebugMsg("file metadata can't be found")
		return nil, errors.New("file metadata can't be found")
	}

	// check integrity
	keyEnc, err := userlib.HMACEval(fileMetaUUID[:], []byte(string(seed) + "ENC"))
	keyEnc = keyEnc[:16]
	if err != nil {
		userlib.DebugMsg("error in downloadFileMetaData")
		return nil, err
	}
	keyMac, err := userlib.HMACEval(fileMetaUUID[:], []byte(string(seed) + "MAC"))
	keyMac = keyMac[:16]
	if err != nil {
		userlib.DebugMsg("error in downloadFileMetaData")
		return nil, err
	}
	var cypher CypherText
	_ = json.Unmarshal(encryptedFileMeta, &cypher)
	C := cypher.Message
	T := cypher.Extra
	newT, err := userlib.HMACEval(keyMac, C)
	if err != nil {
		userlib.DebugMsg("error in downloadFileMetaData")
		return nil, err
	}
	if !userlib.HMACEqual(T, newT) {
		userlib.DebugMsg("the integrity was violated, the file metadata was corrupted")
		return nil, errors.New("the integrity was violated, the file metadata was corrupted")

	}

	// decrypt fileMetaData
	plaintext := userlib.SymDec(keyEnc, C)
	err = json.Unmarshal(plaintext, &fileMeta)
	if err != nil {
		userlib.DebugMsg("error in downloadFileMetaData")
		return nil, err
	}


	return fileMetaPtr, nil

}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	if (userdata == nil) {
		return nil, errors.New("no user")
	}
	file := ""
	// fetch metadata
	fileInfo, ok := userdata.UserFile[filename]
	if ok == false {
		userlib.DebugMsg("can not find the file")
		return nil, errors.New("can not find the file")
	}
	fileMeta, err := downloadFileMetaData(fileInfo.FileMeta_UUID, fileInfo.Seed)
	if err != nil {
		return nil, errors.New("error in LoadFile")
	}
	// check permission
	_, ok = fileMeta.Owner[userdata.Username]
	if !ok {
		userlib.DebugMsg("the user is not allowed to load the file")
		return nil, errors.New("the user is not allowed to load the file")
	}
	for _, fileUUID := range fileMeta.FileUUIDs {
		data, err = downloadFile(fileUUID, fileInfo.Seed)
		if err != nil {
			return nil, errors.New("error in LoadFile")
		}
		file += string(data)
	}


	return []byte(file), nil
}

func downloadFile(fileUUID uuid.UUID, seed []byte) (data []byte, err error) {

	// fetch file from DataStore
	encryptedFile, ok := userlib.DatastoreGet(fileUUID)
	if ok == false {
		userlib.DebugMsg("file can't be found")
		return nil, errors.New("file can't be found")
	}

	// check integrity
	keyEnc, err := userlib.HMACEval(fileUUID[:], []byte(string(seed) + "ENC"))
	keyEnc = keyEnc[:16]
	if err != nil {
		userlib.DebugMsg("error in downloadFile")
		return nil, err
	}
	keyMac, err := userlib.HMACEval(fileUUID[:], []byte(string(seed) + "MAC"))
	keyMac = keyMac[:16]
	if err != nil {
		userlib.DebugMsg("error in downloadFile")
		return nil, err
	}
	var cypher CypherText
	_ = json.Unmarshal(encryptedFile, &cypher)
	C := cypher.Message
	T := cypher.Extra
	newT, err := userlib.HMACEval(keyMac, C)
	if err != nil {
		userlib.DebugMsg("error in downloadFile")
		return nil, err
	}
	if !userlib.HMACEqual(T, newT) {
		userlib.DebugMsg("the integrity was violated, the file was corrupted")
		return nil, errors.New("the integrity was violated, the file was corrupted")

	}

	// decrypt fileMetaData
	data = userlib.SymDec(keyEnc, C)
	//plaintext := userlib.SymDec(keyEnc, C)
	//err = json.Unmarshal(plaintext, data)
	//if err != nil {
	//	userlib.DebugMsg("error in downloadFile")
	//	return nil, err
	//}


	return data, nil

}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	if (userdata == nil) {
		return "", errors.New("no user")
	}
	// get file metadata
	fileInfo, ok := userdata.UserFile[filename]
	if ok == false {
		userlib.DebugMsg("can not find the file")
		return "", errors.New("can not find the file")
	}
	fileMeta, err := downloadFileMetaData(fileInfo.FileMeta_UUID, fileInfo.Seed)
	if err != nil {
		return "", errors.New("error in ShareFile")
	}

	// update file metadata to grant permission to recipient
	shareTo, ok := fileMeta.Owner[userdata.Username]
	if !ok {
		userlib.DebugMsg("the user is not allowed to share the file")
		return "", errors.New("the user is not allowed to share the file")
	}
	existed := false
	for _, shared := range shareTo {
		if shared == recipient {
			existed = true
			continue
		}
	}
	if existed == false {
		fileMeta.Owner[userdata.Username] = append(shareTo, recipient)
		fileMeta.Owner[recipient] = make([]string, 0, 2)
	}
	uploadFileMetaData(fileMeta, fileInfo.FileMeta_UUID, fileInfo.Seed)

	// share magic string
	magic_string_plain, _ := json.Marshal(fileInfo)
	keyEnc, ok := userlib.KeystoreGet(recipient + "PKEEnc")
	if !ok {
		userlib.DebugMsg("can not find recipient's public key for public key encryption")
		return "", errors.New("can not find recipient's public key for public key encryption")
	}
	C1, err := userlib.PKEEnc(keyEnc, magic_string_plain)
	if err != nil {
		userlib.DebugMsg("error in ShareFile")
		return "", err
	}
	C2, err := userlib.DSSign(userdata.DS_Sk, C1)
	if err != nil {
		userlib.DebugMsg("error in ShareFile")
		return "", err
	}
	cypher := CypherText{C1, C2}

	C, _ := json.Marshal(cypher)
	magic_string = string(C)

	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	if (userdata == nil) {
		return errors.New("no user")
	}
	// check filename
	_, ok := userdata.UserFile[filename]
	if ok {
		userlib.DebugMsg("the filename has already been used")
		return errors.New("the filename has already been used")
	}

	// verify magic string
	keyVerify, ok := userlib.KeystoreGet(sender + "DSVerify")
	if !ok {
		userlib.DebugMsg("can not find sender's public key for digital signature")
		return errors.New("can not find sender's public key for digital signature")
	}
	var cypher CypherText
	_ = json.Unmarshal([]byte(magic_string), &cypher)

	err := userlib.DSVerify(keyVerify, cypher.Message, cypher.Extra)
	if err != nil {
		userlib.DebugMsg("integrity and authenticity were violated")
		return err
	}

	// decrypt magic string
	fileInfo_plain, err := userlib.PKEDec(userdata.PKE_Sk, cypher.Message)
	var fileInfo FileInfo
	_ = json.Unmarshal(fileInfo_plain, &fileInfo)

	// update userdata
	userdata.UserFile[filename] = fileInfo
	err = uploadUserData(userdata)
	if err != nil {
		userlib.DebugMsg("error in ReceiveFile")
		return err
	}

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	if (userdata == nil) {
		return errors.New("no user")
	}
	// get file metadata
	fileInfo, ok := userdata.UserFile[filename]
	if ok == false {
		userlib.DebugMsg("can not find the file")
		return errors.New("can not find the file")
	}
	fileMeta, err := downloadFileMetaData(fileInfo.FileMeta_UUID, fileInfo.Seed)
	if err != nil {
		return errors.New("error in RevokeFile")
	}

	// update file metadata to revoke access
	shareTo, ok := fileMeta.Owner[userdata.Username]
	if !ok {
		userlib.DebugMsg("the user is not allowed to revoke the access to this file")
		return errors.New("the user is not allowed to revoke the access to this file")
	}

	//_, ok = fileMeta.Owner[target_username]
	//if ok {
	//	delete(fileMeta.Owner, target_username)
	//}

	newShareTo := make([]string, 0, 2)
	for _, shared := range shareTo {
		if shared != target_username {
			newShareTo = append(newShareTo, shared)
		}
	}
	fileMeta.Owner[userdata.Username] = newShareTo
	revoke(&fileMeta.Owner, target_username)
	uploadFileMetaData(fileMeta, fileInfo.FileMeta_UUID, fileInfo.Seed)



	return nil
}

func revoke(owner *map[string][]string, target_name string) {
	shareTo, ok := (*owner)[target_name]
	if !ok {
		return
	}

	for _, shared := range shareTo {
		// shareToUser, ok = (*owner)[shared]
		revoke(owner, shared)
		//if ok {
		//	revoke(owner, shared)
		//}
	}
	delete(*owner, target_name)
}
