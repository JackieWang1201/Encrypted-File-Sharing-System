package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)


func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
	magic_string, err = u.ShareFile("file11111", "bob")
	if err == nil {
		t.Error("file should not exist", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string + "wrong")
	if err == nil {
		t.Error("wrong magic string", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	err = u2.AppendFile("file2", []byte{1,1,1,1})
	if err != nil {
		t.Error("Failed to append the file", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is not the same", v1, v2)
		return
	}


}

func TestAppend(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	//v := []byte("This is a test")
	v, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load the file", err)
		return
	}
	vp := []byte("This is a test for append the file")
	err = u.AppendFile("file1111", vp)
	if err == nil {
		t.Error("file should not exist", err)
		return
	}
	err = u.AppendFile("file1", vp)
	if err != nil {
		t.Error("Failed to append the file", err)
		return
	}

	v2, err2 := u.LoadFile("file11111")
	if err2 == nil {
		t.Error("file should not exist", err2)
		return
	}
	v2, err2 = u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	v = append(v, vp...)
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}


	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	v3, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}


}

func TestRevoke(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	v2, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is not the same", v1, v2)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}
	//
	//err = u.RevokeFile("file1", "bobbbbbbb") ///////???????
	//if err == nil {
	//	t.Error("have already been revoked", err)
	//	return
	//}

	// user2 "bob" should not load file after been revoked
	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user2 "bob" should not append file after been revoked
	v := []byte("should be unable to append the file")
	err = u2.AppendFile("file2", v)
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user2 "bob" should not share file after been revoked
	u3, err := InitUser("clare", "ccc")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	magic_string, err := u2.ShareFile("file2", "clare")
	if err == nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err == nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	_, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}


}


// a --> b --> c
func TestShare2(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err2 := GetUser("clare", "ccc")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	magic_string, err := u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2_2", "alice", magic_string) // name file2 has been used!
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	err = u3.ReceiveFile("file2_2", "alice", magic_string) // !!!!!!!!!!
	//if err == nil {
	//	t.Error("should not receive the share message", err)
	//	return
	//}
	//err = u3.ReceiveFile("file3", "alice", magic_string)
	//if err == nil {
	//	t.Error("should not receive the share message", err)
	//	return
	//}


	magic_string, err = u2.ShareFile("file2_2", "clare")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err := u2.LoadFile("file2_2") //?
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v1, err := u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v2, v3)
		return
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is not the same", v2, v3)
		return
	}

}

// a --> b --> c
func TestRevoke2(t *testing.T) {
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u3, err2 := GetUser("clare", "ccc")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	_, err = u2.LoadFile("file2_2") //?
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	err = u1.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}

	_, err = u2.LoadFile("file2_2")
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user3 "clare" should not load file after been revoked
	_, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user3 "clare" should not append file after been revoked
	v := []byte("should be unable to append the file")
	err = u3.AppendFile("file3", v)
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user3 "clare" should not share file after been revoked
	u4, err := InitUser("david", "ddd")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	magic_string, err := u3.ShareFile("file3", "david")
	if err == nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	err = u4.ReceiveFile("file4", "clare", magic_string)
	if err == nil {
		t.Error("Failed to revoke the file", err)
		return
	}
	_, err = u4.LoadFile("file4")
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}



}

func TestAttack(t *testing.T) {
	u1, err := GetUser("alice", "fffff")
	if err == nil {
		t.Error("it should be wrong password", err)
		return
	}
	u1, err = GetUser("aliceeeeeeee", "fffff")
	if err == nil {
		t.Error("it should be wrong password", err)
		return
	}
	u1, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	_, err = u2.LoadFile("file222222") //?
	if err == nil {
		t.Error("should be no file", err)
		return
	}

	err = u1.RevokeFile("file1111", "bob")
	if err == nil {
		t.Error("should be no file", err)
		return
	}


	var magic_string string

	magic_string, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2_3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	//fileMeta, _ := userlib.DatastoreGet(u2.UserFile["file2_3"].FileMeta_UUID)
	//fileUUID := fileMeta.
	//
	//nothing := []byte{1,1,1,1,1,1,1}
	//userlib.DatastoreSet(u2.UserFile["file2"].FileMeta_UUID, nothing)
	//_, err = u1.LoadFile("file1")
	//if err == nil {
	//	t.Error("should be integrityError", err)
	//	return
	//}


}

func TestSameUsername(t *testing.T) {
	_, err := InitUser("alice", "fr")
	if err == nil {
		// t.Error says the test fails
		t.Error("same username", err)
		return
	}
}


func TestServer2(t *testing.T){
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("integrity error", err)
		return
	}
	u3, err := GetUser("clare", "ccc")
	if err != nil {
		t.Error("integrity error", err)
		return
	}
	v1, err2 := u1.LoadFile("file1")
	if err2 != nil {
		t.Error("integrity error", err2)
		return
	}
	datastore:=userlib.DatastoreGetMap()
	for i,_:=range datastore{
		userlib.DatastoreDelete(i)
	}
	u2, err := GetUser("bob", "foobar")
	if err == nil {
		t.Error("integrity error", err)
		return
	}

	v2, err2 := u1.LoadFile("file1")
	if err2 == nil {
		t.Error("integrity error", err2)
		return
	}
	if reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is the same", v1, v2)
		return
	}


	magic_string, err := u1.ShareFile("file1", "bob")
	if err == nil {
		t.Error(err)
		return
	}
	err = u2.ReceiveFile("file2_4", "alice", magic_string)
	if err == nil {
		t.Error(err)
		return
	}
	vp := []byte("This is a test for append the file")
	err = u2.AppendFile("file2_4", vp)
	if err == nil {
		t.Error("integrityErr", err)
		return
	}
	v1 = append(v1, vp...)
	if reflect.DeepEqual(v1, v2) {
		t.Error("Integrity Error", v1, v2)
		return
	}

	err = u1.RevokeFile("file1", "bob")
	if err == nil {
		t.Error("integrity", err)
		return
	}


	// user2 "bob" should not load file after been revoked
	_, err = u2.LoadFile("file2_4")
	if err == nil {
		t.Error("integrity", err)
		return
	}

	// user2 "bob" should not append file after been revoked
	v := []byte("should be unable to append the file")
	err = u2.AppendFile("file2_4", v)
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user2 "bob" should not share file after been revoked

	magic_string, err = u2.ShareFile("file2_4", "clare")
	if err == nil {
		t.Error("integrity", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err == nil {
		t.Error("integrity", err)
		return
	}
	_, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("integrity", err)
		return
	}


}




func TestServer(t *testing.T){
	u1, err := InitUser("al", "a")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err := InitUser("bo", "b")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	u3, err := InitUser("cl", "c")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("This is a test")
	u1.StoreFile("file1", v)


	v1, err2 := u1.LoadFile("file1")
	if err2 != nil {
		t.Error("integrity error", err2)
		return
	}


	datastore:=userlib.DatastoreGetMap()
	for i,_:=range datastore{
		userlib.DatastoreSet(i,[]byte{1,2,3,3,4})
	}
	u2, err = GetUser("bo", "foobar")
	if err == nil {
		t.Error("integrity error", err)
		return
	}

	v2, err2 := u1.LoadFile("file1")
	if err2 == nil {
		t.Error("integrity error", err2)
		return
	}
	if reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is the same", v1, v2)
		return
	}


	magic_string, err := u1.ShareFile("file1", "bo")
	if err == nil {
		t.Error(err)
		return
	}
	err = u2.ReceiveFile("file2_4", "al", magic_string)
	if err == nil {
		t.Error(err)
		return
	}
	vp := []byte("This is a test for append the file")
	err = u2.AppendFile("file2_4", vp)
	if err == nil {
		t.Error("integrityErr", err)
		return
	}
	v1 = append(v1, vp...)
	if reflect.DeepEqual(v1, v2) {
		t.Error("Integrity Error", v1, v2)
		return
	}

	err = u1.RevokeFile("file1", "bo")
	if err == nil {
		t.Error("integrity", err)
		return
	}


	// user2 "bob" should not load file after been revoked
	_, err = u2.LoadFile("file2_4")
	if err == nil {
		t.Error("integrity", err)
		return
	}

	// user2 "bob" should not append file after been revoked
	v = []byte("should be unable to append the file")
	err = u2.AppendFile("file2_4", v)
	if err == nil {
		t.Error("Failed to revoke file", err)
		return
	}

	// user2 "bob" should not share file after been revoked

	magic_string, err = u2.ShareFile("file2_4", "clare")
	if err == nil {
		t.Error("integrity", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err == nil {
		t.Error("integrity", err)
		return
	}
	_, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("integrity", err)
		return
	}


}




