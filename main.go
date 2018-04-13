package main

import (
  "os"
  "syscall"
  "fmt"
  "crypto/rand"
  "github.com/lottspot/shadowdb"
  "github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

const PWBYTES int = 32
var PROG string = os.Args[0]

func main() {
  shadowPath := "/etc/shadow"
  db := shadowdb.NewDB()
  shadowFile, e := os.Open(shadowPath)
  if e == nil {
    syscall.Flock(int(shadowFile.Fd()), syscall.LOCK_SH)
    e := db.Load(shadowFile)
    syscall.Flock(int(shadowFile.Fd()), syscall.LOCK_UN)
    shadowFile.Close()
    if e != nil {
      die("error reading shadow file " + shadowPath + ": " + e.Error())
    }
  } else if !os.IsNotExist(e) {
    die("open " + shadowPath + ": " + e.Error())
  }
  root   := db.User("root")
  pwhash := genPwhash()
  if pwhash == "" {
    die("failed to generate password hash")
  }
  root.SetUname("root")
  root.SetPwhash(pwhash)
  db.ApplyRecord(&root)
  shadowFile, e = os.Create(shadowPath)
  if e == nil {
    syscall.Flock(int(shadowFile.Fd()), syscall.LOCK_EX)
    e := db.Dump(shadowFile)
    syscall.Flock(int(shadowFile.Fd()), syscall.LOCK_UN)
    if e != nil {
      die("error writing shadow file " + shadowPath + ": " + e.Error())
    }
    return
  }
  die("open " + shadowPath + ": " + e.Error())
}

func genPwhash() string {
  passwd := make([]byte, PWBYTES)
  crypter := sha512_crypt.New()
  nbytes, _ := rand.Read(passwd)
  if nbytes != len(passwd) {
    return ""
  }
  hash, _ := crypter.Generate(passwd, []byte{})
  return hash
}

func die(msg string) {
  fmt.Printf("%s: %s\n", PROG, msg)
  os.Exit(1)
}
