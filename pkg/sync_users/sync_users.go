package sync_users

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/appvia/aws_usersync/pkg/log"
)

// Constants AuthorizedKeysFile and the sshdir extension
const (
	AuthorizedKeysFile = "authorized_keys"
	SSHDir             = ".ssh"
)

// Define variables for host commands and arguments
var (
	userAddCmd string
	groupAddCmd string
	userDelCmd string
	userAddArgs []string
	groupAddArgs []string
	userDelArgs []string
)

// UserList structure to hold the details of aws users, local users and ignored users
type UserList struct {
	IgnoredUsers []string
	AwsUsers     []string
	LocalUsers   []string
}

type awsUser struct {
	iamUser   string
	Group     string
	SudoGroup string
	Keys      []string
	localUser *user.User
}

func init() {
	if err := setHostCommands(); err != nil {
		log.Fatal(fmt.Sprintf("Failed trying to set host commands: %v", err))
	}
}

// alpine's commands are slightly different to other linux distros so if we're running inside
// a docker container, set the exec commands to the alpine versions
func setHostCommands() error {
	container, err := runningInContainer()
	if err != nil {
		log.Error("Could not determine if running inside a docker container or not")
		return err
	}

	if container == true {
		// set to alpine commands
		log.Debug("Running in a container, using alpine Linux commands...")
		userAddCmd = "adduser"
		userAddArgs = []string{"-D", "-s", "/bin/bash"} // don't set a password, set login shell to /bin/bash
		groupAddCmd = "addgroup"
		userDelCmd = "deluser"
		userDelArgs = []string{"--remove-home"}
	} else {
		log.Debug("Not running in a container, using standard Linux commands...")
		userAddCmd = "useradd"
		userAddArgs = []string{"-p", "123", "-U", "-m"} // set pass to 123, create home dir
		groupAddCmd = "usermod"
		groupAddArgs = []string{"-a", "-G"}
		userDelCmd = "userdel"
		userDelArgs = []string{"-r"}
	}
	return nil
}

// Check whether this is running in a docker container or not
func runningInContainer() (bool, error) {
	_, err := exec.Command("grep", "-q", "docker", "/proc/1/cgroup").Output()
	if err != nil {
		if err.Error() == "exit status 1" {
			// not running in a docker container
			return false, nil
		} else {
			// something went wrong
			return false, err
		}
	} else {
		// running in a docker container
		return true, nil
	}
}

// Initiate the user function
func New(user string, group string, sgroup string, keys []string) *awsUser {
	ustruct := &awsUser{
		iamUser:   user,
		Group:     group,
		SudoGroup: sgroup,
		Keys:      keys,
	}
	return ustruct
}

// Create a compare structure
func CmpNew(iams []string, ignore []string) (*UserList, error) {
	local, err := GetAllUsers()
	if err != nil {
		return nil, err
	}
	cmp := &UserList{
		IgnoredUsers: ignore,
		AwsUsers:     iams,
		LocalUsers:   local,
	}
	return cmp, nil
}

// sshDirPath returns the path to the .ssh dir for the user.
func sshDirPath(u *user.User) string {
	return filepath.Join(u.HomeDir, SSHDir)
}

// authKeysFilePath returns the path to the authorized_keys file for the user.
func authKeysFilePath(u *user.User) string {
	return filepath.Join(sshDirPath(u), AuthorizedKeysFile)
}

// check if string is in a slice array
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Clean up any users that are no longer supposed to be on the box
func (u *UserList) Cleanup() error {
	delUsers := GetArrayDiff(u.AwsUsers, u.LocalUsers)
	for _, usr := range delUsers {
		if stringInSlice(usr, u.IgnoredUsers) {
			log.Debug(fmt.Sprintf("User %v is in ignored users %v not deleting", usr, u.IgnoredUsers))
			continue
		}
		log.Info(fmt.Sprintf("Deleting user %v from host", usr))
		if err := RemoveUser(usr); err != nil {
			return err
		}
	}
	return nil
}

// Remove users from system that are not in the group list
func RemoveUser(usr string) error {
	u, err := user.Lookup(usr)
	if err != nil {
		return err
	}

	// put arguments in the correct order
	CMD_ARGS := append(userDelArgs, u.Username)

	if _, err := exec.Command(userDelCmd, CMD_ARGS...).Output(); err != nil {
		log.Error(fmt.Sprintf("Error deleting user %v", usr))
		return err
	}
	log.Info(fmt.Sprintf("Deleted user %v", usr))
	return nil
}

// Compare the keys to find what keys are missing locally compared to what is in IAM
func GetArrayDiff(k1 []string, k2 []string) []string {
	var diff []string
	for i := 0; i < 2; i++ {
		for _, s1 := range k1 {
			found := false
			for _, s2 := range k2 {
				if s1 == s2 {
					found = true
					break
				}
			}
			// Key not found so add it to difference
			if !found {
				diff = append(diff, s1)
			}
		}
		// Swap the slices, only if it was the first loop
		if i == 0 {
			k1, k2 = k2, k1
		}
	}
	return diff
}

// Loop through the keys and call add key to add key to the box
func Keys(l *user.User, kp string, ks []string) error {
	// create ssh directory if needed
	if err := os.MkdirAll(sshDirPath(l), 700); err != nil {
		log.Debug(fmt.Sprintf("Error creating %v", sshDirPath(l)))
		return err
	}

	f, err := os.Create(kp)
	defer f.Close()
	if err != nil {
		log.Error(fmt.Sprintf("Error creating %v", kp))
		return err
	}
	log.Debug(fmt.Sprintf("Created file %v writing keys %v", kp, ks))
	w := bufio.NewWriter(f)
	for _, k := range ks {
		fmt.Fprintln(w, k)
		log.Info(fmt.Sprintf("Updating key %s for user %s", k[0:20], l.Username))
	}
	w.Flush()
	if err := setPerms(l, kp); err != nil {
		return err
	}
	return nil
}

// Set permissions on file
func setPerms(u *user.User, keypath string) error {
	gid, err := strconv.Atoi(u.Gid)
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	if err := os.Chown(keypath, uid, gid); err != nil {
		return err
	}
	return nil
}

// Get the keys of user if there are any locally if not then add keys from iam.
// if there are keys for the user then find out if there are more local keys than there are in iam in which case
// set it to replace the keys
func (l *awsUser) DoKeys() error {
	keyPath := authKeysFilePath(l.localUser)
	keys, _ := l.getKeys(keyPath)
	writekeys := true
	if keys != nil {
		if len(keys) == len(l.Keys) {
			if len(GetArrayDiff(keys, l.Keys)) == 0 {
				writekeys = false
				log.Debug("No new keys found, nothing to do")
			}
		} else {
			keys = l.Keys
		}
	} else {
		keys = l.Keys
	}
	if writekeys == true {
		if err := Keys(l.localUser, keyPath, keys); err != nil {
			return err
		}
		log.Debug(fmt.Sprintf("Adding keys %v for %v", keys, l.localUser.Username))
	}
	return nil
}

// Check if there is the authorized keys file if it is then return all the keys from it
func (l *awsUser) getKeys(keyPath string) ([]string, error) {
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, err
	} else {
		kfile, err := os.Open(keyPath)
		if err != nil {
			return nil, err
		}
		defer kfile.Close()
		var keys []string
		scanner := bufio.NewScanner(kfile)
		for scanner.Scan() {
			keys = append(keys, scanner.Text())
		}
		log.Debug(fmt.Sprintf("Current keys on host for %v  : %v", keyPath, keys))
		return keys, scanner.Err()
	}
}

func GetAllUsers() ([]string, error) {
	passwd := "/etc/passwd"
	fpasswd, err := os.Open(passwd)
	if err != nil {
		return nil, err
	}
	defer fpasswd.Close()
	var users []string
	scanner := bufio.NewScanner(fpasswd)
	for scanner.Scan() {
		users = append(users, strings.Split(scanner.Text(), ":")[0])
	}
	log.Debug(fmt.Sprintf("Got a list of local users: %v", users))
	return users, scanner.Err()
}

// Add user onto the system
func (l *awsUser) addUser() error {
	if l.localUser == nil {
		log.Info(fmt.Sprintf("Creating user %v", l.iamUser))

		// put arguments in the correct order
		CMD_ARGS := append(userAddArgs, l.iamUser)

		_, err := exec.Command(userAddCmd, CMD_ARGS...).Output()
		if err != nil {
			return err
		}

		luser, _ := user.Lookup(l.iamUser)
		l.localUser = luser
	}
	return nil
}

// Add user to sudo group
func (l *awsUser) addUserToSudoGroup() error {
	if l.localUser != nil {
		log.Info(fmt.Sprintf("Adding user %v to %v group", l.localUser.Username, l.SudoGroup))

		// put arguments in the correct order
		CMD_ARGS := append([]string{l.localUser.Username}, groupAddArgs...)
		CMD_ARGS = append(CMD_ARGS, l.SudoGroup)

		_, err := exec.Command(groupAddCmd, CMD_ARGS...).Output()
		if err != nil {
			return err
		}
	}
	return nil
}

// Sync all users and keys onto the host
func (l *awsUser) Sync() error {
	// check if the iam user has a user created for them
	usr, err := user.Lookup(l.iamUser)
	if err != nil {
		if err := l.addUser(); err != nil {
			log.Error("Failed trying to add user")
			return err
		}

		if err := l.addUserToSudoGroup(); err != nil {
			log.Error(fmt.Sprintf("Failed trying to add user %v to %v group", l.localUser.Username, l.SudoGroup))
			return err
		}
	} else {
		l.localUser = usr
	}

	if err := l.DoKeys(); err != nil {
		log.Error("Failed on calling DoKeys")
		return err
	}
	return nil
}
