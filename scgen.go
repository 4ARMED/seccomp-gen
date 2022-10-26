package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/4armed/seccomp-gen/seccomp"
	"github.com/4armed/seccomp-gen/seccomp/syscalls"
	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
)

var requiredSyscalls = []string{
	"capget",
	"capset",
	"chdir",
	"execve",
	"fchown",
	"futex",
	"getdents64",
	"getpid",
	"getppid",
	"lstat",
	"openat",
	"prctl",
	"setgid",
	"setgroups",
	"setuid",
	"stat",
}

func unique(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

func init() {
	log.SetHandler(clihander.Default)
}

func main() {

	var sc string
	var scs []string

	verbosePtr := flag.Bool("verbose", false, "verbose output")
	processSyslog := flag.Bool("syslog", false, "process syslog output")
	flag.Parse()

	var re *regexp.Regexp

	if *processSyslog {
		re = regexp.MustCompile(`syscall=([0-9]+)`)
	} else {
		re = regexp.MustCompile(`^[a-zA-Z_]+\(`)
	}

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := scanner.Text()
		if *processSyslog {
			matches := re.FindStringSubmatch(line)
			if *verbosePtr {
				log.Infof("matched syscall %s", matches[1])
			}
			if len(matches) > 0 {
				i, _ := strconv.Atoi(matches[1])
				if sc, ok := syscalls.IsValidByNumber(i); ok {
					scs = unique(scs, sc)
				}
			}
		} else {
			sc = strings.TrimRight(re.FindString(line), "(")
			if len(sc) > 0 {
				if syscalls.IsValid(sc) {
					scs = unique(scs, sc)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	for _, sc := range scs {
		if *verbosePtr {
			log.Infof("found syscall: %s", sc)
		}
		requiredSyscalls = unique(requiredSyscalls, sc)
	}

	sort.Strings(requiredSyscalls)

	// write out to file
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	f := filepath.Join(wd, "seccomp.json")

	// write the default profile to the file
	b, err := json.MarshalIndent(seccomp.DefaultProfile(requiredSyscalls, runtime.GOARCH), "", "\t")
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(f, b, 0644); err != nil {
		panic(err)
	}
}
