/*
   Simple Netstat implementation.
   Get data from /proc/net/tcp and /proc/net/udp and
   and parse /proc/[0-9]/fd/[0-9].

   Author: Rafael Santos <rafael@sourcecode.net.br>
*/

package GOnetstat

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	PROC_TCP  = "net/tcp"
	PROC_UDP  = "net/udp"
	PROC_TCP6 = "net/tcp6"
	PROC_UDP6 = "net/udp6"
)

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type Process struct {
	User        string
	Name        string
	Pid         string
	Exe         string
	State       string
	IP          string
	Port        int64
	ForeignIP   string
	ForeignPort int64
}

func (n NetStat) getData(t string) []string {
	// Get data from tcp or udp file.

	var procT string

	if t == "tcp" {
		procT = n.getProcPath(PROC_TCP)
	} else if t == "udp" {
		procT = n.getProcPath(PROC_UDP)
	} else if t == "tcp6" {
		procT = n.getProcPath(PROC_TCP6)
	} else if t == "udp6" {
		procT = n.getProcPath(PROC_UDP6)
	} else {
		fmt.Printf("%s is a invalid type, tcp and udp only!\n", t)
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(procT)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1:]

}

func hexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return d
}

func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6], i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		i := []int64{hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func (n NetStat) findPid(paths []string, inode string) string {

	pid := "-"

	//re := regexp.MustCompile(inode)
	searchFor := "[" + inode + "]"
	for _, item := range paths {
		path, _ := os.Readlink(item)
		//out := re.FindString(path)
		out := strings.Index(path, searchFor)

		if out != -1 {
			start := len(n.procRoot)
			if !strings.HasSuffix(n.procRoot, "/") {
				start++
			}
			index := strings.Index(item[start:], "/")
			pid = item[start : start+index]
			break
		}
	}
	return pid
}

func (n NetStat) getProcessExe(pid string) string {
	exe := n.getProcPath(fmt.Sprintf("%s/exe", pid))
	path, _ := os.Readlink(exe)
	return path
}

func (n NetStat) getProcPath(relativePath string) string {
	return path.Join(n.procRoot, relativePath)
}

func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n)-1]
	return strings.Title(name)
}

func getUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return ""
	}

	return u.Username
}

func removeEmpty(array []string) []string {
	// remove empty data from line
	var result []string
	for _, i := range array {
		if i != "" {
			result = append(result, i)
		}
	}
	return result
}

func (n NetStat) netstat(t string) []*Process {
	// Return a array of Process with Name, Ip, Port, State .. etc
	// Require Root acess to get information about some processes.

	var Processes []*Process

	data := n.getData(t)

	d, err := filepath.Glob(n.getProcPath("[0-9]*/fd/[0-9]*"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, line := range data {

		lineArray := removeEmpty(strings.Split(strings.TrimSpace(line), " "))

		if len(lineArray) == 0 {
			continue
		}

		// local ip and port
		ipPort := strings.Split(lineArray[1], ":")
		ip := convertIp(ipPort[0])
		port := hexToDec(ipPort[1])

		// foreign ip and port
		fipPort := strings.Split(lineArray[2], ":")
		fip := convertIp(fipPort[0])
		fport := hexToDec(fipPort[1])

		state := STATE[lineArray[3]]
		//uid := getUser(lineArray[7])
		uid := ""
		pid := n.findPid(d, lineArray[9])
		exe := n.getProcessExe(pid)
		name := getProcessName(exe)

		p := &Process{uid, name, pid, exe, state, ip, port, fip, fport}

		Processes = append(Processes, p)

	}

	return Processes
}

type NetStat struct {
	procRoot string
}

// NewNetStat creates a new NetStat
func NewNetStat(procPath string) NetStat {

	if procPath == "" {
		procPath = "/proc"
	}

	netstat := NetStat{
		procRoot: procPath,
	}

	return netstat
}

func (n NetStat) Tcp() []*Process {
	// Get a slice of Process type with TCP data
	data := n.netstat("tcp")
	return data
}

func (n NetStat) Udp() []*Process {
	// Get a slice of Process type with UDP data
	data := n.netstat("udp")
	return data
}

func (n NetStat) Tcp6() []*Process {
	// Get a slice of Process type with TCP6 data
	data := n.netstat("tcp6")
	return data
}

func (n NetStat) Udp6() []*Process {
	// Get a slice of Process type with UDP6 data
	data := n.netstat("udp6")
	return data
}
