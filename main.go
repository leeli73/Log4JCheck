package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"path"
	"strings"
	"time"
)

type Log4JInfo struct {
	filepath string
	version string
	isBUG bool
	sign bool
	IP string
}

type ServerInfo struct {
	IP string
	Port string
	Username string
	Password string
	RootPassword string
	Log4jList []Log4JInfo
}

var (
	AllServer []ServerInfo
	importExcel = flag.String("file","import.xlsx","Import you server list.")
	processType = flag.String("proc","update","Input you process mode,update1:update to new log4j,update_r:update to new log4j with old filename,rm:remove JndiLookup.class")
)

func main()  {
	flag.Parse()
	readImportExcel()
}

func readImportExcel(){
	excel,err := excelize.OpenFile(*importExcel)
	if err != nil{
		log.Panicf("Read import server list error:%v\n",err)
	}
	sheetList := excel.GetSheetList()
	rows,err := excel.GetRows(sheetList[0])
	if err != nil{
		log.Panicf("Read import server list <sheet:%s> error:%v\n",sheetList[0],err)
	}
	for index,row := range rows{
		if index > 0{
			if len(row) < 5{
				log.Panicf("You server list irregularity")
			}
			AllServer = append(AllServer,ServerInfo{
				IP:row[0],
				Port:row[1],
				Username:row[2],
				Password:row[3],
				RootPassword: row[4],
				Log4jList:make([]Log4JInfo,0),
			})
		}
	}
	log.Printf("Load server count:%d\n",len(AllServer))
	bugList := []Log4JInfo{}
	log4jList := []Log4JInfo{}
	jarList := []Log4JInfo{}
	for index,info := range AllServer{
		err = ScanLog4J(index,info)
		if err != nil{
			log.Printf("Process server %s with error %v\n",info.IP,err)
		}
		for _,key := range AllServer[index].Log4jList{
			key.IP = info.IP
			if key.isBUG && key.sign{
				bugList = append(bugList,key)
				continue
			}
			if key.sign && !key.isBUG{
				log4jList = append(log4jList,key)
				continue
			}
			if !key.isBUG && !key.sign{
				jarList = append(jarList,key)
				continue
			}
		}
	}
	log.Printf("Scan finished,confirm: %d,suspected: %d,jar: %d\n",len(bugList),len(log4jList),len(jarList))
	fmt.Printf("Confirm List:\n")
	fmt.Printf("\tindex\tIP\tVersion\tPath\n")
	for index,key := range bugList{
		fmt.Printf("\t%d\t%s\t%s\t%s\n",index+1,key.IP,key.version,key.filepath)
	}
	fmt.Printf("Suspected List:\n")
	fmt.Printf("\tIndex\tIP\tVersion\tPath\n")
	for index,key := range log4jList{
		fmt.Printf("\t%d\t%s\t%s\t%s\n",index+1,key.IP,key.version,key.filepath)
	}
	if *processType == "rm"{
		fmt.Printf("Remove JndiLookup.class List:\n")
		for index,key := range bugList{
			if _,err = GetServerInfoByIP(key.IP);err != nil{
				fmt.Printf("\t%d\t%s\t%s\t%s\n",index+1,key.IP,key.version,key.filepath)
			}
		}
	}
	log.Printf("End. By Li Yilong")
}

func GetServerInfoByIP(ip string)(ServerInfo,error){
	for _,info := range AllServer{
		if info.IP == ip{
			return info,nil
		}
	}
	return ServerInfo{},nil
}

func ScanLog4J(index int,info ServerInfo) error {
	log.Printf("Start scan %s...\n",info.IP)
	client,err := ssh.Dial("tcp",fmt.Sprintf("%s:%s",info.IP,info.Port),&ssh.ClientConfig{
		User: info.Username,
		Auth: []ssh.AuthMethod{ssh.Password(info.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil{
		return err
	}
	session,err := client.NewSession()
	if err != nil{
		return err
	}
	defer session.Close()

	stdin,err := session.StdinPipe()
	stdout,err := session.StdoutPipe()
	session.Stderr = os.Stderr
	if err != nil{
		log.Fatalf("create ssh session error:%v\n",err)
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err = session.RequestPty("linux", 32, 160, modes); err != nil {
		log.Fatalf("request pty error: %s\n", err.Error())
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			output := scanner.Text()
			//log.Printf("%v\n",output)
			if strings.Contains(strings.ToUpper(output),"LOG4J") && strings.ToUpper(path.Ext(output)) == ".JAR"{
				version := checkVersion(output)
				if version != ""{
					if strings.Contains(strings.ToUpper(output),"CORE"){
						AllServer[index].Log4jList = append(AllServer[index].Log4jList,Log4JInfo{
							filepath: output,
							version: version,
							isBUG: true,
							sign: true,
						})
					} else {
						AllServer[index].Log4jList = append(AllServer[index].Log4jList,Log4JInfo{
							filepath: output,
							version: version,
							isBUG: false,
							sign: true,
						})
					}
				} else {
					//log.Printf("Find log4j jar,filename %s\n",output)
					AllServer[index].Log4jList = append(AllServer[index].Log4jList,Log4JInfo{
						filepath: output,
						version: version,
						isBUG: false,
						sign: false,
					})
				}
			}
		}
	}()
	if err = session.Shell(); err != nil {
		return err
	}
	go func() {
		stdin.Write([]byte("su\n"))
		time.Sleep(2 * time.Second)
		stdin.Write([]byte(fmt.Sprintf("%s\n\n\n\n\n",info.RootPassword)))
		time.Sleep(2 * time.Second)
		stdin.Write([]byte("find / -name *log4j*\n"))
		time.Sleep(2 * time.Second)
		stdin.Write([]byte("exit\n"))
		time.Sleep(2 * time.Second)
		stdin.Write([]byte("exit\n"))
	}()
	if err = session.Wait(); err != nil {
		return err
	}
	return nil
}

func checkVersion(name string) string {
	name = path.Base(name)
	for i:=15;i>0;i--{
		versionStr := fmt.Sprintf("2.%d",i)
		if index:=strings.Index(name,versionStr); index != -1{
			if index-2 >=0 && name[index-2:index] != "1."{
				return versionStr
			}
		}
	}
	return ""
}

func fixWithRemove(info ServerInfo,log4jinfo Log4JInfo)error{
	client,err := ssh.Dial("tcp",fmt.Sprintf("%s:%s",info.IP,info.Port),&ssh.ClientConfig{
		User: info.Username,
		Auth: []ssh.AuthMethod{ssh.Password(info.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil{
		return err
	}
	session,err := client.NewSession()
	if err != nil{
		return err
	}
	defer session.Close()
	_,err = session.Output(fmt.Sprintf("zip -q -d %s org/apache/logging/log4j/core/lookup/JndiLookup.class",log4jinfo.filepath))
	if err != nil {
		return err
	}
	return nil
}