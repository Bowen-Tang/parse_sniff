package main

import (
        "bufio"
        "encoding/json"
        "fmt"
        "os"
        "flag"
        "strings"
    "github.com/pingcap/tidb/pkg/parser"
)

type SniffEntry struct {
        CIP  string `json:"cip"`
        CPort int    `json:"cport"`
        User string `json:"user"`
        DB   string `json:"db"`
        SQL  string `json:"sql"`
        Cus  int    `json:"cus"`
}

type HostInfo struct {
        Host string `json:"host"`
        ID   int    `json:"id"`
        User string `json:"user"`
        DB   string `json:"db"`
}

type OutputEntry struct {
        ConnectionID string `json:"connection_id"`
        QueryTime    int    `json:"query_time"`
        SQL          string `json:"sql"`
        RowsSent     int    `json:"rows_sent"`
        Username     string `json:"username"`
        DBName       string `json:"dbname"`
        SQLType      string `json:"sql_type"`
}

var (
    sniffDir    string
    hostInfoDir string
    outputDir   string
)

func init() {
        flag.StringVar(&sniffDir, "sniff", ".", "Directory containing the sniff log file")
        flag.StringVar(&hostInfoDir, "hostinfo", ".", "Directory containing the host info file")
        flag.StringVar(&outputDir, "output", ".", "Directory for the output file")
}

func main() {
        flag.Parse()
        sniffFile := sniffDir
        hostInfoFile := hostInfoDir
        outputFile := outputDir

        hostInfoMap := readHostInfo(hostInfoFile)

        file, err := os.Open(sniffFile)
        if err != nil {
                panic(err)
        }
        defer file.Close()

        output, err := os.Create(outputFile)
        if err != nil {
                panic(err)
        }
        defer output.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                var entry SniffEntry
                json.Unmarshal([]byte(scanner.Text()), &entry)

                host := fmt.Sprintf("%s:%d", entry.CIP, entry.CPort)
                info, exists := hostInfoMap[host]

                if !exists {
                        info = HostInfo{ID: 99999}
                } else {
                        if entry.User == "" {
                                entry.User = info.User
                        }
                        if entry.DB == "" {
                                entry.DB = info.DB
                        }
                }

                sqlType := getSQLType(entry.SQL)

                outputEntry := OutputEntry{
                        ConnectionID: fmt.Sprintf("%d", info.ID),
                        QueryTime:    entry.Cus,
                        SQL:          entry.SQL,
                        RowsSent:     0, // Assuming rows sent is always 0
                        Username:     entry.User,
                        DBName:       entry.DB,
                        SQLType:      sqlType,
                }

                jsonData, _ := json.Marshal(outputEntry)
                output.WriteString(string(jsonData) + "\n")
        }

        if err := scanner.Err(); err != nil {
                panic(err)
        }
}

func readHostInfo(filename string) map[string]HostInfo {
        file, err := os.Open(filename)
        if err != nil {
                panic(err)
        }
        defer file.Close()

        hostInfoMap := make(map[string]HostInfo)
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                var info HostInfo
                json.Unmarshal([]byte(scanner.Text()), &info)
                hostInfoMap[info.Host] = info
        }
        return hostInfoMap
}

func getSQLType(sql string) string {
    normalizedSQL := parser.Normalize(sql)
    words := strings.Fields(normalizedSQL)
    if len(words) > 0 {
        return words[0]
    }
    return "other"
}