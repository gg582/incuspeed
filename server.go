package main

import (
    "crypto/aes"
    "fmt"
    client "github.com/lxc/incus/client"
    "github.com/lxc/incus/shared/api"
    "crypto/cipher"
    "crypto/sha256"
    "net/http"
    "context"
    crand "crypto/rand"
    rand "math/rand"
    "bytes"
    "encoding/base64"
    "encoding/json"
    "io/ioutil"
    "log"
    "math"
    "math/big"
    "os"
    "os/exec"
    "strconv"
    "sync"
    "time"

    "github.com/gorilla/mux"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

var ePlace int64
var lxdClient client.InstanceServer 
var mydir string = "/usr/local/bin/linuxVirtualization/"
var SERVER_IP = os.Args[1] 
var PORT_LIST = make([]int64,0,100000)
var flag   bool
var authFlag bool = false
var port   string
var portprev string = "60001"
var cursor interface{}
var route *mux.Router
var route_MC *mux.Router
var current []byte
var current_Config []byte 
var buf bytes.Buffer
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"
var col *mongo.Collection
var ipCol , UserCol *mongo.Collection
var portInt int = 27020
var portIntonePlace int = 27020
var ctx context.Context
var cancel context.CancelFunc
var tag string
var ADMIN    string = "yjlee"
var password string = "asdfasdf"
var ADDR string = "http://hobbies.yoonjin2.kr"

// 포트 관리를 위한 뮤텍스 추가
var portMutex sync.Mutex

type UserInfo struct {
    Username     string `json:"username"`
    UsernameIV   string `json:"username_iv"`
    Password     string `json:"password"`
    PasswordIV   string `json:"password_iv"`
    Key          string `json:"key"`
}

type ContainerInfo struct {
    Username string `json:"username"`
    UsernameIV string `json:"username_iv"`
    Password string `json:"password"`
    PasswordIV       string `json:"password_iv"`
    Key      string `json:"key"`
    TAG      string `json:"tag"`
    Serverip string `json:"serverip"`
    Serverport string `json:"serverport"`
    VMStatus     string `json:"vmstatus"`
}

var INFO ContainerInfo

func TouchFile(name string) {
    file, _ := os.OpenFile(name, os.O_RDONLY|os.O_CREATE, 0644)
    file.Close()
}

func decrypt_password(ct string, key string, iv string) (string, error) {
    // Key 디코딩 및 검증
    key_bytes, err := base64.StdEncoding.DecodeString(key)
    if err != nil {
        return "", fmt.Errorf("invalid key: %v", err)
    }
    if len(key_bytes) != 16 && len(key_bytes) != 24 && len(key_bytes) != 32 {
        return "", fmt.Errorf("invalid key length: %d (must be 16, 24, or 32 bytes)", len(key_bytes))
    }

    // IV 디코딩 및 검증
    iv_bytes, err := base64.StdEncoding.DecodeString(iv)
    if err != nil {
        return "", fmt.Errorf("invalid iv: %v", err)
    }
    if len(iv_bytes) != aes.BlockSize {
        return "", fmt.Errorf("invalid iv length: %d (must be %d bytes)", len(iv_bytes), aes.BlockSize)
    }

    // 암호문 디코딩 및 검증
    ct_bytes, err := base64.StdEncoding.DecodeString(ct)
    if err != nil {
        return "", fmt.Errorf("invalid ciphertext: %v", err)
    }
    if len(ct_bytes)%aes.BlockSize != 0 {
        return "", fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(ct_bytes), aes.BlockSize)
    }

    // AES 복호화
    block, err := aes.NewCipher(key_bytes)
    if err != nil {
        return "", fmt.Errorf("failed to create cipher: %v", err)
    }
    mode := cipher.NewCBCDecrypter(block, iv_bytes)
    pt_bytes := make([]byte, len(ct_bytes))
    mode.CryptBlocks(pt_bytes, ct_bytes)

    // 패딩 제거
    if len(pt_bytes) == 0 {
        return "", fmt.Errorf("decrypted plaintext is empty")
    }
    padding := int(pt_bytes[len(pt_bytes)-1])
    if padding < 1 || padding > aes.BlockSize {
        return "", fmt.Errorf("invalid padding value: %d", padding)
    }
    for i := len(pt_bytes) - padding; i < len(pt_bytes); i++ {
        if pt_bytes[i] != byte(padding) {
            return "", fmt.Errorf("invalid padding bytes")
        }
    }
    pt_bytes = pt_bytes[:len(pt_bytes)-padding]

    return string(pt_bytes), nil
}
func sha256_hash(password string) string {
    hasher := sha256.New()
    hasher.Write([]byte(password))
    hashedBytes := hasher.Sum(nil)
    hashedString := base64.StdEncoding.EncodeToString(hashedBytes)
    return hashedString
}

func RandStringBytes(n int) string {
    seed, _ := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
    rand.Seed(seed.Int64())

    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(b)
}

func botCheck(u string, pw string) bool {
    cur, err := UserCol.Find(context.Background(), bson.D{{}})
    if err != nil {
        log.Printf("Database query error: %v", err)
        return true
    }
    defer cur.Close(context.Background())

    for cur.Next(context.TODO()) {
        current, err := bson.MarshalExtJSON(cur.Current, false, false)
        if err != nil {
            continue
        }
        var i UserInfo
        if err := json.Unmarshal(current, &i); err != nil {
            continue
        }
        if i.Password == pw && i.Username == u {
            return false
        }
    }
    return true
}

func check(u string, pw string) bool {
    if (u == ADMIN) && !botCheck(u, pw) {
        return true
    }
    return false
}

func get_TAG(mydir string, user string) string {
    var err error
    var file *os.File
    file, err = os.OpenFile(mydir+"/container/latest_access", os.O_RDWR, os.FileMode(0644))
    if err != nil {
        log.Println(tag)
    }
    tagRet := user+"-"+RandStringBytes(20)
    file.Write([]byte(tagRet))
    file.Close()
    return tagRet
}

// 컨테이너 생성을 위한 작업자 풀
type ContainerQueue struct {
    tasks chan ContainerInfo
    wg    sync.WaitGroup
}

var containerQueue = &ContainerQueue{
    tasks: make(chan ContainerInfo, 100), // 버퍼 크기 100으로 설정
}

func (q *ContainerQueue) Start(numWorkers int) {
    for i := 0; i < numWorkers; i++ {
        q.wg.Add(1)
        go q.worker()
    }
}

func (q *ContainerQueue) Stop() {
    close(q.tasks)
    q.wg.Wait()
}

func (q *ContainerQueue) worker() {
    defer q.wg.Done()
    for info := range q.tasks {
        createContainer(info)
    }
}

func getContainerInfo(tag string, info ContainerInfo) ContainerInfo {
     state, _, err := lxdClient.GetInstanceState(tag)
     if err != nil {
         log.Println("failed to get instance state")
     }
    // 결과 문자열 처리
    info.VMStatus = state.Status

    // 결과 출력
    fmt.Println("STATE:", info.VMStatus)
    return info
}


func createContainer(info ContainerInfo) {
    username, err := decrypt_password(info.Username, info.Key, info.UsernameIV)
    password, err := decrypt_password(info.Password, info.Key, info.PasswordIV)
    if err != nil {
        return
    }
    tag := get_TAG(mydir, username)
    info.TAG = tag

    portMutex.Lock()
    port := strconv.Itoa(portInt + 3)
    portInt += 3
    portMutex.Unlock()

    info.Serverport = port
    log.Println("/container_creation.sh " + tag + " " + port + " " + username +  " " + password)
    portprev = port

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    cmdCreate := exec.CommandContext(ctx, "/bin/bash", "-c", "container_creation.sh "+tag+" "+port+" "+username+" "+password)
    cmdCreate.Stdout = os.Stdout
    cmdCreate.Stderr = os.Stderr
    
    if err := cmdCreate.Run(); err != nil {
        log.Printf("Error creating container: %v", err)
        return
    }

    mcEXEC := exec.CommandContext(ctx, "/bin/bash", "-c",  "init_server.sh " +tag)
    mcEXEC.Stdout = os.Stdout
    mcEXEC.Stderr = os.Stderr
    if err := mcEXEC.Run(); err != nil {
        log.Printf("Error initializing server: %v", err)
        return
    }

    info = getContainerInfo(tag, info)

    ipRes, insertErr := ipCol.InsertOne(ctx, info)
    if insertErr != nil {
        log.Println("Cannot insert container IP into MongoDB")
    } else {
        log.Println("container IP Insert succeed. Result is : ", ipRes)
    }

}

func CreateContainer(wr http.ResponseWriter, req *http.Request) {
    wr.Header().Set("Content-Type", "application/json; charset=utf-8")

    var info ContainerInfo
    if err := json.NewDecoder(req.Body).Decode(&info); err != nil {
        http.Error(wr, "Failed to parse JSON: "+err.Error(), http.StatusBadRequest)
        return
    }

    select {
    case containerQueue.tasks <- info:
        string_Reply, _ := json.Marshal(info)
        wr.Write(string_Reply)
    default:
        http.Error(wr, "Server is busy", http.StatusServiceUnavailable)
    }
}
func UseContainer(wr http.ResponseWriter, req *http.Request) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    wr.Header().Set("Content-Type", "application/json; charset=utf-8")
    
    var in UserInfo
    body, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }
    
    if err := json.Unmarshal(body, &in); err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }

    filter := bson.M{"username": in.Username, "password": in.Password}
    cur, err := ipCol.Find(ctx, filter)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusInternalServerError)
        return
    }
    defer cur.Close(ctx)

    var results []ContainerInfo
    for cur.Next(ctx) {
        var info ContainerInfo
        if err := cur.Decode(&info); err != nil {
            continue
        }
        results = append(results, info)
    }

    resp, err := json.Marshal(results)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusInternalServerError)
        return
    }

    wr.Write(resp)
}

func DeleteFromListByValue(slice []int64, value int64) []int64 {
    for i, itm := range slice {
        if itm == value {
            return append(slice[:i], slice[i+1:]...)
        }
    }
    return slice
}

func ChangeState(tag string, state string) {
    req := api.InstanceStatePut{
        Action: state,
    }

    _, err := lxdClient.UpdateInstanceState(tag, req, "")
    if err != nil {
        log.Fatalf("Container state change failed: %v", err)
    }
}

func StopByTag(wr http.ResponseWriter, req *http.Request) {
    forTag, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }

    //stringForStopTask := string(forTag)
    //cmdStop := exec.CommandContext(ctx, "/bin/bash", "-c", "stop.sh " +stringForStopTask)
    //cmdStop.Run()
    ChangeState(string(forTag), "stop")
}

func RestartByTag(wr http.ResponseWriter, req *http.Request) {

    forTag, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }

    log.Println("Received TAG:" + string(forTag))
    ChangeState(string(forTag), "restart")

}

func PauseByTag(wr http.ResponseWriter, req *http.Request) {

    forTag, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }

    log.Println("Received TAG:" + string(forTag))
    ChangeState(string(forTag), "freeze")

}

func StartByTag(wr http.ResponseWriter, req *http.Request) {

    forTag, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }

    log.Println("Received TAG:" + string(forTag))
    ChangeState(string(forTag), "start")
    //stringForStartTask := string(forTag)
    //cmdStart := exec.CommandContext(ctx, "/bin/bash", "-c", "start.sh "+stringForStartTask)
    //cmdStart.Run()

}

func DeleteByTag(wr http.ResponseWriter, req *http.Request) {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    forTag, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, err.Error(), http.StatusBadRequest)
        return
    }

    stringForTag := string(forTag)
    cmdDelete := exec.CommandContext(ctx, "/bin/bash", "delete_container.sh "+stringForTag)

    cur, err := ipCol.Find(ctx, bson.D{{}})
    if err != nil {
        http.Error(wr, err.Error(), http.StatusInternalServerError)
        return
    }
    defer cur.Close(ctx)

    for cur.Next(ctx) {
        resp, err := bson.MarshalExtJSON(cur.Current, false, false)
        if err != nil {
            continue
        }
        var INFO ContainerInfo
        if err := json.Unmarshal(resp, &INFO); err != nil {
            continue
        }
        if INFO.TAG == stringForTag {
            p32, _ := strconv.Atoi(INFO.Serverport)
            p := int(p32)
            
            portMutex.Lock()
            PORT_LIST = DeleteFromListByValue(PORT_LIST, int64(p))
            portIntonePlace = p
            ePlace += 1
            portMutex.Unlock()

            if _, err := ipCol.DeleteOne(ctx, cur.Current); err != nil {
                log.Printf("Error deleting container from database: %v", err)
            }

            cmdDelete.Stdout = os.Stdout
            cmdDelete.Stderr = os.Stderr
            if err := cmdDelete.Run(); err != nil {
                log.Printf("Error deleting container: %v", err)
                http.Error(wr, "Failed to delete container", http.StatusInternalServerError)
                return
            }
            return
        }
    }
}

func GetContainers(wr http.ResponseWriter, req *http.Request) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    INFO.Serverip = SERVER_IP
    wr.Header().Set("Content-Type", "application/json; charset=utf-8")

    var in UserInfo
    body, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
        return
    }

    if err := json.Unmarshal(body, &in); err != nil {
        http.Error(wr, "Failed to parse JSON: "+err.Error(), http.StatusBadRequest)
        return
    }

    decodedUsername, err := decrypt_password(in.Username, in.Key, in.UsernameIV)
    if err != nil {
        http.Error(wr, "Failed to decrypt username: "+err.Error(), http.StatusBadRequest)
        return
    }
    decodedPassword, err := decrypt_password(in.Password, in.Key, in.PasswordIV)
    if err != nil {
        http.Error(wr, "Failed to decrypt password: "+err.Error(), http.StatusBadRequest)
        return
    }

    cur, err := ipCol.Find(ctx, bson.D{{}})
    if err != nil {
        log.Println("Error on finding information: ", err)
        http.Error(wr, "Database error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer cur.Close(ctx)

    jsonList := make([]interface{}, 0, 100000)
    for cur.Next(ctx) {
        var info ContainerInfo
        if err := cur.Decode(&info); err != nil {
            log.Println("Error decoding document: ", err)
            continue
        }
        Username, _ := decrypt_password(info.Username, info.Key, info.UsernameIV)
        Password, _ := decrypt_password(info.Password, info.Key, info.PasswordIV)
        if Username == decodedUsername && Password == decodedPassword {
            jsonList = append(jsonList, info)
        }
    }

    resp, err := json.Marshal(jsonList)
    if err != nil {
        http.Error(wr, "Failed to marshal response: "+err.Error(), http.StatusInternalServerError)
        return
    }

    wr.WriteHeader(http.StatusOK)
    wr.Write(resp)
}

func Register(wr http.ResponseWriter, req *http.Request) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var u UserInfo
    body, err := ioutil.ReadAll(req.Body)
    if err != nil {
        http.Error(wr, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
        return
    }

    if err := json.Unmarshal(body, &u); err != nil {
        http.Error(wr, "Failed to parse JSON: "+err.Error(), http.StatusBadRequest)
        return
    }

    u.Password, err = decrypt_password(u.Password, u.Key, u.PasswordIV)
    if err != nil {
        http.Error(wr, "Failed to decrypt password: "+err.Error(), http.StatusBadRequest)
        return
    }
    u.Username, err = decrypt_password(u.Username, u.Key, u.UsernameIV)
    if err != nil {
        http.Error(wr, "Failed to decrypt username: "+err.Error(), http.StatusBadRequest)
        return
    }

    if _, err := UserCol.InsertOne(ctx, u); err != nil {
        http.Error(wr, "Failed to register user: "+err.Error(), http.StatusInternalServerError)
        return
    }

    wr.Write([]byte("User Registration Done"))
}

func main() {
    // 기본 컨텍스트 설정
    var err error
    lxdClient, err = client.ConnectIncusUnix("",nil)
    if err != nil {
        log.Fatalf("Failed to connect to LXD")
    }
    ctx, cancel = context.WithCancel(context.Background())
    defer cancel()

    // MongoDB 연결 설정
    clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
    client, err := mongo.Connect(ctx, clientOptions)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Disconnect(ctx)

    // MongoDB 연결 테스트
    err = client.Ping(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }

    // 컬렉션 초기화
    col = client.Database("MC_Json").Collection("Flag Collections")
    ipCol = client.Database("MC_IP").Collection("IP Collections")
    UserCol = client.Database("MC_USER").Collection("User Collections")

    // 컨테이너 작업자 풀 시작
    containerQueue.Start(5) // 5개의 작업자 시작
    defer containerQueue.Stop()

    // 라우터 설정
    route = mux.NewRouter()
    route.HandleFunc("/register", Register).Methods("POST")
    route.HandleFunc("/create", CreateContainer).Methods("POST")
    route.HandleFunc("/request", GetContainers).Methods("POST")
    route.HandleFunc("/delete", DeleteByTag).Methods("POST")
    route.HandleFunc("/stop", StopByTag).Methods("POST")
    route.HandleFunc("/start", StartByTag).Methods("POST")
    route.HandleFunc("/pause", PauseByTag).Methods("POST")
    route.HandleFunc("/restart", RestartByTag).Methods("POST")


    // HTTP 서버 설정
    srv := &http.Server{
        Handler:      route,
        Addr:         ":32000",
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // 서버 시작
    log.Printf("Starting server on port 32000")
    if err := srv.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
} 
