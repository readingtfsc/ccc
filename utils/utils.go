package utils

import (
	"bytes"
	rands "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"
)

var src = rand.NewSource(time.Now().UnixNano())

const (
	letterBytes       = "abcdefghijklmNOPQRSTUVWXYZ"
	letterNumberBytes = "0123456789"
	letterIdxBits     = 6
	letterIdxMask     = 1<<letterIdxBits - 1
	letterIdxMax      = 63 / letterIdxBits
)

func GetString(v interface{}) string {
	switch result := v.(type) {
	case string:
		return result
	case []byte:
		return string(result)
	default:
		if v != nil {
			return fmt.Sprint(result)
		}
	}
	return ""
}

// GetInt convert interface to int.
func GetInt(v interface{}) int {
	switch result := v.(type) {
	case int:
		return result
	case int32:
		return int(result)
	case int64:
		return int(result)
	default:
		if d := GetString(v); d != "" {
			value, _ := strconv.Atoi(d)
			return value
		}
	}
	return 0
}

// GetInt64 convert interface to int64.
func GetInt64(v interface{}) int64 {
	switch result := v.(type) {
	case int:
		return int64(result)
	case int32:
		return int64(result)
	case int64:
		return result
	default:

		if d := GetString(v); d != "" {
			value, _ := strconv.ParseInt(d, 10, 64)
			return value
		}
	}
	return 0
}

// GetFloat64 convert interface to float64.
func GetFloat64(v interface{}) float64 {
	switch result := v.(type) {
	case float64:
		return result
	default:
		if d := GetString(v); d != "" {
			value, _ := strconv.ParseFloat(d, 64)
			return value
		}
	}
	return 0
}

// GetBool convert interface to bool.
func GetBool(v interface{}) bool {
	switch result := v.(type) {
	case bool:
		return result
	default:
		if d := GetString(v); d != "" {
			value, _ := strconv.ParseBool(d)
			return value
		}
	}
	return false
}
func RandString(n int) string {
	b := make([]byte, n)

	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func RandNumberString(n int) string {
	b := make([]byte, n)

	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterNumberBytes) {
			b[i] = letterNumberBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
func DeleteSlice(slice interface{}, index int) (interface{}, error) {
	sliceValue := reflect.ValueOf(slice)
	length := sliceValue.Len()
	if slice == nil || length == 0 || (length-1) < index {
		return nil, errors.New("errors")
	}
	if length-1 == index {
		return sliceValue.Slice(0, index).Interface(), nil
	} else if (length - 1) >= index {
		return reflect.AppendSlice(sliceValue.Slice(0, index), sliceValue.Slice(index+1, length)).Interface(), nil
	}
	return nil, errors.New("errors")
}
func RandInt(min, max int) int {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	i := r.Intn(max)
	if i < min {
		RandInt(min, max)
	}
	return i
}

func GetEncodingValue(src, secret string) (string, error) {
	key, err := Base64Decode(secret + "=")
	if err != nil {
		return "", err
	}
	ecdata, err := AesEncrypt([]byte(src), key)
	if err != nil {
		return "", err
	}
	ecstr := Base64Encode(ecdata)
	return ecstr, nil
}

func GetDecodingValue(src, secret string) (string, error) {
	key, err := Base64Decode(secret + "=")
	if err != nil {
		return "", err
	}
	srcData, err := Base64Decode(src)
	if err != nil {
		return "", err
	}
	decodeData, err := AesDecrypt(srcData, key)
	if err != nil {
		return "", err
	}

	return string(decodeData), nil
}

//钉钉提醒功能
func SendDingDingMsg(content string) error {
	var dingdingURL = "https://oapi.dingtalk.com/robot/send?access_token=22"

	if content == "" {
		return nil
	}
	formt := `
		{
			"msgtype": "text",
			"text": {
				"content": "%s"
			},
			"at": {
         		"isAtAll": true
     		}
		}`
	body := fmt.Sprintf(formt, content)
	jsonValue := []byte(body)
	_, err := http.Post(dingdingURL, "application/json", bytes.NewBuffer(jsonValue))
	return err
}

func RandInt64(min, max int64) int64 {
	maxBigInt := big.NewInt(max)
	i, _ := rands.Int(rands.Reader, maxBigInt)
	print(i.Uint64())
	if i.Int64() < min && i.Int64() == 0 {
		RandInt64(min, max)
	}
	return i.Int64()
}

//表情解码
func UnicodeEmojiDecode(s string) string {
	//emoji表情的数据表达式
	re := regexp.MustCompile("\\[[\\\\u0-9a-zA-Z]+\\]")
	//提取emoji数据表达式
	reg := regexp.MustCompile("\\[\\\\u|]")
	src := re.FindAllString(s, -1)
	for i := 0; i < len(src); i++ {
		e := reg.ReplaceAllString(src[i], "")
		p, err := strconv.ParseInt(e, 16, 32)
		if err == nil {
			s = strings.Replace(s, src[i], string(rune(p)), -1)
		}
	}
	return s
}

//表情转换
func UnicodeEmojiCode(s string) string {
	ret := ""
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if len(string(rs[i])) == 4 {
			u := `[\u` + strconv.FormatInt(int64(rs[i]), 16) + `]`
			ret += u

		} else {
			ret += string(rs[i])
		}
	}
	return ret
}

//判断是否是emoji表情
func JudgeEmoji(content string) bool {
	for _, value := range content {
		_, size := utf8.DecodeRuneInString(string(value))
		if size == 4 {
			return true
		}
	}
	return false
}

func IsEmptyStr(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

//不能判断一定是，可以判断一定不是
func JudgeBase64(str string) bool {
	pattern := "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
	matched, err := regexp.MatchString(pattern, str)
	if err != nil {
		return false
	}
	if !(len(str)%4 == 0 && matched) {
		return false
	}
	unCodeStr, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return false
	}
	tranStr := base64.StdEncoding.EncodeToString(unCodeStr)
	//return str==base64.StdEncoding.EncodeToString(unCodeStr)
	if str == tranStr {
		return true
	}
	return false
}
func IsTimeOut(t, timeOutRange int64) bool {
	now := time.Now().Unix()

	return now < (t-timeOutRange) || now > (t+timeOutRange)
}

// ParseEndpoint parses endpoint to a URL
func ParseEndpoint(endpoint string) (*url.URL, error) {
	endpoint = strings.Trim(endpoint, " ")
	endpoint = strings.TrimRight(endpoint, "/")
	if len(endpoint) == 0 {
		return nil, fmt.Errorf("empty URL")
	}
	i := strings.Index(endpoint, "://")
	if i >= 0 {
		scheme := endpoint[:i]
		if scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("invalid scheme: %s", scheme)
		}
	} else {
		endpoint = "http://" + endpoint
	}

	return url.ParseRequestURI(endpoint)
}

func GenerateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	l := len(chars)
	result := make([]byte, length)
	_, err := rand.Read(result)
	if err != nil {
		fmt.Println("Error reading random bytes: %v", err)
	}
	for i := 0; i < length; i++ {
		result[i] = chars[int(result[i])%l]
	}
	return string(result)
}

// TestTCPConn tests TCP connection
// timeout: the total time before returning if something is wrong
// with the connection, in second
// interval: the interval time for retring after failure, in second
func TestTCPConn(addr string, timeout, interval int) error {
	success := make(chan int)
	cancel := make(chan int)

	go func() {
		for {
			select {
			case <-cancel:
				break
			default:
				conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
				if err != nil {
					fmt.Println("failed to connect to tcp://%s, retry after %d seconds :%v",
						addr, interval, err)
					time.Sleep(time.Duration(interval) * time.Second)
					continue
				}
				if err = conn.Close(); err != nil {
					fmt.Println("failed to close the connection: %v", err)
				}
				success <- 1
				break
			}
		}
	}()

	select {
	case <-success:
		return nil
	case <-time.After(time.Duration(timeout) * time.Second):
		cancel <- 1
		return fmt.Errorf("failed to connect to tcp:%s after %d seconds", addr, timeout)
	}
}

// ParseTimeStamp parse timestamp to time
func ParseTimeStamp(timestamp string) (*time.Time, error) {
	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, err
	}
	t := time.Unix(i, 0)
	return &t, nil
}
func ParseTimeStampToDataStr(timestamp interface{}) string {
	time, err := ParseTimeStamp(GetString(timestamp))
	if err != nil {
		fmt.Println("ParseTimeStamp errors", err)
		return ""
	}
	timeLayout := "2006-01-02 15:04:05"
	return time.Format(timeLayout)
}

func GetCurrentDataStr() string {
	timeLayout := "2006-01-02 15:04:05"
	return time.Now().Format(timeLayout)
}

//ConvertMapToStruct is used to fill the specified struct with map.
func ConvertMapToStruct(object interface{}, values interface{}) error {
	if object == nil {
		return errors.New("nil struct is not supported")
	}

	if reflect.TypeOf(object).Kind() != reflect.Ptr {
		return errors.New("object should be referred by pointer")
	}

	bytes, err := json.Marshal(values)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, object)
}

//对象拷贝
func Copy(dst interface{}, src interface{}) (err error) {
	dstValue := reflect.ValueOf(dst)
	if dstValue.Kind() != reflect.Ptr {
		err = errors.New("dst isn't a pointer to struct")
		return
	}
	dstElem := dstValue.Elem()
	if dstElem.Kind() != reflect.Struct {
		err = errors.New("pointer doesn't point to struct")
		return
	}

	srcValue := reflect.ValueOf(src)
	srcType := reflect.TypeOf(src)
	if srcType.Kind() != reflect.Struct {
		err = errors.New("src isn't struct")
		return
	}

	for i := 0; i < srcType.NumField(); i++ {
		sf := srcType.Field(i)
		sv := srcValue.FieldByName(sf.Name)
		// make sure the value which in dst is valid and can set
		if dv := dstElem.FieldByName(sf.Name); dv.IsValid() && dv.CanSet() {
			dv.Set(sv)
		}
	}
	return
}

//比较两个实体对象之前差异  返回属性名{"旧值":"新值"}
//old只需要传入指针类型
func CompareStructDifference(old interface{}, new interface{}) (diffMaps map[string]string, err error) {
	oldValue := reflect.ValueOf(old)
	oldElem := oldValue.Elem()
	newValue := reflect.ValueOf(new)
	newType := reflect.TypeOf(new)
	if oldValue.Kind() != reflect.Ptr {
		err = errors.New("old isn't a pointer to struct")
		return
	}
	if oldElem.Kind() != reflect.Struct {
		err = errors.New("pointer doesn't point to struct")
		return
	}

	if newType.Kind() != reflect.Struct {
		err = errors.New("new isn't struct")
		return
	}
	diffMaps = make(map[string]string)
	for i := 0; i < newType.NumField(); i++ {
		newf := newType.Field(i)
		newv := newValue.FieldByName(newf.Name)
		oldv := oldElem.FieldByName(newf.Name)
		oldValue := "-"
		newValue := "-"
		if len(GetString(oldv)) > 0 {
			oldValue = GetString(oldv)
		}
		if len(GetString(newv)) > 0 {
			newValue = GetString(newv)
		}
		if oldValue != newValue {
			diffMaps[newf.Name] = fmt.Sprintf(oldValue+" %s "+newValue, "to")
		}
	}
	return
}

func BytesToStringWithNoCopy(bytes []byte) string {
	return *(*string)(unsafe.Pointer(&bytes))
}

func StringToBytesWithNoCopy(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func ToJson(obj interface{}) string {
	b, err := json.Marshal(obj)
	if err != nil {
		fmt.Printf("tojson errors %s", err.Error())
		return ""
	} else {
		return GetString(b)
	}
}

func JsonToMap(obj interface{}) (map[string]string, error) {
	var result map[string]string
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func ListToMap(list []string) map[string]struct{} {
	ret := make(map[string]struct{}, len(list))
	for _, v := range list {
		ret[v] = struct{}{}
	}
	return ret
}

func MapToList(dict map[string]struct{}) []string {
	ret := make([]string, 0, len(dict))
	for k := range dict {
		ret = append(ret, k)
	}
	return ret
}

func StringJoin(args []string, sep string) string {
	l := len(args)
	switch l {
	case 0:
		return ""
	case 1:
		return args[0]
	default:
		n := len(sep) * (l - 1)
		for i := 0; i < l; i++ {
			n += len(args[i])
		}
		b := make([]byte, n)
		sl := copy(b, args[0])
		for i := 1; i < l; i++ {
			sl += copy(b[sl:], sep)
			sl += copy(b[sl:], args[i])
		}
		return BytesToStringWithNoCopy(b)
	}
}

func Decimal(value float64) float64 {
	value, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", value), 64)
	return value
}
func Map2Json(m map[string]interface{}) ([]byte, error) {
	result, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return nil, err
	}
	return result, nil
}
