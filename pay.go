package goweixin

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	Fail    = "FAIL"
	Success = "SUCCESS"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

type WeixinPay struct {
	*http.Client
	AppId     string
	MchId     string
	MchKey    string
	NotifyUrl string
	host      string
}

func NewWeixinPay(appId, mchId, mchKey, notifyUrl string) *WeixinPay {
	pay := &WeixinPay{
		Client:    http.DefaultClient,
		AppId:     appId,
		MchId:     mchId,
		MchKey:    mchKey,
		NotifyUrl: notifyUrl,
		host:      "https://api.mch.weixin.qq.com",
	}
	return pay
}

// 切换沙箱模式
func (pay *WeixinPay) Sanbox() *WeixinPay {
	pay.host = "https://api.mch.weixin.qq.com/sandboxnew"
	var out struct {
		MchId string `xml:"mch_id"`
		Key   string `xml:"sandbox_signkey"`
	}
	params := map[string]string{"mch_id": pay.MchId}
	err := pay.Do("/pay/getsignkey", params, &out)
	if err != nil {
		panic(err)
	}
	pay.MchKey = out.Key
	return pay
}

func (pay *WeixinPay) Cert(caCert string) *WeixinPay {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(caCert))
	if !ok {
		panic("failed to parse root certificate")
	}
	tlsConf := &tls.Config{RootCAs: roots}
	pay.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConf,
			Proxy:           http.ProxyFromEnvironment,
		},
	}
	return pay
}

func (pay *WeixinPay) ToXml(params map[string]string) string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("<xml>")
	for k, v := range params {
		buf.WriteString(fmt.Sprintf("<%s>%s</%s>", k, v, k))
	}
	buf.WriteString("</xml>")
	return buf.String()
}

func (pay *WeixinPay) Do(path string, in, res interface{}) error {
	targetUrl := pay.host + path
	params := ToData(in, "xml")
	//params["appId"] = pay.AppId
	//params["mch_id"] = pay.MchId
	params["nonce_str"] = pay.NonceStr()
	params["sign"] = pay.Sign(params, nil)

	items := url.Values{}
	for k, v := range params {
		items.Set(k, v)
	}
	req, err := http.NewRequest("POST", targetUrl, strings.NewReader(pay.ToXml(params)))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "goweixin/"+Version)

	resp, err := pay.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if res != nil {
		if val, ok := res.(*string); ok {
			*val = string(body)
			return nil
		}
	}

	var out struct {
		Code       string `xml:"return_code"`
		Message    string `xml:"return_msg"`
		ResultCode string `xml:"result_code"`
		ErrCode    string `xml:"err_code"`
		ErrCodeDes string `xml:"err_code_des"`
	}
	err = xml.Unmarshal(body, &out)
	if err != nil {
		return err
	}
	if out.Code == Fail {
		return errors.New(out.Message)
	}
	// 业务失败
	if out.ResultCode == Fail {
		return errors.New(out.ErrCode + "-" + out.ErrCodeDes)
	}
	if res != nil {
		return xml.Unmarshal(body, &res)
	}
	return nil
}

// 生成32位随机字符串
func (pay *WeixinPay) NonceStr() string {
	return RandString(32)
}

// 生成签名
func (pay *WeixinPay) Sign(raw interface{}, fn func() hash.Hash) string {
	if fn == nil {
		fn = md5.New
	}
	params := ToData(raw, "xml")
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := fn()
	bufw := bufio.NewWriterSize(h, 128)
	for _, k := range keys {
		v := params[k]
		if v == "" {
			continue
		}
		bufw.WriteString(k)
		bufw.WriteByte('=')
		bufw.WriteString(v)
		bufw.WriteByte('&')
	}
	bufw.WriteString("key=")
	bufw.WriteString(pay.MchKey)
	bufw.Flush()

	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// 检测签名是否正确
func (pay *WeixinPay) Check(raw interface{}, fn func() hash.Hash) (ok bool, err error) {
	data := ToData(raw, "xml")
	sign := data["sign"]
	if sign == "" {
		return false, ErrInvalidSignature
	}
	delete(data, "sign")
	ok = pay.Sign(raw, fn) == sign
	return
}

// 回复微信通知
func (pay *WeixinPay) Reply(ok bool, msg string) string {
	var out struct {
		xml.Name `xml:"xml"`
		Code     string `xml:"return_code"`
		Message  string `xml:"return_msg"`
	}
	if ok {
		out.Code = Success
	} else {
		out.Code = Fail
	}
	out.Message = msg
	body, _ := xml.Marshal(out)
	return string(body)
}

type UnifiedOrderRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选参数
	Body           string `xml:"body"`             // 商品或支付单简要描述
	OutTradeNo     string `xml:"out_trade_no"`     // 商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号
	TotalFee       int64  `xml:"total_fee"`        // 订单总金额，单位为分，详见支付金额
	SpbillCreateIP string `xml:"spbill_create_ip"` // APP和网页支付提交用户端ip，Native支付填调用微信支付API的机器IP。
	NotifyUrl      string `xml:"notify_url"`       // 接收微信支付异步通知回调地址，通知url必须为直接可访问的url，不能携带参数。
	TradeType      string `xml:"trade_type"`       // 取值如下：JSAPI，NATIVE，APP，详细说明见参数规定

	// 可选参数
	DeviceInfo string `xml:"device_info"` // 终端设备号(门店号或收银设备ID)，注意：PC网页或公众号内支付请传"WEB"
	NonceStr   string `xml:"nonce_str"`   // 随机字符串，不长于32位。NOTE: 如果为空则系统会自动生成一个随机字符串。
	SignType   string `xml:"sign_type"`   // 签名类型，默认为MD5，支持HMAC-SHA256和MD5。
	Detail     string `xml:"detail"`      // 商品名称明细列表
	Attach     string `xml:"attach"`      // 附加数据，在查询API和支付通知中原样返回，该字段主要用于商户携带订单的自定义数据
	FeeType    string `xml:"fee_type"`    // 符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	TimeStart  string `xml:"time_start"`  // 订单生成时间，格式为yyyyMMddHHmmss，如2009年12月25日9点10分10秒表示为20091225091010。其他详见时间规则
	TimeExpire string `xml:"time_expire"` // 订单失效时间，格式为yyyyMMddHHmmss，如2009年12月27日9点10分10秒表示为20091227091010。其他详见时间规则
	GoodsTag   string `xml:"goods_tag"`   // 商品标记，代金券或立减优惠功能的参数，说明详见代金券或立减优惠
	ProductId  string `xml:"product_id"`  // trade_type=NATIVE，此参数必传。此id为二维码中包含的商品ID，商户自行定义。
	LimitPay   string `xml:"limit_pay"`   // no_credit--指定不能使用信用卡支付
	OpenId     string `xml:"openid"`      // rade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。
	SubOpenId  string `xml:"sub_openid"`  // trade_type=JSAPI，此参数必传，用户在子商户appid下的唯一标识。openid和sub_openid可以选传其中之一，如果选择传sub_openid,则必须传sub_appid。
	SceneInfo  string `xml:"scene_info"`  // 该字段用于上报支付的场景信息,针对H5支付有以下三种场景,请根据对应场景上报,H5支付不建议在APP端使用，针对场景1，2请接入APP支付，不然可能会出现兼容性问题
}

type UnifiedOrderResponse struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选返回
	PrepayId  string `xml:"prepay_id"`  // 微信生成的预支付回话标识，用于后续接口调用中使用，该值有效期为2小时
	TradeType string `xml:"trade_type"` // 调用接口提交的交易类型，取值如下：JSAPI，NATIVE，APP，详细说明见参数规定

	// 下面字段都是可选返回的(详细见微信支付文档), 为空值表示没有返回, 程序逻辑里需要判断
	DeviceInfo string `xml:"device_info"` // 调用接口提交的终端设备号。
	CodeUrl    string `xml:"code_url"`    // trade_type 为 NATIVE 时有返回，可将该参数值生成二维码展示出来进行扫码支付
	MwebUrl    string `xml:"mweb_url"`    // trade_type 为 MWEB 时有返回
}

// 统一下单
func (pay *WeixinPay) UnifiedOrder(req *UnifiedOrderRequest) (resp *UnifiedOrderResponse, err error) {
	if req.NotifyUrl == "" {
		req.NotifyUrl = pay.NotifyUrl
	}
	resp = &UnifiedOrderResponse{}
	err = pay.Do("/pay/unifiedorder", req, resp)
	if err != nil {
		return nil, err
	}
	return
}

type JsapiResponse struct {
	Package   string `xml:"package" json:"package"`
	AppId     string `xml:"appId" json:"appId"`
	TimeStamp string `xml:"timeStamp" json:"timeStamp"`
	NonceStr  string `xml:"nonceStr" json:"nonceStr"`
	SignType  string `xml:"signType" json:"signType"`
	PaySign   string `xml:"paySign" json:"paySign"`
}

// 生成给JavaScript调用的数据
// 详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=7_7&index=6
func (pay *WeixinPay) Jsapi(req *UnifiedOrderRequest) (resp *JsapiResponse, err error) {
	req.TradeType = "JSAPI"
	res, err := pay.UnifiedOrder(req)
	if err != nil {
		return nil, err
	}
	resp = &JsapiResponse{
		Package:   fmt.Sprintf("prepay_id=%s", res.PrepayId),
		TimeStamp: fmt.Sprint(time.Now().Unix()),
		AppId:     pay.AppId,
		NonceStr:  pay.NonceStr(),
		SignType:  "MD5",
	}
	resp.PaySign = pay.Sign(resp)
	return
}
