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
	"io"
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

// 返回带证书的客户端
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

func (pay *WeixinPay) DoWithParams(path string, params map[string]string, in, out interface{}) error {
	data := ToData(in, "xml")
	for k, v := range params {
		data[k] = v
	}
	return pay.Do(path, data, out)
}

// 默认参数
// 发红包等API与此默认参数有些不同
func (pay *WeixinPay) DoWithDefaultParams(path string, in, out interface{}) error {
	params := map[string]string{
		"appId":  pay.AppId,
		"mch_id": pay.MchId,
	}
	return pay.DoWithParams(path, params, in, out)
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
	DeviceInfo string `xml:"device_info,omitempty"` // 终端设备号(门店号或收银设备ID)，注意：PC网页或公众号内支付请传"WEB"
	Detail     string `xml:"detail,omitempty"`      // 商品名称明细列表
	Attach     string `xml:"attach,omitempty"`      // 附加数据，在查询API和支付通知中原样返回，该字段主要用于商户携带订单的自定义数据
	FeeType    string `xml:"fee_type,omitempty"`    // 符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	TimeStart  string `xml:"time_start,omitempty"`  // 订单生成时间，格式为yyyyMMddHHmmss，如2009年12月25日9点10分10秒表示为20091225091010。其他详见时间规则
	TimeExpire string `xml:"time_expire,omitempty"` // 订单失效时间，格式为yyyyMMddHHmmss，如2009年12月27日9点10分10秒表示为20091227091010。其他详见时间规则
	GoodsTag   string `xml:"goods_tag,omitempty"`   // 商品标记，代金券或立减优惠功能的参数，说明详见代金券或立减优惠
	ProductId  string `xml:"product_id,omitempty"`  // trade_type=NATIVE，此参数必传。此id为二维码中包含的商品ID，商户自行定义。
	LimitPay   string `xml:"limit_pay,omitempty"`   // no_credit--指定不能使用信用卡支付
	OpenId     string `xml:"openid,omitempty"`      // rade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。
	SubOpenId  string `xml:"sub_openid,omitempty"`  // trade_type=JSAPI，此参数必传，用户在子商户appid下的唯一标识。openid和sub_openid可以选传其中之一，如果选择传sub_openid,则必须传sub_appid。
	SceneInfo  string `xml:"scene_info,omitempty"`  // 该字段用于上报支付的场景信息,针对H5支付有以下三种场景,请根据对应场景上报,H5支付不建议在APP端使用，针对场景1，2请接入APP支付，不然可能会出现兼容性问题
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
	err = pay.DoWithDefaultParams("/pay/unifiedorder", req, resp)
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
	resp.PaySign = pay.Sign(resp, nil)
	return
}

type OrderQueryRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 下面这些参数至少提供一个
	TransactionId string `xml:"transaction_id,omitempty"` // 微信的订单号，优先使用
	OutTradeNo    string `xml:"out_trade_no,omitempty"`   // 商户系统内部的订单号，当没提供transaction_id时需要传这个。
}

type OrderQueryResponse struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选返回
	TradeState     string `xml:"trade_state"`      // 交易状态
	TradeStateDesc string `xml:"trade_state_desc"` // 对当前查询订单状态的描述和下一步操作的指引
	OpenId         string `xml:"openid"`           // 用户在商户appid下的唯一标识
	TransactionId  string `xml:"transaction_id"`   // 微信支付订单号
	OutTradeNo     string `xml:"out_trade_no"`     // 商户系统的订单号，与请求一致。
	TradeType      string `xml:"trade_type"`       // 调用接口提交的交易类型，取值如下：JSAPI，NATIVE，APP，MICROPAY，详细说明见参数规定
	BankType       string `xml:"bank_type"`        // 银行类型，采用字符串类型的银行标识
	TotalFee       int64  `xml:"total_fee"`        // 订单总金额，单位为分
	CashFee        int64  `xml:"cash_fee"`         // 现金支付金额订单现金支付金额，详见支付金额
	TimeEnd        string `xml:"time_end"`         // 订单支付时间，格式为yyyyMMddHHmmss，如2009年12月25日9点10分10秒表示为20091225091010。其他详见时间规则

	// 下面字段都是可选返回的(详细见微信支付文档), 为空值表示没有返回, 程序逻辑里需要判断
	DeviceInfo         string `xml:"device_info"`          // 微信支付分配的终端设备号
	IsSubscribe        string `xml:"is_subscribe"`         // 用户是否关注公众账号
	SubOpenId          string `xml:"sub_openid"`           // 用户在子商户appid下的唯一标识
	SubIsSubscribe     string `xml:"sub_is_subscribe"`     // 用户是否关注子公众账号
	SettlementTotalFee int64  `xml:"settlement_total_fee"` // 应结订单金额=订单金额-非充值代金券金额，应结订单金额<=订单金额。
	FeeType            string `xml:"fee_type"`             // 货币类型，符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	CashFeeType        string `xml:"cash_fee_type"`        // 货币类型，符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	Detail             string `xml:"detail"`               // 商品详情
	Attach             string `xml:"attach"`               // 附加数据，原样返回
}

// 订单查询
func (pay *WeixinPay) OrderQuery(req *OrderQueryRequest) (resp *OrderQueryResponse, err error) {
	resp = &OrderQueryResponse{}
	err = pay.DoWithDefaultParams("/pay/orderquery", req, resp)
	if err != nil {
		return nil, err
	}
	return
}

type CloseOrderRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选参数
	OutTradeNo string `xml:"out_trade_no"` // 商户系统内部订单号
}

// 关闭订单
func (pay *WeixinPay) CloseOrder(req *CloseOrderRequest) (err error) {
	err = pay.DoWithDefaultParams("/pay/closeorder", req, nil)
	return
}

type RefundRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选参数, TransactionId 和 OutTradeNo 二选一即可.
	TransactionId string `xml:"transaction_id"` // 微信生成的订单号，在支付通知中有返回
	OutTradeNo    string `xml:"out_trade_no"`   // 商户侧传给微信的订单号
	OutRefundNo   string `xml:"out_refund_no"`  // 商户系统内部的退款单号，商户系统内部唯一，同一退款单号多次请求只退一笔
	TotalFee      int64  `xml:"total_fee"`      // 订单总金额，单位为分，只能为整数，详见支付金额
	RefundFee     int64  `xml:"refund_fee"`     // 退款总金额，订单总金额，单位为分，只能为整数，详见支付金额

	// 可选参数
	RefundFeeType string `xml:"refund_fee_type,omitempty"` // 货币类型，符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	RefundDesc    string `xml:"refund_desc,omitempty"`     // 若商户传入，会在下发给用户的退款消息中体现退款原因
	RefundAccount string `xml:"refund_account,omitempty"`  // 退款资金来源
}

type RefundResponse struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选返回
	TransactionId string `xml:"transaction_id"` // 微信订单号
	OutTradeNo    string `xml:"out_trade_no"`   // 商户系统内部的订单号
	OutRefundNo   string `xml:"out_refund_no"`  // 商户退款单号
	RefundId      string `xml:"refund_id"`      // 微信退款单号
	RefundFee     int64  `xml:"refund_fee"`     // 退款总金额,单位为分,可以做部分退款
	TotalFee      int64  `xml:"total_fee"`      // 订单总金额，单位为分，只能为整数，详见支付金额
	CashFee       int64  `xml:"cash_fee"`       // 现金支付金额，单位为分，只能为整数，详见支付金额

	// 下面字段都是可选返回的(详细见微信支付文档), 为空值表示没有返回, 程序逻辑里需要判断
	SettlementRefundFee int64  `xml:"settlement_refund_fee"` // 退款金额=申请退款金额-非充值代金券退款金额，退款金额<=申请退款金额
	SettlementTotalFee  int64  `xml:"settlement_total_fee"`  // 应结订单金额=订单金额-非充值代金券金额，应结订单金额<=订单金额。
	FeeType             string `xml:"fee_type"`              // 订单金额货币类型，符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	CashFeeType         string `xml:"cash_fee_type"`         // 货币类型，符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	CashRefundFee       int64  `xml:"cash_refund_fee"`       // 现金退款金额，单位为分，只能为整数，详见支付金额
}

// 退款
// 需要证书, Cert() 函数
func (pay *WeixinPay) Refund(req *RefundRequest) (resp *RefundResponse, err error) {
	resp = &RefundResponse{}
	err = pay.DoWithDefaultParams("/secapi/pay/refund", req, resp)
	if err != nil {
		return nil, err
	}
	return
}

type RefundQueryRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选参数, 四选一
	TransactionId string `xml:"transaction_id,omitempty"` // 微信订单号
	OutTradeNo    string `xml:"out_trade_no,omitempty"`   // 商户订单号
	OutRefundNo   string `xml:"out_refund_no,omitempty"`  // 商户退款单号
	RefundId      string `xml:"refund_id,omitempty"`      // 微信退款单号
}

type RefundQueryResponse struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选返回
	TransactionId string       `xml:"transaction_id"` // 微信订单号
	OutTradeNo    string       `xml:"out_trade_no"`   // 商户系统内部的订单号
	TotalFee      int64        `xml:"total_fee"`      // 订单总金额，单位为分，只能为整数，详见支付金额
	CashFee       int64        `xml:"cash_fee"`       // 现金支付金额，单位为分，只能为整数，详见支付金额
	RefundCount   int          `xml:"refund_count"`   // 退款笔数
	RefundList    []RefundItem `xml:"refund_list"`    // 退款列表

	// 下面字段都是可选返回的(详细见微信支付文档), 为空值表示没有返回, 程序逻辑里需要判断
	SettlementTotalFee int64  `xml:"settlement_total_fee"` // 应结订单金额=订单金额-非充值代金券金额，应结订单金额<=订单金额。
	FeeType            string `xml:"fee_type"`             // 订单金额货币类型，符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	CashFeeType        string `xml:"cash_fee_type"`        // 现金支付货币类型
}

type RefundItem struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选返回
	OutRefundNo      string `xml:"out_refund_no"`      // 商户退款单号
	RefundId         string `xml:"refund_id"`          // 微信退款单号
	RefundFee        int64  `xml:"refund_fee"`         // 申请退款金额
	RefundStatus     string `xml:"refund_status"`      // 退款状态
	RefundRecvAccout string `xml:"refund_recv_accout"` // 退款入账账户

	// 下面字段都是可选返回的(详细见微信支付文档), 为空值表示没有返回, 程序逻辑里需要判断
	RefundChannel       string `xml:"refund_channel"`        // 退款渠道
	SettlementRefundFee int64  `xml:"settlement_refund_fee"` // 退款金额
	RefundAccount       string `xml:"refund_account"`        // 退款资金来源
	RefundSuccessTime   string `xml:"refund_success_time"`   // 退款成功时间
}

// 退款订单查询
func (pay *WeixinPay) RefundQuery(req *RefundQueryRequest) (resp *RefundQueryResponse, err error) {
	resp = &RefundQueryResponse{}
	err = pay.DoWithDefaultParams("/pay/refundquery", req, resp)
	if err != nil {
		return nil, err
	}
	return
}

type ReverseRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选参数，二选一
	TransactionId string `xml:"transaction_id,omitempty"` // 微信的订单号，优先使用
	OutTradeNo    string `xml:"out_trade_no,omitempty"`   // 商户系统内部订单号
}

type ReverseResponse struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选返回
	Recall bool `xml:"recall"` // 是否需要继续调用撤销
}

// Reverse 撤销订单.
//  NOTE: 请求需要双向证书.
func (pay *WeixinPay) Reverse(req *ReverseRequest) (resp *ReverseResponse, err error) {
	resp = &ReverseResponse{}
	err = pay.DoWithDefaultParams("/secapi/pay/reverse", req, resp)
	if err != nil {
		return nil, err
	}
	return
}

type DownloadBillRequest struct {
	XMLName struct{} `xml:"xml" json:"-"`

	// 必选参数
	BillDate string `xml:"bill_date"` // 下载对账单的日期，格式：20140603
	BillType string `xml:"bill_type"` // 账单类型

	// 可选参数
	DeviceInfo string `xml:"device_info,omitemepty"` // 微信支付分配的终端设备号
	TarType    string `xml:"tar_type,omitemepty"`    // 压缩账单
}

// 下载涨到到io.Writer
func (pay *WeixinPay) DownloadBillToWriter(req *DownloadBillRequest, writer io.Writer) error {
	var out string
	err := pay.DoWithDefaultParams("/pay/downloadbill", req, &out)
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte(out))
	return err
}

// 下载账单到文件
func (pay *WeixinPay) DownloadBillToFile(req *DownloadBillRequest, path string) error {
	var out string
	err := pay.DoWithDefaultParams("/pay/downloadbill", req, &out)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, []byte(out), 0644)
}
