微信
=====

[![GoDoc](https://godoc.org/github.com/zwczou/goweixin?status.svg)](https://godoc.org/github.com/zwczou/goweixin)

### 微信支付

```go
pay := goweixin.NewWeixinPay("appid", "mch_id", "mch_key", "http://example.com/weixin/notify")
// 开启沙箱模式
pay.Sanbox()
// 也可以 pay = pay.Sanbox()

// 强制使用双向认证
//pay = pay.Cert("证书内容...")

// 开启debug模式
pay = pay.Debug()

// 统一下单
req := &goweixin.UnifiedOrderRequest{
    TradeType:      "JSAPI",
    Body:           "测试标题",
    OutTradeNo:     pay.NonceStr(),
    TotalFee:       101,
    SpbillCreateIP: "127.0.0.1",
    OpenId:         "openid",
}
resp, err := pay.UnifiedOrder(req)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("%+v\n", resp)

// JSAPI
req.OutTradeNo = pay.NonceStr()
resp2, err := pay.Jsapi(req)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("%+v\n", resp2)

// 校验通知内容
// 伪代码
// body 请求body
var notify goweixin.WeixinPayNotify
xml.Unmarshal(body, &notify)
ok, err := pay.Check(notify, nil)
if ok {
    ctx.String(200, pay.Reply(true, "OK"))
}
ctx.String(200, pay.Reply(true, "reason"))
```

### 工具函数

```go
// 转换map[string]string为xml
pay.ToXML(map[string]string{"result": "abc"}) // <xml><result>abc</result></xml>

// 校验签名是否正确
// nil使用MD5
ok, err := pay.Check(val, nil)

// 生成随机字符串
RandString(10)

// 生成通知回复消息
pay.Reply(true, "OK")
// 如果需要自己格式化, 比如使用`echo`框架
ctx.XML(200, goweixin.ReplyResponse{Code: goweixin.Success, Message: "ok"})
```
