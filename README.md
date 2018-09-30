微信
=====

### 微信支付

```go
    pay := goweixin.NewWeixinPay("appid", "mch_id", "mch_key", "http://example.com/weixin/notify")
	// 开启沙箱模式
	pay.Sanbox()
	// 也可以 pay = pay.Sanbox()
	// 强制使用双向认证
	//pay = pay.Cert("证书内容...")

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
        ctx.String(200, pay.Reply(True, "OK"))
    }
    ctx.String(200, pay.Reply(True, "reason"))
```
