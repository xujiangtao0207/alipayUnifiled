package alipay

// AccessToken https://docs.open.alipay.com/api_9/alipay.system.oauth.token
func (this *AliPay) AccessToken(param AliPayAccessToken) (results *AliPayAccessTokenResponse, err error) {
	err = this.doRequest("POST", param, &results)
	return results, err
}
