package alipay

// UserInfoShare https://docs.open.alipay.com/api_2/alipay.user.info.share
func (this *AliPay) GetUserInfoShare(param AliPayUserInfoShare) (results *AliPayUserInfoShareResponse, err error) {
	err = this.doRequest("POST", param, &results)
	return results, err
}
