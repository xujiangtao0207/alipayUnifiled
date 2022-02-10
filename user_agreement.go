package alipay

// UserAgreementPageSign https://docs.alipay.com/pre-open/api_pre/alipay.user.agreement.page.sign
func (this *AliPay) UserAgreementPageSign(param AliPayUserAgreementPageSign) (signStr string, err error) {
	signStr, err = this.doPacket("GET", param)
	return signStr, err
}

// UserAgreementQuery https://docs.alipay.com/pre-open/api_pre/alipay.user.agreement.query
func (this *AliPay) UserAgreementQuery(param AliPayUserAgreementQuery) (results *AliPayUserAgreementQueryResponse, err error) {
	err = this.doRequest("POST", param, &results)
	return results, err
}

// UserAgreementUnSign https://docs.alipay.com/pre-open/20170601105911096277/wob270
func (this *AliPay) UserAgreementUnSign(param AliPayUserAgreementUnSign) (results *AliPayUserAgreementUnSignResponse, err error) {
	err = this.doRequest("POST", param, &results)
	return results, err
}
