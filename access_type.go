package alipay

// https://docs.open.alipay.com/api_9/alipay.system.oauth.token
type AliPayAccessToken struct {
	AppAuthToken string `json:"-"` // 可选
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RefreshToken string `json:"refresh_token"`
}

func (this AliPayAccessToken) APIName() string {
	return "alipay.system.oauth.token"
}

func (this AliPayAccessToken) Params() map[string]string {
	var m = make(map[string]string)
	m["app_auth_token"] = this.AppAuthToken
	m["grant_type"] = this.GrantType
	m["code"] = this.Code
	return m
}

func (this AliPayAccessToken) ExtJSONParamName() string {
	return ""
}

func (this AliPayAccessToken) ExtJSONParamValue() string {
	return marshal(this)
}

type AliPayAccessTokenResponse struct {
	Body struct {
		//error
		Code    string `json:"code"`
		Msg     string `json:"msg"`
		SubCode string `json:"sub_code"`
		SubMsg  string `json:"sub_msg"`

		//success
		UserId       string `json:"user_id"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		ReFreshToken string `json:"refresh_token"`
		ReExpiresIn  int64  `json:"re_expires_in"`
	} `json:"alipay_system_oauth_token_response"`
	ErrorResp struct {
		Code    string `json:"code"`
		Msg     string `json:"msg"`
		SubCode string `json:"sub_code"`
		SubMsg  string `json:"sub_msg"`
	} `json:"error_response"`
	Sign string `json:"sign"`
}

func (this *AliPayAccessTokenResponse) IsSuccess() (bool, string) {
	if this.Body.AccessToken != "" {
		return true, ""
	}
	return false, marshal(this.ErrorResp)
}
