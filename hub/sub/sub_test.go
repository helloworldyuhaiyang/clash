package sub

import (
	"encoding/json"
	"reflect"
	"testing"
)

func Test_mergeAllConfig(t *testing.T) {
	info := `[{"name":"日本 04  | 1x JP","type":"vmess","server":"6w7j3p04.mcfront.xyz","port":"31116","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"日本 05  | 1x JP","type":"vmess","server":"6w7j3p05.mcfront.xyz","port":"31106","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"日本 06  | 1x JP","type":"vmess","server":"6w7j3p06.mcfront.xyz","port":"31111","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"香港 04 | 1x HK","type":"vmess","server":"5m4h0k04.mcfront.xyz","port":"31601","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"香港 05 | 1x HK","type":"vmess","server":"5m4h0k05.mcfront.xyz","port":"31606","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"香港 06 | 1x HK","type":"vmess","server":"5m4h0k06.mcfront.xyz","port":"31611","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"台湾 04  | 1x TWN","type":"vmess","server":"2d1t5w04.mcfront.xyz","port":"31301","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"台湾 05  | 1x TWN","type":"vmess","server":"2d1t5w05.mcfront.xyz","port":"31306","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"台湾 06  | 1x TWN","type":"vmess","server":"2d1t5w06.mcfront.xyz","port":"31311","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"新加坡 04 | 1x SG","type":"vmess","server":"1c7s2g04.mcfront.xyz","port":"31201","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"新加坡 05 | 1x SG","type":"vmess","server":"1c7s2g05.mcfront.xyz","port":"31206","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"新加坡 06 | 1x SG","type":"vmess","server":"1c7s2g06.mcfront.xyz","port":"31211","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"美国 04 | 1x US","type":"vmess","server":"4a2u0a04.mcfront.xyz","port":"31501","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"美国 05 | 1x US","type":"vmess","server":"4a2u0a05.mcfront.xyz","port":"31506","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"美国 06 | 1x US","type":"vmess","server":"4a2u0a06.mcfront.xyz","port":"31511","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"韩国 02 | 1x KR","type":"vmess","server":"8l2k1r04.mcfront.xyz","port":"31401","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"菲律宾 04 | 1x PH","type":"vmess","server":"1a4p0h04.mcfront.xyz","port":"31801","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"俄罗斯 04 | 1x RU","type":"vmess","server":"4t1r5u04.mcfront.xyz","port":"31851","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"马来西亚 04 | 1x MY","type":"vmess","server":"6e3m6y04.mcfront.xyz","port":"31887","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"泰国 04 | 1x TH","type":"vmess","server":"2c2t8h04.mcfront.xyz","port":"31904","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"阿根廷 04 | 1x AR","type":"vmess","server":"7c1a1r04.mcfront.xyz","port":"31861","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"匈牙利 04 | 1x HU","type":"vmess","server":"3c2h4u04.mcfront.xyz","port":"31864","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"土耳其 04 | 1x TR","type":"vmess","server":"4t1u6r04.mcfront.xyz","port":"31868","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"乌克兰 04 | 1x UA","type":"vmess","server":"4w7u4a04.mcfront.xyz","port":"31871","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"越南 04 | 1x VN","type":"vmess","server":"2w8u2a04.mcfront.xyz","port":"31874","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"巴西 04 | 1x BR","type":"vmess","server":"7c6i2r04.mcfront.xyz","port":"31877","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"印度 04 | 1x IN","type":"vmess","server":"6q3i1n04.mcfront.xyz","port":"31831","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"澳大利亚 04 | 1x AU","type":"vmess","server":"4o5a3u04.mcfront.xyz","port":"31821","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"英国 04 | 1x UK","type":"vmess","server":"3a4u0k04.mcfront.xyz","port":"31811","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"德国 04 | 1x AU","type":"vmess","server":"9t1d5e04.mcfront.xyz","port":"31841","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"葡萄牙 04 | 1x PT","type":"vmess","server":"4c3p1t01.mcfront.xyz","port":"31881","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"加拿大 02 | 1x CA","type":"vmess","server":"3d1c4a04.mcfront.xyz","port":"31701","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"荷兰 02 | 1x NL","type":"vmess","server":"6e2n8l04.mcfront.xyz","port":"31901","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}},{"name":"西班牙 02 | 1x ES","type":"vmess","server":"2d3e6s01.mcfront.xyz","port":"31884","uuid":"fb50cf9e-b84e-4b31-b95c-1656c1c08236","alterId":"0","cipher":"none","tls":true,"ws-opts":{}}]`
	ps := make([]any, 0)
	err := json.Unmarshal([]byte(info), &ps)
	if err != nil {
		t.Error(err)
		return
	}
	ps2 := make([]any, 0)
	_ = json.Unmarshal([]byte(info), &ps2)

	type args struct {
		ps map[string][]any
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "test",
			args: args{ps: map[string][]any{"S1": ps, "S2": ps2}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeAllConfig(tt.args.ps); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeAllConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
