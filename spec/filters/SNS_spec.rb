require 'logstash/devutils/rspec/spec_helper'
require "logstash/filters/SNS"

describe LogStash::Filters::SNS do
  describe "SNS log analyser" do
    let(:config) do <<-CONFIG
      filter {
        SNS {
        }
      }
    CONFIG
    end
    sample(
      "CPU" => "10,20,30",
      "Agg0" => "in,963446,40909184,2803352,918612032,148119,102",
      "Ethernet0" => "out,30061363,47621456,898553,1508784,293925,1958",
      "ipsec" => "bench,163446,10909184,1803352,118612032",
      "qid4" => "queue,1234,5678,910,1112131415,1617,18",
      "sslvpn1" => "vpn,100,101,102,103",
      "vlan3" => "vlan,200,201,202,203",
      "wifi1" => "PublicAP,300,301,302,303,300004,300005",
      "wlan" => "wlan2,400,401,402,403,400004,400005",
      "wldev0" => "WifiPhy0,500,501,502,503"
    ) do
      expect(subject.get('CPU_Userland')).to eq(10)
      expect(subject.get('CPU_Kernel')).to eq(20)
      expect(subject.get('CPU_Interrupt')).to eq(30)
      expect(subject.get('CPU')).to be_nil

      expect(subject.get('[Ethernet0][name]')).to eq('out')
      expect(subject.get('[Ethernet0][ingress]')).to eq(30061363)
      expect(subject.get('[Ethernet0][ingress_max]')).to eq(47621456)
      expect(subject.get('[Ethernet0][egress]')).to eq(898553)
      expect(subject.get('[Ethernet0][egress_max]')).to eq(1508784)
      expect(subject.get('[Ethernet0][packet_accept]')).to eq(293925)
      expect(subject.get('[Ethernet0][packet_block]')).to eq(1958)

      expect(subject.get('[ipsec][name]')).to eq('bench')
      expect(subject.get('[ipsec][ingress]')).to eq(163446)
      expect(subject.get('[ipsec][ingress_max]')).to eq(10909184)
      expect(subject.get('[ipsec][egress]')).to eq(1803352)
      expect(subject.get('[ipsec][egress_max]')).to eq(118612032)
      expect(subject.get('ipsec')).not_to have_key('packet_accept')
      expect(subject.get('ipsec')).not_to have_key('packet_block')

      expect(subject.get('[Agg0][name]')).to eq('in')
      expect(subject.get('[Agg0][ingress]')).to eq(963446)
      expect(subject.get('[Agg0][ingress_max]')).to eq(40909184)
      expect(subject.get('[Agg0][egress]')).to eq(2803352)
      expect(subject.get('[Agg0][egress_max]')).to eq(918612032)
      expect(subject.get('[Agg0][packet_accept]')).to eq(148119)
      expect(subject.get('[Agg0][packet_block]')).to eq(102)

      expect(subject.get('[qid4][name]')).to eq('queue')
      expect(subject.get('[qid4][ingress]')).to eq(1234)
      expect(subject.get('[qid4][ingress_max]')).to eq(5678)
      expect(subject.get('[qid4][egress]')).to eq(910)
      expect(subject.get('[qid4][egress_max]')).to eq(1112131415)
      expect(subject.get('[qid4][packet_accept]')).to eq(1617)
      expect(subject.get('[qid4][packet_block]')).to eq(18)

      expect(subject.get('[sslvpn1][name]')).to eq('vpn')
      expect(subject.get('[sslvpn1][ingress]')).to eq(100)
      expect(subject.get('[sslvpn1][ingress_max]')).to eq(101)
      expect(subject.get('[sslvpn1][egress]')).to eq(102)
      expect(subject.get('[sslvpn1][egress_max]')).to eq(103)
      expect(subject.get('sslvpn1')).not_to have_key('packet_accept')
      expect(subject.get('sslvpn1')).not_to have_key('packet_block')

      expect(subject.get('[vlan3][name]')).to eq('vlan')
      expect(subject.get('[vlan3][ingress]')).to eq(200)
      expect(subject.get('[vlan3][ingress_max]')).to eq(201)
      expect(subject.get('[vlan3][egress]')).to eq(202)
      expect(subject.get('[vlan3][egress_max]')).to eq(203)
      expect(subject.get('vlan3')).not_to have_key('packet_accept')
      expect(subject.get('vlan3')).not_to have_key('packet_block')

      expect(subject.get('[wifi1][name]')).to eq('PublicAP')
      expect(subject.get('[wifi1][ingress]')).to eq(300)
      expect(subject.get('[wifi1][ingress_max]')).to eq(301)
      expect(subject.get('[wifi1][egress]')).to eq(302)
      expect(subject.get('[wifi1][egress_max]')).to eq(303)
      expect(subject.get('[wifi1][packet_accept]')).to eq(300004)
      expect(subject.get('[wifi1][packet_block]')).to eq(300005)

      expect(subject.get('[wlan][name]')).to eq('wlan2')
      expect(subject.get('[wlan][ingress]')).to eq(400)
      expect(subject.get('[wlan][ingress_max]')).to eq(401)
      expect(subject.get('[wlan][egress]')).to eq(402)
      expect(subject.get('[wlan][egress_max]')).to eq(403)
      expect(subject.get('[wlan][packet_accept]')).to eq(400004)
      expect(subject.get('[wlan][packet_block]')).to eq(400005)

      expect(subject.get('[wldev0][name]')).to eq('WifiPhy0')
      expect(subject.get('[wldev0][ingress]')).to eq(500)
      expect(subject.get('[wldev0][ingress_max]')).to eq(501)
      expect(subject.get('[wldev0][egress]')).to eq(502)
      expect(subject.get('[wldev0][egress_max]')).to eq(503)
      expect(subject.get('wldev0')).not_to have_key('packet_accept')
      expect(subject.get('wldev0')).not_to have_key('packet_block')
    end
  end
end
