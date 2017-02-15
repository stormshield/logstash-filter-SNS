require 'spec_helper'
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
    	"Ethernet0" => "out,30061363,47621456,898553,1508784",
    	"Ethernet7" => "bench,163446,10909184,1803352,118612032",
    	"Agg0" => "in,963446,40909184,2803352,918612032"
    ) do
      expect(subject['CPU_Userland']).to eq(10)
      expect(subject['CPU_Interrupt']).to eq(20)
      expect(subject['CPU_Kernel']).to eq(30)
      expect(subject).not_to include('CPU')

      expect(subject['Ethernet0']['name']).to eq('out')
      expect(subject['Ethernet0']['ingress']).to eq(30061363)
      expect(subject['Ethernet0']['ingress_max']).to eq(47621456)
      expect(subject['Ethernet0']['egress']).to eq(898553)
      expect(subject['Ethernet0']['egress_max']).to eq(1508784)

      expect(subject['Ethernet7']['name']).to eq('bench')
      expect(subject['Ethernet7']['ingress']).to eq(163446)
      expect(subject['Ethernet7']['ingress_max']).to eq(10909184)
      expect(subject['Ethernet7']['egress']).to eq(1803352)
      expect(subject['Ethernet7']['egress_max']).to eq(118612032)

      expect(subject['Agg0']['name']).to eq('in')
      expect(subject['Agg0']['ingress']).to eq(963446)
      expect(subject['Agg0']['ingress_max']).to eq(40909184)
      expect(subject['Agg0']['egress']).to eq(2803352,)
      expect(subject['Agg0']['egress_max']).to eq(918612032)

    end
  end
end
