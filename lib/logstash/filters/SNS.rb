# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::SNS < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   SNS {}
  # }
  #
  config_name "SNS"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    #CPU
    if event.include?('CPU')
		values = event.get('CPU').split(',')
    event.remove('CPU')
		event.set('CPU_Userland', values[0].to_i)
		event.set('CPU_Kernel', values[1].to_i)
		event.set('CPU_Interrupt', values[2].to_i)
    end

    #PVM
    if event.include?('Pvm')
		values = event.get('Pvm').split(',')
    event.remove('Pvm')
		event.set('[Pvm][vuln_total]',    values[0].to_i)
		event.set('[Pvm][vuln_remote]',   values[1].to_i)
		event.set('[Pvm][vuln_server]',   values[2].to_i)
		event.set('[Pvm][vuln_crit]',     values[3].to_i)
		event.set('[Pvm][vuln_minor]',    values[4].to_i)
		event.set('[Pvm][vul_major]',     values[5].to_i)
		event.set('[Pvm][vuln_with_fix]', values[6].to_i)
		event.set('[Pvm][info_total]',    values[7].to_i)
		event.set('[Pvm][info_minor]',    values[8].to_i)
		event.set('[Pvm][info_major]',    values[9].to_i)
		event.set('[Pvm][info_host]',     values[10].to_i)
    end

    #aggXX, ethernetXX, ipsecXX, qidXX, sslvpnXX, vlanXX, wifiXX, wlanXX, wldevXX
    interfaces = event.to_hash.select { |key| key.to_s.match(/^(agg|ethernet|ipsec|qid|sslvpn|vlan|wifi|wlan|wldev)\d*$/i) }.keys
    interfaces.each do |iface|
      values = event.get(iface).split(',')
      event.remove(iface)
      event.set("[#{iface}][name]",          values[0])
      event.set("[#{iface}][ingress]",       values[1].to_i)
      event.set("[#{iface}][ingress_max]",   values[2].to_i)
      event.set("[#{iface}][egress]",        values[3].to_i)
      event.set("[#{iface}][egress_max]",    values[4].to_i)
      # For SNS > 3.x, interfaces have 7 values
      if values.size > 5
        event.set("[#{iface}][packet_accept]", values[5].to_i)
        event.set("[#{iface}][packet_block]",  values[6].to_i)
      end
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::SNS
