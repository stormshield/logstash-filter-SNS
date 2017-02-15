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
		values = event['CPU'].split(',')
		event['CPU_Userland']  = values[0].to_i
		event['CPU_Interrupt'] = values[1].to_i
		event['CPU_Kernel']    = values[2].to_i
		event.remove('CPU')
    end

    #PVM
    if event.include?('Pvm')
		values = event['Pvm'].split(',')
		event['Pvm']  = {}
		event['Pvm']['vuln_total']    = values[0].to_i
		event['Pvm']['vuln_remote']   = values[1].to_i
		event['Pvm']['vuln_server']   = values[2].to_i
		event['Pvm']['vuln_crit']     = values[3].to_i
		event['Pvm']['vuln_minor']    = values[4].to_i
		event['Pvm']['vul_major']     = values[5].to_i
		event['Pvm']['vuln_with_fix'] = values[6].to_i
		event['Pvm']['info_total']    = values[7].to_i
		event['Pvm']['info_minor']    = values[8].to_i
		event['Pvm']['info_major']    = values[9].to_i
		event['Pvm']['info_host']     = values[10].to_i
    end

    #EthernetX
    interfaces = event.to_hash.select { |key| key.to_s.match(/^(ethernet|vlan|wlan|sslvpn|qid|ipsec|agg)\d*$/i) }.keys
    interfaces.each do |iface|
      values = event[iface].split(',')
      event[iface] = {}
      event[iface]['name']        = values[0]
      event[iface]['ingress']     = values[1].to_i
      event[iface]['ingress_max'] = values[2].to_i
      event[iface]['egress']      = values[3].to_i
      event[iface]['egress_max']  = values[4].to_i
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::SNS
