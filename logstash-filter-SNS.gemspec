Gem::Specification.new do |s|
  s.name = 'logstash-filter-SNS'
  s.version = '0.3'
  s.licenses = ['Stormshield']
  s.summary = "This filter transforms l_monitor statistics."
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Stormshield"]
  s.email = 'svc@stormshield.eu'
  s.homepage = "http://www.stormshield.eu"
  s.require_paths = ["lib"]

  # Files
  s.files = [
'Gemfile',
'LICENSE',
'NOTICE.TXT',
'README.md',
'Rakefile',
'lib/logstash/filters/SNS.rb',
'logstash-filter-SNS.gemspec',
'spec/filters/SNS_spec.rb',
'spec/spec_helper.rb'
  ]
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", ">= 2.0.0", "< 3.0.0"
  s.add_development_dependency 'logstash-devutils', "~> 0"
end
