Gem::Specification.new do |s|
  s.name = 'logstash-filter-SNS'
  s.version = '1.0.0'
  s.licenses = ['Stormshield']
  s.summary = "This filter transforms l_monitor statistics."
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Stormshield"]
  s.email = 'svc@stormshield.eu'
  s.homepage = "http://www.stormshield.eu"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency "logstash-devutils", "~> 1.3", ">= 1.3.1"
end
