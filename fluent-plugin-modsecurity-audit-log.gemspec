# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-modsecurity-audit-log"
  spec.version       = File.read("VERSION").strip
  spec.authors       = ["Hiroshi Nakamura"]
  spec.email         = ["nahi@ruby-lang.org"]

  spec.summary       = %q{Modsecurity AuditLog input plugin for Fluentd}
  spec.description   = %q{Modsecurity AuditLog input plugin for Fluentd}
  spec.homepage      = "https://github.com/nahi/fluent-plugin-modsecurity-audit-log"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "fluentd", ["~> 0.12.31", "< 2"]
  spec.add_dependency "modsecurity_audit_log_parser", ">= 0.1.4"

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "test-unit", ">= 3.0.0"
end
