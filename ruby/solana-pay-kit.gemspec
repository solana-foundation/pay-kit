# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "solana-pay-kit"
  spec.version = "0.1.0"
  spec.summary = "Building blocks for Agentic payments (x402, MPP, AP2)"
  spec.description = "Let your APIs charge agents using x402 and MPP protocols"
  spec.authors = ["Solana Foundation"]
  spec.homepage = "https://github.com/solana-foundation/pay-kit"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"].select { |path| File.file?(path) }
  spec.require_paths = ["lib"]

  spec.add_dependency "base64", "~> 0.3"
  spec.add_dependency "bigdecimal", "~> 3.1"
  spec.add_dependency "ed25519", "~> 1.4"
  spec.add_dependency "json", "~> 2.9"
  spec.add_dependency "net-http", "~> 0.6"
  spec.add_dependency "rack", "~> 3.1"
  spec.add_dependency "rackup", "~> 2.2"
  spec.add_dependency "puma", "~> 7.1"
  spec.add_dependency "sinatra", "~> 4.2"

  spec.add_development_dependency "bundler-audit", "~> 0.9"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rack-test", "~> 2.1"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "standard", "~> 1.43"
  spec.add_development_dependency "yard", "~> 0.9"
end
