# Local preparation

Upstream: https://github.com/njh/ruby-mqtt
Upstream commit: db29b48456f8c40600cbddf3dd70ef390d4efd35

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec rspec spec/mqtt_packet_spec.rb spec/mqtt_client_spec.rb spec/mqtt_sn_packet_spec.rb
```

The baseline passed in 2.57 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
