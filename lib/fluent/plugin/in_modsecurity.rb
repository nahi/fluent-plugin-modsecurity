require 'fluent/plugin/in_tail'
require 'modsecurity_audit_log_parser'

module Fluent
  # TODO: 0.14 support
  class ModsecurityAuditLogInput < NewTailInput
    Plugin.register_input('modsecurity', self)

    # TODO: make format non-required config

    def initialize
      super
      @parsers = {}
    end

    def configure(conf)
      super
      @receive_handler = method(:modsecurity_receive_handler)
    end

    def flush_buffer(tw)
      # it does not use TailWatcher#line_buffer
    end

    # TODO: it only assumes 'Concurrent' log setting
    def modsecurity_receive_handler(lines, tail_watcher)
      path = tail_watcher.path
      es = MultiEventStream.new
      lines.each do |line|
        if log = get_parser(path).parse(line).shift
          es.add(log.time, log.to_h)
          delete_parser(path)
        end
      end
      es
    end

  private

    def get_parser(path)
      # TODO: clean up aged parser instances
      @parsers[path] ||= ModsecurityAuditLogParser.new
    end

    def delete_parser(path)
      @parsers.delete(path)
    end
  end
end
