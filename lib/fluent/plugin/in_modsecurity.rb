require 'fluent/plugin/in_tail'
require 'modsecurity_audit_log_parser'
require 'mutex_m'

module Fluent
  # TODO: 0.14 support
  class ModsecurityAuditLogInput < NewTailInput
    Plugin.register_input('modsecurity', self)

    # TODO: make format non-required config
    config_param :parser_cleanup_retention_sec, :integer, default: 600
    config_param :parser_cleanup_interval_sec, :integer, default: 300

    def initialize
      super
      @parsers = {}
      @parsers.extend Mutex_m
    end

    def configure(conf)
      super
      @receive_handler = method(:modsecurity_receive_handler)
      @next_cleanup = Time.now.to_i + @parser_cleanup_interval_sec
    end

    def flush_buffer(tw)
      # it does not use TailWatcher#line_buffer
    end

    # CAUTION: it only assumes 'Concurrent' log setting
    def modsecurity_receive_handler(lines, tail_watcher)
      path = tail_watcher.path
      parser = get_parser(path)
      es = MultiEventStream.new
      lines.each do |line|
        if log = parser.parse(line).shift
          es.add(log.time, log.to_h)
          delete_parser(path)
        end
      end
      es
    end

    def stat
      {
        parser_cache_size: @parsers.size
      }
    end

  private

    def get_parser(path)
      now = Time.now.to_i
      @parsers.synchronize {
        if now > @next_cleanup
          @next_cleanup = now + @parser_cleanup_interval_sec
          @parsers.delete_if do |k, v|
            v[0] < now - @parser_cleanup_retention_sec
          end
        end
        @parsers[path] ||= [now, ModsecurityAuditLogParser.new]
        @parsers[path][1]
      }
    end

    def delete_parser(path)
      @parsers.delete(path)
    end
  end
end
