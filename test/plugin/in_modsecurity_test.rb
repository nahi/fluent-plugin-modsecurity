require 'test_helper'
require 'tmpdir'
require 'fileutils'

class ModsecurityInputTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
    @dir = Dir.mktmpdir
    @config = %[
      format ltsv
      read_from_head true
      path #{@dir}/audit/*/*/*
      pos_file #{@dir}/modsecurity-audit-log.pos
      tag t1
      parser_cleanup_retention_sec 1
      parser_cleanup_interval_sec 0
    ]
  end

  LOG = <<__EOM__
--2e793d5f-A--
[23/May/2017:07:44:10 +0000] mcAcAcecAcAcAbAcAcAcAcmo 123.45.67.8 60491 127.0.0.1 80
--2e793d5f-B--
HTTP/1.1 200 OK
Server:
Content-Type: application/json
Content-Length: 15
Connection: keep-alive

--2e793d5f-F--
HTTP/1.1 400 Bad Request
Server: Nahi server
Content-Type: application/json
Content-Length: 2
Connection: keep-alive

--2e793d5f-E--

--2e793d5f-H--
Message: Warning. Match of "eq 0" against "REQBODY_ERROR" required. [file "/path/to/conf.d/modsecurity.conf"] [line "60"] [id "200002"] [msg "Failed to parse request body."] [data ""] [severity "CRITICAL"]
Message: Warning. Match of "eq 0" against "REQBODY_ERROR" required. [file "/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "157"] [id "920130"] [rev "1"] [msg "Failed to parse request body."] [data ""] [severity "CRITICAL"] [ver "OWASP_CRS/3.0.0"] [maturity "9"] [accuracy "9"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS/PROTOCOL_VIOLATION/INVALID_REQ"] [tag "CAPEC-272"]
Apache-Handler: IIS
Stopwatch: 1495601080000788 792314 (- - -)
Stopwatch2: 1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0
Response-Body-Transformed: Dechunked
Producer: ModSecurity for nginx (STABLE)/2.9.0 (http://www.modsecurity.org/); OWASP_CRS/3.0.2.
Server: ModSecurity Standalone
Engine-Mode: "DETECTION_ONLY"

--2e793d5f-Z--

__EOM__

  def create_driver(conf = @config)
    Fluent::Test::InputTestDriver.new(Fluent::ModsecurityAuditLogInput).configure(conf)
  end

  sub_test_case 'normal case' do
    test 'scans audit log' do
      logdir = File.join(@dir, 'audit', '20170616', '20170616-0001')
      FileUtils.mkdir_p(logdir)
      logfile = File.join(logdir, '20170616-000101-@cAb')
      FileUtils.touch(logfile)
      d = create_driver
      d.run do
        File.open(logfile, 'w') do |f|
          f << LOG
        end
        sleep 1
      end
      events = d.events
      assert_equal 1, events.size
      time, record = events.first
      assert_equal 1495525450, time
      assert_equal 'mcAcAcecAcAcAbAcAcAcAcmo', record[:unique_transaction_id]
      assert_equal 'CAPEC-272', record[:rule_tag]
      # consumed
      assert_equal 0, d.instance.instance_eval { @tails }.size
    end

    test 'scans audit log which was incrementally written' do
      logdir = File.join(@dir, 'audit', '20170616', '20170616-0001')
      FileUtils.mkdir_p(logdir)
      logfile1 = File.join(logdir, '20170616-000101-@cAbAb_1')
      FileUtils.touch(logfile1)
      logfile2 = File.join(logdir, '20170616-000101-@cAbAb_2')
      FileUtils.touch(logfile2)
      d = create_driver
      d.run do
        File.open(logfile1, 'w') do |f|
          f << LOG[0, 500]
        end
        sleep 1
        File.open(logfile2, 'w') do |f|
          f << LOG
        end
        File.open(logfile1, 'w') do |f|
          f << LOG[501, LOG.size]
        end
        sleep 1
        # both were consumed
        assert_equal 0, d.instance.instance_eval { @tails }.size
      end
      events = d.events
      assert_equal 2, events.size
    end
  end

  sub_test_case 'parser cache' do
    test 'parser cache disappears after specific seconds' do
      logdir = File.join(@dir, 'audit', '20170616', '20170616-0001')
      FileUtils.mkdir_p(logdir)
      logfile1 = File.join(logdir, '20170616-000101-@cAbAbAb_1')
      FileUtils.touch(logfile1)
      logfile2 = File.join(logdir, '20170616-000101-@cAbAbAb_2')
      FileUtils.touch(logfile2)
      logfile3 = File.join(logdir, '20170616-000101-@cAbAbAb_3')
      FileUtils.touch(logfile3)
      d = create_driver
      d.run do
        sleep 1
        # plugin keeps parser cache for incomplete write
        File.open(logfile1, 'w') do |f|
          f << LOG[0, 500]
        end
        File.open(logfile2, 'w') do |f|
          f << LOG[0, 500]
        end
        sleep 1
        assert_equal 2, d.instance.stat[:parser_cache_size]
        sleep 1
        # but cache only keeps specified seconds
        File.open(logfile3, 'w') do |f|
          f << LOG[0, 500]
        end
        sleep 1
        assert_equal 1, d.instance.stat[:parser_cache_size]
        # all were not yet consumed
        assert_equal 3, d.instance.instance_eval { @tails }.size
      end
    end
  end
end
