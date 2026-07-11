# frozen_string_literal: true

require_relative "../../../test_helper"
require_relative "../../../../../harness/ruby-server/harness_replay_store"

class HarnessReplayStoreTest < Minitest::Test
  def test_cross_process_reservations_are_atomic_and_survive_restart
    Dir.mktmpdir do |dir|
      path = File.join(dir, "replay.json")
      assert_single_reservation_winner(spawn_workers(path))
      assert_persisted_reservations(path)
    end
  end

  private

  def spawn_workers(path)
    8.times.map do |index|
      fork do
        store = HarnessReplayStore.new(path)
        unique = store.put_if_absent("unique-#{index}", index)
        shared = store.put_if_absent("shared", index)
        exit!(1) unless unique
        exit!(shared ? 0 : 2)
      end
    end
  end

  def assert_single_reservation_winner(children)
    statuses = children.map do |pid|
      _child, status = Process.wait2(pid)
      assert_includes [0, 2], status.exitstatus
      status.exitstatus
    end
    assert_equal 1, statuses.count(0)
    assert_equal 7, statuses.count(2)
  end

  def assert_persisted_reservations(path)
    values = JSON.parse(File.read(path))
    8.times { |index| assert_equal index, values.fetch("unique-#{index}") }
    assert values.key?("shared")
    refute HarnessReplayStore.new(path).put_if_absent("shared", "replayed")
  end
end
