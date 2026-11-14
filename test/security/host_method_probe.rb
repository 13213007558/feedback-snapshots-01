# frozen_string_literal: true

module LiquidSecurityProbe
  class Recorder
    def initialize
      @calls = []
    end

    def record(name)
      @calls << name
      self
    end

    def clear
      @calls.clear
    end

    def calls
      @calls.dup
    end
  end

  class TracedObject
    attr_reader :recorder
    attr_accessor :context

    def initialize
      @recorder = Recorder.new
      @tags = %w[t1 t2]
    end

    def to_liquid
      recorder.record(:to_liquid)
      self
    end

    def to_liquid_value
      recorder.record(:to_liquid_value)
      self
    end

    def to_s
      recorder.record(:to_s)
      'TRACED'
    end

    def inspect
      recorder.record(:inspect)
      'TRACED-INSPECT'
    end

    def ==(other)
      recorder.record(:==)
      other.is_a?(TracedObject)
    end

    def <=>(_other)
      recorder.record(:<=>)
      0
    end

    def <(_other)
      recorder.record(:<)
      false
    end

    def >(_other)
      recorder.record(:>)
      false
    end

    def empty?
      recorder.record(:empty?)
      false
    end

    def include?(_value)
      recorder.record(:include?)
      false
    end

    def key?(_key)
      recorder.record(:key?)
      true
    end

    def [](key)
      recorder.record(:[])
      key.to_s == 'name' ? 'acme' : nil
    end

    def each
      recorder.record(:each)
      @tags.each { |tag| yield tag }
    end

    def count
      recorder.record(:count)
      @tags.length
    end

    def size
      recorder.record(:size)
      @tags.length
    end

    def first
      recorder.record(:first)
      @tags.first
    end

    def delete_all
      recorder.record(:delete_all)
      :deleted
    end
  end

  class TracedDrop < Liquid::Drop
    attr_reader :recorder

    def initialize
      super()
      @recorder = Recorder.new
      @tags = %w[t1 t2]
    end

    def name
      recorder.record(:name)
      'acme'
    end

    def delete_all
      recorder.record(:delete_all)
      :deleted
    end

    def secret_token
      recorder.record(:secret_token)
      's3cr3t'
    end

    def tags
      recorder.record(:tags)
      @tags
    end

    def to_s
      recorder.record(:to_s)
      'DROP-TO-S'
    end

    def inspect
      recorder.record(:inspect)
      'DROP-INSPECT'
    end

    def ==(other)
      recorder.record(:==)
      other.is_a?(TracedDrop)
    end

    def empty?
      recorder.record(:empty?)
      false
    end

    def include?(_value)
      recorder.record(:include?)
      false
    end

    def each
      recorder.record(:each)
      @tags.each { |tag| yield tag }
    end

    def count
      recorder.record(:count)
      @tags.length
    end

    def size
      recorder.record(:size)
      @tags.length
    end

    def first
      recorder.record(:first)
      @tags.first
    end

    def <(_other)
      recorder.record(:<)
      false
    end

    def >(_other)
      recorder.record(:>)
      false
    end

    def liquid_method_missing(_method)
      recorder.record(:liquid_method_missing)
      nil
    end
  end

  class MissingRaisingDrop < Liquid::Drop
    def name
      'acme'
    end
  end

  class MemoryFileSystem
    def initialize(partials)
      @partials = partials
    end

    def read_template_file(template_name)
      @partials.fetch(template_name)
    end
  end
end
