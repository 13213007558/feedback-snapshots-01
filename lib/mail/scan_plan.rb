# frozen_string_literal: true

module Mail
  # A ScanPlan walks the complete MIME tree of a Mail::Message and enumerates
  # every node that can actually carry content: leaf parts (including every
  # branch of a multipart/alternative), nested message/rfc822 messages, the
  # preamble and epilogue of multipart bodies, and any part whose transfer
  # encoding cannot be decoded.
  #
  # Each node is represented by a Mail::ScanItem describing the decoding steps
  # required to inspect its bytes and a completion status. A node that cannot be
  # decoded can never be marked clean, so an unresolved or undecodable node
  # keeps the plan from reporting #all_clear? until the caller explicitly
  # rejects it.
  #
  # ScanPlan never performs any virus checking itself. It only produces the
  # inventory and tracks the dispositions recorded by the caller's scanner.
  class ScanPlan
    include Enumerable

    # Raised when a caller tries to mark content clean or as a threat without
    # being able to decode and inspect it first.
    class UndecodableContentError < StandardError; end

    # Disposition recorded by the caller once a node has been handled.
    module Status
      PENDING  = 'pending'.freeze
      CLEAN    = 'clean'.freeze
      THREAT   = 'threat'.freeze
      REJECTED = 'rejected'.freeze
    end

    # The kind of content-bearing node a ScanItem represents.
    module Kind
      LEAF      = 'leaf'.freeze
      MESSAGE   = 'message/rfc822'.freeze
      PREAMBLE  = 'preamble'.freeze
      EPILOGUE  = 'epilogue'.freeze
    end

    attr_reader :items

    def initialize(message)
      @items = []
      walk(message, '')
    end

    def each(&block)
      @items.each(&block)
    end

    def size
      @items.size
    end

    # Returns the items that no registered transfer encoding can decode. These
    # nodes cannot be inspected and therefore block an all-clear result.
    def undecodable_items
      @items.reject(&:decodable?)
    end

    def pending_items
      @items.select(&:pending?)
    end

    def threats
      @items.select(&:threat?)
    end

    def rejected_items
      @items.select(&:rejected?)
    end

    def pending?
      @items.any?(&:pending?)
    end

    # True once every node has been dispositioned.
    def fully_scanned?
      @items.none?(&:pending?)
    end

    # True only when every node is either confirmed clean or has been
    # explicitly rejected. A pending node, a threat, or an undecodable node
    # that has not been rejected all keep this false.
    def all_clear?
      @items.all? { |item| item.clean? || item.rejected? }
    end

    private

    def walk(node, container_path)
      if node.mime_type == Kind::MESSAGE
        walk_message(node, container_path)
      elsif node.multipart?
        walk_multipart(node, container_path)
      else
        add_leaf(node, container_path)
      end
    end

    def walk_multipart(part, container_path)
      body = part.body

      unless Utilities.blank?(body.preamble)
        @items << ScanItem.preamble(label_path(container_path, 'preamble'), body.preamble)
      end

      part.parts.each_with_index do |child, index|
        child_path = join_path(container_path, index + 1)
        walk(child, child_path)
      end

      unless Utilities.blank?(body.epilogue)
        @items << ScanItem.epilogue(label_path(container_path, 'epilogue'), body.epilogue)
      end
    end

    def walk_message(part, path)
      item = ScanItem.message(path, part)
      @items << item

      return unless item.decodable?

      inner = Mail.new(part.body.decoded)
      walk(inner, path)
    end

    def add_leaf(part, path)
      @items << ScanItem.leaf(path, part)
    end

    def join_path(container_path, index)
      container_path.empty? ? index.to_s : "#{container_path}.#{index}"
    end

    def label_path(container_path, label)
      container_path.empty? ? label : "#{container_path}.#{label}"
    end
  end

  # A single content-bearing MIME node and the disposition recorded for it.
  class ScanItem
    attr_reader :path, :kind, :part, :mime_type, :filename,
                :transfer_encoding, :decoding_steps, :status,
                :decode_error, :reject_reason

    def self.leaf(path, part)
      new(path: path, kind: ScanPlan::Kind::LEAF, part: part,
          mime_type: part.mime_type, filename: safe_filename(part),
          transfer_encoding: part.body.encoding,
          decoding_steps: leaf_steps(part))
    end

    def self.message(path, part)
      steps = ["transfer-decode:#{part.body.encoding}", 'parse-message/rfc822']
      new(path: path, kind: ScanPlan::Kind::MESSAGE, part: part,
          mime_type: part.mime_type, filename: safe_filename(part),
          transfer_encoding: part.body.encoding,
          decoding_steps: steps)
    end

    def self.preamble(path, content)
      new(path: path, kind: ScanPlan::Kind::PREAMBLE, part: nil,
          mime_type: nil, filename: nil, transfer_encoding: nil,
          decoding_steps: [], content: content)
    end

    def self.epilogue(path, content)
      new(path: path, kind: ScanPlan::Kind::EPILOGUE, part: nil,
          mime_type: nil, filename: nil, transfer_encoding: nil,
          decoding_steps: [], content: content)
    end

    def self.leaf_steps(part)
      steps = ["transfer-decode:#{part.body.encoding}"]
      charset = part.charset
      if part.text? && charset && !/^utf-?8$/i.match?(charset) && !/^us-ascii$/i.match?(charset)
        steps << "charset-transcode:#{charset}>UTF-8"
      end
      steps
    end

    def self.safe_filename(part)
      part.filename
    rescue StandardError
      nil
    end

    def initialize(path:, kind:, part:, mime_type:, filename:,
                   transfer_encoding:, decoding_steps:, content: nil)
      @path = path
      @kind = kind
      @part = part
      @mime_type = mime_type
      @filename = filename
      @transfer_encoding = transfer_encoding
      @decoding_steps = decoding_steps
      @status = ScanPlan::Status::PENDING
      @decode_error = nil
      @reject_reason = nil
      @decoded_content = content
      @decode_attempted = !content.nil?
    end

    # A node is inspectable when a registered transfer encoding exists for it.
    # Preamble and epilogue text needs no transfer decoding and is always
    # inspectable.
    def decodable?
      return true if @part.nil?
      Mail::Encodings.defined?(@transfer_encoding)
    end

    # Returns the transfer-decoded bytes for this node, or nil when the node
    # cannot be decoded (in which case #decode_error is populated).
    def decoded
      return @decoded_content if @decode_attempted

      @decode_attempted = true
      begin
        @decoded_content = @part.body.decoded
      rescue StandardError => e
        @decode_error = e.message
      end
      @decoded_content
    end

    def mark_clean!
      assert_decodable!(:mark_clean!)
      @status = ScanPlan::Status::CLEAN
      self
    end

    def mark_threat!
      assert_decodable!(:mark_threat!)
      @status = ScanPlan::Status::THREAT
      self
    end

    # Explicitly quarantines or drops a node without inspecting its bytes. This
    # is the only disposition allowed for an undecodable node.
    def reject!(reason = nil)
      @reject_reason = reason
      @status = ScanPlan::Status::REJECTED
      self
    end

    def pending?
      @status == ScanPlan::Status::PENDING
    end

    def clean?
      @status == ScanPlan::Status::CLEAN
    end

    def threat?
      @status == ScanPlan::Status::THREAT
    end

    def rejected?
      @status == ScanPlan::Status::REJECTED
    end

    def leaf?
      @kind == ScanPlan::Kind::LEAF
    end

    def message?
      @kind == ScanPlan::Kind::MESSAGE
    end

    def preamble?
      @kind == ScanPlan::Kind::PREAMBLE
    end

    def epilogue?
      @kind == ScanPlan::Kind::EPILOGUE
    end

    def inspect
      "#<#{self.class} path=#{path.inspect} kind=#{kind.inspect} " \
        "mime_type=#{mime_type.inspect} status=#{status.inspect} " \
        "decodable=#{decodable?}>"
    end

    private

    def assert_decodable!(action)
      unless decodable?
        raise ScanPlan::UndecodableContentError,
              "cannot #{action.to_s.delete_suffix('!')} #{path}: " \
              "transfer encoding #{transfer_encoding.inspect} is not supported"
      end
    end
  end
end
