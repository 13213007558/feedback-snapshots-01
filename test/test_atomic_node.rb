# frozen_string_literal: true

require_relative "common"

describe "Sanitize#node! atomicity" do
  make_my_diffs_pretty!

  # Returns every node in the tree along with the state that must survive a
  # failed sanitization attempt.
  def capture(node, acc = [])
    acc << [node, (node.parent if node.respond_to?(:parent)), node.previous_sibling,
      node.next_sibling, node.document]
    node.children.each { |child| capture(child, acc) }
    acc
  end

  def assert_tree_unchanged(refs, expected_html, document)
    refs.each do |node, parent, previous_sibling, next_sibling, owner|
      # Nokogiri can't reattach a doctype without recreating it.
      next if node.type == Nokogiri::XML::Node::DTD_NODE

      if node.respond_to?(:parent)
        if parent.nil?
          assert_nil node.parent
        else
          _(node.parent).must_equal parent
        end
      end

      _(node.document).must_equal owner
      if next_sibling.nil?
        assert_nil node.next_sibling
      else
        _(node.next_sibling).must_equal next_sibling
      end

      # The node before a document's root may be a doctype that was recreated.
      unless node.previous_sibling&.type == Nokogiri::XML::Node::DTD_NODE &&
          previous_sibling&.type == Nokogiri::XML::Node::DTD_NODE
        if previous_sibling.nil?
          assert_nil node.previous_sibling
        else
          _(node.previous_sibling).must_equal previous_sibling
        end
      end
    end

    _(document.to_html).must_equal expected_html
  end

  it "should commit successful sanitization in place" do
    frag = Nokogiri::HTML5.fragment('<div><b>keep</b><script>alert(1)</script></div>')
    b = frag.at_css("b")

    Sanitize.node!(frag, elements: %w[div strong], transformers: lambda { |env|
      env[:node].name = "strong" if env[:node].name == "b"
    })

    _(frag.to_html).must_equal "<div><strong>keep</strong></div>"
    _(frag.at_css("strong")).must_equal b
  end

  it "should restore the tree and node identity when a transformer raises" do
    doc = Nokogiri::HTML5.parse(%q{
      <!DOCTYPE html>
      <html lang="en"><body>
        <div id="wrapper" class="box">
          <p id="first">first</p>
          <p id="second">second<b id="bold">bold</b>tail<!--note--></p>
        </div>
      </body></html>
    })
    expected = doc.to_html
    refs = capture(doc)
    ids = %w[wrapper first second bold].map { |id| doc.at_css("##{id}") }

    assert_raises(RuntimeError) do
      Sanitize.node!(doc, elements: %w[html body div p b em], transformers: lambda { |env|
        n = env[:node]

        case n.name
        when "p"
          n["class"] = "touched"
        when "b"
          n.name = "strong"
          n["data-user"] = "1"
          n.next_sibling.content = "changed"
        when "div"
          n.at_css("#first").unlink

          extra = n.document.create_element("em")
          extra.content = "new"
          n.add_child(extra)
        when "comment"
          n.content = "changed"
        when "body"
          raise "transformer failed"
        end
      })
    end

    assert_tree_unchanged(refs, expected, doc)

    ids.each_with_index do |node, index|
      _(doc.at_css("##{%w[wrapper first second bold][index]}")).must_equal node
    end

    _(doc.at_css("#bold")["data-user"]).must_be_nil
    _(doc.at_css("#bold").next_sibling.content).must_equal "tail"
    _(doc.at_css("div").element_children.map(&:name)).must_equal %w[p p]
  end

  it "should restore nodes that a transformer moved" do
    frag = Nokogiri::HTML5.fragment("<div><section><b>bold</b>tail</section><p>para</p></div>")
    expected = frag.to_html
    refs = capture(frag)
    section = frag.at_css("section")
    bold = frag.at_css("b")
    tail = bold.next_sibling

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div section b p], transformers: lambda { |env|
        n = env[:node]

        if n.name == "p"
          n.parent.add_child(section)
        end

        raise "transformer failed" if n.name == "b"
      })
    end

    assert_tree_unchanged(refs, expected, frag)
    _(frag.at_css("section")).must_equal section
    _(frag.at_css("b")).must_equal bold
    _(frag.at_css("section").children.last).must_equal tail
  end

  it "should remove nodes created during a failed attempt" do
    frag = Nokogiri::HTML5.fragment("<div><b>bold</b></div>")
    expected = frag.to_html
    div = frag.at_css("div")

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div b em], transformers: lambda { |env|
        n = env[:node]

        if n.name == "div"
          wrapper = n.document.create_element("span")
          n.add_child(wrapper)
          wrapper.add_child(n.document.create_element("em"))
        end

        raise "transformer failed" if n.name == "b"
      })
    end

    _(frag.to_html).must_equal expected

    div.children.each do |child|
      _(child.name).must_equal "b"
    end
  end

  it "should leave a detached root detached after a failure" do
    frag = Nokogiri::HTML5.fragment("<section id='target'><b>bold</b></section>")
    target = frag.at_css("#target")
    target.unlink
    expected = target.to_html
    refs = capture(target)

    assert_raises(RuntimeError) do
      Sanitize.node!(target, elements: %w[section strong], transformers: lambda { |env|
        if env[:node].name == "b"
          env[:node].name = "strong"
        end

        raise "transformer failed" if env[:node].name == "text"
      })
    end

    _(target.parent).must_be_nil
    assert_tree_unchanged(refs, expected, target)
  end

  it "should roll back a nested Sanitize.node! failure before the outer failure" do
    frag = Nokogiri::HTML5.fragment('<div><b id="inner">inner</b><span>span</span></div>')
    expected = frag.to_html
    inner = frag.at_css("#inner")

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div b span], transformers: lambda { |env|
        n = env[:node]

        if n.name == "b"
          assert_raises(RuntimeError) do
            Sanitize.node!(n, elements: %w[b], transformers: lambda { |_env|
              n["data-failed"] = "1"
              raise "inner failed"
            })
          end

          _(n["data-failed"]).must_be_nil
        end

        raise "outer failed" if n.name == "span"
      })
    end

    _(frag.to_html).must_equal expected
    _(frag.at_css("#inner")).must_equal inner
    _(inner["data-failed"]).must_be_nil
  end

  it "should start a retry with a fresh allowlist" do
    attempts = 0
    allowlist_states = []

    transformer = lambda do |env|
      if env[:node].name == "div"
        allowlist_states << env[:is_allowlisted]
        attempts += 1
        raise "transformer failed" if attempts == 1
      end

      {node_allowlist: [env[:node]]} if env[:node].name == "div"
    end

    frag = Nokogiri::HTML5.fragment('<div class="keep">text</div>')

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div], attributes: {"div" => %w[class]},
        transformers: transformer)
    end

    _(frag.to_html).must_equal '<div class="keep">text</div>'

    Sanitize.node!(frag, elements: %w[div], attributes: {"div" => %w[class]},
      transformers: transformer)

    _(allowlist_states).must_equal [false, false]
    _(frag.to_html).must_equal '<div class="keep">text</div>'
  end

  it "should restore attribute and namespace state" do
    doc = Nokogiri::HTML5.parse(
      '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">' \
      '<circle id="circle" cx="1"/><use id="use" xlink:href="#target"/></svg>'
    )
    expected = doc.to_html
    circle = doc.at_css("#circle")
    use = doc.at_css("#use")

    assert_raises(RuntimeError) do
      Sanitize.node!(doc, elements: %w[html body svg circle use], transformers: lambda { |env|
        n = env[:node]

        case n.name
        when "circle"
          n.name = "rect"
          n["cx"] = "99"
          n["data-extra"] = "1"
        when "use"
          n.attribute_nodes.each(&:unlink)
          n["xlink:href"] = "#evil"
        end

        raise "transformer failed" if n.name == "use"
      })
    end

    _(doc.to_html).must_equal expected
    _(circle.name).must_equal "circle"
    _(circle.namespace.href).must_equal "http://www.w3.org/2000/svg"
    _(use.attribute("href").namespace.href).must_equal "http://www.w3.org/1999/xlink"
    _(use.attribute("href").value).must_equal "#target"
  end

  it "should restore text and comment content" do
    frag = Nokogiri::HTML5.fragment("<div>text<!--comment--></div>")
    expected = frag.to_html
    text = frag.at_css("div").children[0]
    comment = frag.at_css("div").children[1]

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div], transformers: lambda { |env|
        n = env[:node]

        if n.text? || n.comment?
          n.content = "changed"
        end

        raise "transformer failed" if n.name == "div"
      })
    end

    _(frag.to_html).must_equal expected
    _(text.content).must_equal "text"
    _(comment.content).must_equal "comment"
  end

  it "should restore a doctype removed during a failed attempt" do
    doc = Nokogiri::HTML5.parse("<!DOCTYPE html><html><body><b>bold</b></body></html>")
    expected = doc.to_html

    assert_raises(RuntimeError) do
      Sanitize.node!(doc, elements: %w[html body b], transformers: lambda { |env|
        env[:node].document.internal_subset&.unlink
        raise "transformer failed" if env[:node].name == "b"
      })
    end

    _(doc.to_html).must_equal expected
    _(doc.internal_subset.name).must_equal "html"
  end

  it "should remove a doctype added during a failed attempt" do
    doc = Nokogiri::HTML5.parse("<html><body><b>bold</b></body></html>")
    expected = doc.to_html

    assert_raises(RuntimeError) do
      Sanitize.node!(doc, elements: %w[html body b], allow_doctype: true,
        transformers: lambda { |env|
          if env[:node].name == "body"
            env[:node].document.create_internal_subset("html", nil, nil)
          end

          raise "transformer failed" if env[:node].name == "b"
        })
    end

    _(doc.to_html).must_equal expected
    _(doc.internal_subset).must_be_nil
  end

  it "should restore text moved by a transformer to its original position" do
    frag = Nokogiri::HTML5.fragment("<div>first<b>bold</b>second</div>")
    expected = frag.to_html

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div b], transformers: lambda { |env|
        n = env[:node]

        if n.name == "b"
          n.parent.add_child(n.parent.children[0])
        end

        raise "transformer failed" if n.name == "b"
      })
    end

    _(frag.to_html).must_equal expected
    _(frag.at_css("div").children[0].content).must_equal "first"

    # A transformer that moved this text node merged it with its neighbor,
    # which Nokogiri doesn't allow to be undone while keeping both wrappers.
    # The content is restored, and the tree's text nodes are valid again.
    frag.at_css("div").children[0].content = "changed"
    _(frag.to_html).must_equal "<div>changed<b>bold</b>second</div>"
  end

  it "should not restore the parsed tree of a failed document sanitization" do
    transformer = lambda { |_env| raise "transformer failed" }

    assert_raises(RuntimeError) do
      Sanitize.document("<!DOCTYPE html><html><body><b>bold</b></body></html>",
        elements: %w[html body b], transformers: transformer)
    end

    assert_raises(RuntimeError) do
      Sanitize.fragment("<b>bold</b>", elements: %w[b], transformers: transformer)
    end
  end

  it "should restore the enclosing document when sanitizing an attached subtree" do
    doc = Nokogiri::HTML5.parse("<div><section><b>bold</b></section></div>")
    section = doc.at_css("section")
    expected = section.to_html
    expected_document = doc.to_html

    assert_raises(RuntimeError) do
      Sanitize.node!(section, elements: %w[section b], transformers: lambda { |env|
        n = env[:node]

        if n.name == "section"
          doc.at_css("div")["data-other"] = "1"
        end

        raise "transformer failed" if n.name == "b"
      })
    end

    _(section.to_html).must_equal expected
    _(doc.to_html).must_equal expected_document
    _(doc.at_css("div")["data-other"]).must_be_nil
  end

  it "should roll back attribute changes on a detached root" do
    doc = Nokogiri::HTML5.parse("<div><section id='target'><b>bold</b></section></div>")
    section = doc.at_css("#target")
    section.unlink
    expected = section.to_html

    assert_raises(RuntimeError) do
      Sanitize.node!(section, elements: %w[section strong], transformers: lambda { |env|
        n = env[:node]

        if n.name == "b"
          n.name = "strong"
          n["data-extra"] = "1"
        end

        raise "transformer failed" if n.name == "text"
      })
    end

    _(section.to_html).must_equal expected
    _(doc.to_html).must_equal "<html><head></head><body><div></div></body></html>"
  end

  it "should restore a document containing a comment before the doctype" do
    doc = Nokogiri::HTML5.parse("<!--lead--><!DOCTYPE html><html><body><b>bold</b></body></html>")
    expected = doc.to_html

    assert_raises(RuntimeError) do
      Sanitize.node!(doc, elements: %w[html body b], transformers: lambda { |env|
        if env[:node].name == "body"
          env[:node].document.internal_subset&.unlink
        end

        raise "transformer failed" if env[:node].name == "b"
      })
    end

    _(doc.to_html).must_equal expected
    _(doc.internal_subset.name).must_equal "html"
  end

  it "should restore a renamed foreign element and a removed doctype together" do
    doc = Nokogiri::HTML5.parse(
      '<!DOCTYPE html><html><body><svg xmlns="http://www.w3.org/2000/svg">' \
      '<circle id="circle" cx="1"/></svg></body></html>'
    )
    expected = doc.to_html
    circle = doc.at_css("#circle")

    assert_raises(RuntimeError) do
      Sanitize.node!(doc, elements: %w[html body svg circle], transformers: lambda { |env|
        n = env[:node]

        if n.name == "circle"
          n.name = "rect"
          n["cx"] = "9"
          n["data-extra"] = "1"
        end

        if n.name == "body"
          doc.internal_subset&.unlink
        end

        raise "transformer failed" if n.name == "rect"
      })
    end

    _(doc.to_html).must_equal expected
    _(doc.internal_subset.name).must_equal "html"
    _(circle.name).must_equal "circle"
    _(circle.namespace.href).must_equal "http://www.w3.org/2000/svg"
    _(circle["cx"]).must_equal "1"
    _(circle["data-extra"]).must_be_nil
  end

  it "should not leave text wrappers that alias a neighbor after a merge" do
    frag = Nokogiri::HTML5.fragment("<div>first<b>bold</b>second</div>")
    expected = frag.to_html
    first = frag.at_css("div").children[0]

    assert_raises(RuntimeError) do
      Sanitize.node!(frag, elements: %w[div b], transformers: lambda { |env|
        n = env[:node]

        if n.name == "b"
          n.parent.add_child(n.parent.children[0])
        end

        raise "transformer failed" if n.name == "b"
      })
    end

    _(frag.to_html).must_equal expected

    # `first` was merged into `second` by Nokogiri and then rebuilt during
    # rollback. Writing through the old wrapper must not affect the tree.
    first.content = "corrupted"
    _(frag.to_html).must_equal expected
  end
end
