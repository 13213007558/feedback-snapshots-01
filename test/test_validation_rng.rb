# frozen_string_literal: false

require "rexml/validation/relaxng"

module REXMLTests
  class RNGValidation < Test::Unit::TestCase
    include REXML

    def test_validate
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <element name="C">
      <attribute name="X"/>
      <zeroOrMore>
        <element name="E">
          <empty/>
        </element>
      </zeroOrMore>
    </element>
    <element name="D">
      <empty/>
    </element>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A><B><C X="x"><E/><E/></C><D/></B></A>} )
      error( validator, %q{<A><B><D/><C X="x"/></B></A>} )
    end


    def test_sequence
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <element name="C">
      <empty/>
    </element>
    <element name="D">
      <empty/>
    </element>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B><C/><C/><D/></B></A>} )
      error( validator, %q{<A><B><D/><C/></B></A>} )
      error( validator, %q{<A><C/><D/></A>} )
      no_error( validator, %q{<A><B><C/><D/></B></A>} )
    end


    def test_choice
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <choice>
      <element name="C">
        <empty/>
      </element>
      <element name="D">
        <empty/>
      </element>
    </choice>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B><C/><D/></B></A>} )
      no_error( validator, %q{<A><B><D/></B></A>} )
      no_error( validator, %q{<A><B><C/></B></A>} )
    end

    def test_optional
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <optional>
      <element name="C">
        <empty/>
      </element>
    </optional>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B><C/></B></A>} )
      error( validator, %q{<A><B><D/></B></A>} )
      error( validator, %q{<A><B><C/><C/></B></A>} )
    end

    def test_zero_or_more
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <zeroOrMore>
      <element name="C">
        <empty/>
      </element>
    </zeroOrMore>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )
      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B><C/></B></A>} )
      no_error( validator, %q{<A><B><C/><C/><C/></B></A>} )
      error( validator, %q{<A><B><D/></B></A>} )
      error( validator, %q{<A></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <zeroOrMore>
      <element name="C">
        <empty/>
      </element>
      <element name="D">
        <empty/>
      </element>
    </zeroOrMore>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B><C/><D/></B></A>} )
      no_error( validator, %q{<A><B><C/><D/><C/><D/></B></A>} )
      error( validator, %q{<A><B><D/></B></A>} )
    end

    def test_one_or_more
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <oneOrMore>
      <element name="C">
        <empty/>
      </element>
    </oneOrMore>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B><C/></B></A>} )
      no_error( validator, %q{<A><B><C/><C/><C/></B></A>} )
      error( validator, %q{<A><B><D/></B></A>} )
      error( validator, %q{<A></A>} )
    end

    def test_attribute
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <attribute name="X"/>
  <attribute name="Y"/>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A/>} )
      error( validator, %q{<A X=""/>} )
      no_error( validator, %q{<A X="1" Y="1"/>} )
    end

    def test_choice_attributes
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <choice>
    <attribute name="X"/>
    <attribute name="Y"/>
  </choice>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A X="1" Y="1"/>} )
      error( validator, %q{<A/>} )
      no_error( validator, %q{<A X="1"/>})
      no_error( validator, %q{<A Y="1"/>} )
    end

    def test_choice_attribute_element
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <choice>
    <attribute name="X"/>
    <element name="B"/>
  </choice>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A X="1"><B/></A>} )
      error( validator, %q{<A/>} )
      no_error( validator, %q{<A X="1"/>})
      no_error( validator, %q{<A><B/></A>} )
    end

    def test_empty
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <empty/>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A>Text</A>} )
      no_error( validator, %q{<A/>})
    end

    def test_text_val
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <text/>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A>Text</A>} )
      error( validator, %q{<A/>})
    end

    def test_choice_text
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <choice>
    <element name="B"/>
    <text/>
  </choice>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/>Text</A>} )
      error( validator, %q{<A>Text<B/></A>} )
      no_error( validator, %q{<A>Text</A>} )
      no_error( validator, %q{<A><B/></A>} )
    end

    def test_group
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <choice>
    <element name="B"/>
    <group>
      <element name="C"/>
      <element name="D"/>
    </group>
  </choice>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/><C/></A>} )
      error( validator, %q{<A><C/></A>} )
      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><C/><D/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B"/>
  <group>
    <element name="C"/>
    <element name="D"/>
  </group>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/><C/></A>} )
      error( validator, %q{<A><B/><D/></A>} )
      error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B/><C/><D/></A>} )
    end

    def test_value
      # Values as text nodes
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <value>VaLuE</value>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B>X</B></A>} )
      error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B>VaLuE</B></A>} )

      # Values as text nodes, via choice
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <choice>
      <value>Option 1</value>
      <value>Option 2</value>
    </choice>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><B>XYZ</B></A>} )
      no_error( validator, %q{<A><B>Option 1</B></A>} )
      no_error( validator, %q{<A><B>Option 2</B></A>} )

      # Attribute values
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <attribute name="B">
    <value>VaLuE</value>
  </attribute>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A/>} )
      error( validator, %q{<A B=""/>} )
      error( validator, %q{<A B="Lala"/>} )
      no_error( validator, %q{<A B="VaLuE"/>} )

      # Attribute values via choice
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <attribute name="B">
    <choice>
      <value>Option 1</value>
      <value>Option 2</value>
    </choice>
  </attribute>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A B=""/>} )
      error( validator, %q{<A B="Value"/>} )
      no_error( validator, %q{<A B="Option 1"></A>} )
      no_error( validator, %q{<A B="Option 2"/>} )
    end

    def test_interleave
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <interleave>
      <element name="C"/>
      <element name="D"/>
      <element name="E"/>
    </interleave>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B><C/></B></A>} )
      error( validator, %q{<A><B><C/><D/><C/></B></A>} )
      no_error( validator, %q{<A><B><C/><D/><E/></B></A>} )
      no_error( validator, %q{<A><B><E/><D/><C/></B></A>} )
      no_error( validator, %q{<A><B><D/><C/><E/></B></A>} )
      no_error( validator, %q{<A><B><E/><C/><D/></B></A>} )
      error( validator, %q{<A><B><E/><C/><D/><C/></B></A>} )
    end

    def test_mixed
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <element name="B">
    <mixed>
      <element name="D"/>
    </mixed>
  </element>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A><B>Text<D/></B></A>} )
      no_error( validator, %q{<A><B><D/>Text</B></A>} )
    end

    def test_ref_sequence
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <element name="B">
      <attribute name="X"/>
    </element>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A><B X=''/><B X=''/></A>} )
      error( validator, %q{<A><B X=''/></A>} )
    end

    def test_ref_choice
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <choice>
        <ref name="B"/>
      </choice>
    </element>
  </start>

  <define name="B">
    <element name="B"/>
    <element name="C"/>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><D/></A>} )
      error( validator, %q{<A><B/><C/></A>} )
      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><C/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <choice>
      <element name="B"/>
      <element name="C"/>
    </choice>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><D/></A>} )
      error( validator, %q{<A><B/><C/></A>} )
      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><C/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <choice>
        <ref name="B"/>
        <element name="D"/>
      </choice>
    </element>
  </start>

  <define name="B">
    <element name="B"/>
    <element name="C"/>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/><C/></A>} )
      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><C/></A>} )
      no_error( validator, %q{<A><D/></A>} )
    end


    def test_ref_zero_plus
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <zeroOrMore>
        <ref name="B"/>
      </zeroOrMore>
    </element>
  </start>

  <define name="B">
    <element name="B">
      <attribute name="X"/>
    </element>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A/>} )
      no_error( validator, %q{<A><B X=''/></A>} )
      no_error( validator, %q{<A><B X=''/><B X=''/><B X=''/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <zeroOrMore>
      <element name="B">
        <attribute name="X"/>
      </element>
    </zeroOrMore>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A/>} )
      no_error( validator, %q{<A><B X=''/></A>} )
      no_error( validator, %q{<A><B X=''/><B X=''/><B X=''/></A>} )
    end


    def test_ref_one_plus
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <oneOrMore>
        <ref name="B"/>
      </oneOrMore>
    </element>
  </start>

  <define name="B">
    <element name="B">
      <attribute name="X"/>
    </element>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A/>} )
      no_error( validator, %q{<A><B X=''/></A>} )
      no_error( validator, %q{<A><B X=''/><B X=''/><B X=''/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <oneOrMore>
      <element name="B">
        <attribute name="X"/>
      </element>
    </oneOrMore>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A/>} )
      no_error( validator, %q{<A><B X=''/></A>} )
      no_error( validator, %q{<A><B X=''/><B X=''/><B X=''/></A>} )
    end

    def test_ref_interleave
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <interleave>
        <ref name="B"/>
      </interleave>
    </element>
  </start>

  <define name="B">
    <element name="B"/>
    <element name="C"/>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><C/></A>} )
      error( validator, %q{<A><C/><C/></A>} )
      no_error( validator, %q{<A><B/><C/></A>} )
      no_error( validator, %q{<A><C/><B/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <interleave>
      <element name="B"/>
      <element name="C"/>
    </interleave>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><C/></A>} )
      error( validator, %q{<A><C/><C/></A>} )
      no_error( validator, %q{<A><B/><C/></A>} )
      no_error( validator, %q{<A><C/><B/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <interleave>
        <ref name="B"/>
        <ref name="C"/>
      </interleave>
    </element>
  </start>

  <define name="B">
    <element name="B"/>
  </define>
  <define name="C">
    <element name="C"/>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><C/></A>} )
      error( validator, %q{<A><C/><C/></A>} )
      no_error( validator, %q{<A><B/><C/></A>} )
      no_error( validator, %q{<A><C/><B/></A>} )
    end

    def test_ref_recurse
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <element name="B">
      <optional>
        <ref name="B"/>
      </optional>
    </element>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      error( validator, %q{<A></A>} )
      no_error( validator, %q{<A><B/></A>} )
      no_error( validator, %q{<A><B><B/></B></A>} )
    end

    def test_ref_optional
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <optional>
        <ref name="B"/>
      </optional>
    </element>
  </start>

  <define name="B">
    <element name="B">
    </element>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A></A>} )
      no_error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><B/><B/></A>} )
      error( validator, %q{<A><C/></A>} )

      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="B"/>
    </element>
  </start>

  <define name="B">
    <optional>
      <element name="B">
      </element>
    </optional>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng )

      no_error( validator, %q{<A></A>} )
      no_error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><B/><B/></A>} )
      error( validator, %q{<A><C/></A>} )
    end



    def test_strict_rejects_unsupported_data_constraint
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="SecurityConfig">
      <attribute name="mode">
        <data type="token" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">
          <param name="pattern">safe|audit</param>
        </data>
      </attribute>
      <attribute name="endpoint">
        <text/>
      </attribute>
      <empty/>
    </element>
  </start>
</grammar>
      XML

      # The permissive validator drops <data> and accepts a dangerous value.
      permissive = REXML::Validation::RelaxNG.new( rng )
      no_error( permissive,
                %q{<SecurityConfig mode="disabled" endpoint="http://evil.example/"/>} )

      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "data", error.construct )
      assert_match( /Unsupported RELAX NG construct <data>/, error.message )
      assert_not_nil( error.line )
      assert_not_nil( error.column )
      assert_match( %r{\A/grammar/start/element/attribute/data\z},
                    error.path )
    end

    def test_strict_rejects_not_allowed
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <group>
        <element name="B"><empty/></element>
        <notAllowed/>
      </group>
    </element>
  </start>
</grammar>
      XML
      permissive = REXML::Validation::RelaxNG.new( rng )
      no_error( permissive, %q{<A><B/></A>} )

      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "notAllowed", error.construct )
      assert_match( /notAllowed/, error.message )
      assert_match( %r{\A/grammar/start/element/group/notAllowed\z},
                    error.path )
    end

    def test_strict_rejects_undefined_reference
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="Missing"/>
    </element>
  </start>
</grammar>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "ref", error.construct )
      assert_match( /Undefined RELAX NG reference "Missing"/, error.message )
      assert_equal( "/grammar/start/element/ref", error.path )
      assert_equal( 5, error.line )
    end

    def test_strict_rejects_undefined_reference_in_define
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <ref name="Known"/>
    </element>
  </start>
  <define name="Known">
    <element name="B">
      <ref name="Missing"/>
    </element>
  </define>
</grammar>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "ref", error.construct )
      assert_equal( "/grammar/define/element/ref", error.path )
      assert_match( /Undefined RELAX NG reference/, error.message )
    end

    def test_strict_rejects_unnamespaced_construct
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <data xmlns="" type="token"/>
      <empty/>
    </element>
  </start>
</grammar>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "data", error.construct )
      assert_match( /not in the RELAX NG namespace/, error.message )
    end

    def test_strict_ignores_foreign_annotations_only
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0"
         xmlns:ann="urn:example:annotation">
  <ann:documentation>Only annotations may be foreign.</ann:documentation>
  <start>
    <element name="A">
      <ann:documentation>element docs</ann:documentation>
      <empty/>
    </element>
  </start>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng, strict: true )
      no_error( validator, %q{<A/>} )
      error( validator, %q{<A><B/></A>} )
    end

    def test_strict_rejects_nullable_choice_branch
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <choice>
        <optional>
          <element name="B"><empty/></element>
        </optional>
        <element name="C"><empty/></element>
      </choice>
    </element>
  </start>
</grammar>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_match( /choice/, error.message )
    end

    def test_strict_rejects_ambiguous_choice
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <choice>
        <element name="B"><empty/></element>
        <element name="B"><text/></element>
      </choice>
    </element>
  </start>
</grammar>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_match( /Ambiguous <choice>/, error.message )
    end

    def test_strict_rejects_non_productive_recursion
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <ref name="A"/>
  </start>
  <define name="A">
    <ref name="A"/>
  </define>
</grammar>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_match( /without consuming input/, error.message )
    end

    def test_strict_choice_interleave_ref
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="Config">
      <interleave>
        <ref name="Auth"/>
        <ref name="Logging"/>
      </interleave>
    </element>
  </start>
  <define name="Auth">
    <element name="Auth">
      <attribute name="mode">
        <choice>
          <value>safe</value>
          <value>audit</value>
        </choice>
      </attribute>
      <empty/>
    </element>
  </define>
  <define name="Logging">
    <element name="Logging">
      <attribute name="level">
        <choice>
          <value>info</value>
          <value>debug</value>
        </choice>
      </attribute>
      <empty/>
    </element>
  </define>
</grammar>
      XML
      no_error( REXML::Validation::RelaxNG.new( rng, strict: true ),
                %q{<Config><Auth mode="safe"/><Logging level="info"/></Config>} )
      no_error( REXML::Validation::RelaxNG.new( rng, strict: true ),
                %q{<Config><Logging level="debug"/><Auth mode="audit"/></Config>} )
      error( REXML::Validation::RelaxNG.new( rng, strict: true ),
             %q{<Config><Auth mode="disabled"/><Logging level="info"/></Config>} )
      error( REXML::Validation::RelaxNG.new( rng, strict: true ),
             %q{<Config><Logging level="info"/></Config>} )
    end

    def test_strict_nested_group_choice_ref
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<grammar xmlns="http://relaxng.org/ns/structure/1.0">
  <start>
    <element name="A">
      <group>
        <element name="B">
          <choice>
            <element name="X"><empty/></element>
            <element name="Y"><empty/></element>
          </choice>
        </element>
        <ref name="Tail"/>
      </group>
    </element>
  </start>
  <define name="Tail">
    <element name="C">
      <zeroOrMore>
        <element name="D"><empty/></element>
      </zeroOrMore>
    </element>
  </define>
</grammar>
      XML
      validator = REXML::Validation::RelaxNG.new( rng, strict: true )

      no_error( validator, %q{<A><B><X/></B><C/></A>} )
      no_error( validator, %q{<A><B><Y/></B><C><D/><D/></C></A>} )
      error( validator, %q{<A><B/></B></A>} )
      error( validator, %q{<A><C/><B><X/></B></A>} )
      error( validator, %q{<A><B><X/></B><C><E/></C></A>} )
    end

    def test_strict_is_opt_in
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <data type="token"/>
</element>
      XML
      # Default behaviour is unchanged.
      permissive = REXML::Validation::RelaxNG.new( rng )
      assert_false( permissive.strict? )
      # Explicit permissive mode is also unchanged.
      assert_nothing_raised do
        REXML::Validation::RelaxNG.new( rng, strict: false )
      end
      assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
    end

    def test_strict_repetition_sequence
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <zeroOrMore>
    <element name="B"><empty/></element>
    <element name="C"><empty/></element>
  </zeroOrMore>
</element>
      XML
      validator = REXML::Validation::RelaxNG.new( rng, strict: true )
      assert_true( validator.strict? )

      no_error( validator, %q{<A/>} )
      no_error( validator, %q{<A><B/><C/><B/><C/></A>} )
      error( validator, %q{<A><B/></A>} )
      error( validator, %q{<A><B/><B/><C/></A>} )
    end

    def test_strict_rejects_empty_value
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <value/>
</element>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "value", error.construct )
      assert_match( /empty <value>/, error.message )
    end

    def test_strict_rejects_narrowed_value
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">
  <value type="xsd:integer">1</value>
</element>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_equal( "value", error.construct )
      assert_match( /<value> type="xsd:integer"/, error.message )
    end

    def test_strict_rejects_namespace_prefixed_name
      rng = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<element name="p:A" xmlns="http://relaxng.org/ns/structure/1.0">
  <empty/>
</element>
      XML
      error = assert_raise( REXML::Validation::RelaxNG::CompileError ) do
        REXML::Validation::RelaxNG.new( rng, strict: true )
      end
      assert_match( /namespace prefix/, error.message )
    end

    def error( validator, source )
      parser = REXML::Parsers::TreeParser.new( source )
      parser.add_listener( validator.reset )
      assert_raise( REXML::Validation::ValidationException,
                    "Expected a validation error" ) { parser.parse }
    end

    def no_error( validator, source )
      parser = REXML::Parsers::TreeParser.new( source )
      parser.add_listener( validator.reset )
      assert_nothing_raised { parser.parse }
    end
  end
end
