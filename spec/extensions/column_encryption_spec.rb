# frozen_string_literal: true
require_relative "spec_helper"

describe "column_encryption plugin" do
  def have_matching_search(ds, obj)
    ds.sql.gsub("\\_", "_").include?("'#{obj[:enc][0, 48]}%'")
  end

  before do
    @db = Sequel.mock(:numrows=>1)
    @model = Class.new(Sequel::Model)
    @model.set_dataset @db[:ce_test]
    @model.columns :id, :not_enc, :enc
    @model.plugin :column_encryption do |enc|
      enc.key 0, "0"*32

      enc.column :enc
    end
    @obj = @model.new(:not_enc=>'123', :enc=>'Abc')
    @obj.valid?
    @db.fetch = {:id=>1, :not_enc=>'123', :enc=>@obj[:enc]}
    @obj.save
    @db.sqls
  end

  it "should store columns encrypted" do
    @obj.not_enc.must_equal '123'
    @obj[:not_enc].must_equal '123'
    @obj.enc.must_equal 'Abc'
    @obj[:enc].start_with?('AAAA').must_equal true
  end

  it "should support searching encrypted columns" do
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true
    end
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal false
    @obj.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal false
  end

  it "should support case insensitive searching encrypted columns" do
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>:case_insensitive
    end
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal false
    @obj.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'Abd'), @obj).must_equal false
  end

  it "should support searching columns encrypted with previous keys" do
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true
    end
    @obj.reencrypt
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true do |cenc|
        cenc.key 1, "1"*32
        cenc.key 0, "0"*32
      end
    end
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal false
    @obj[:enc].start_with?('AQAA').must_equal true

    @obj.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal false
    @obj.enc.must_equal 'Abc'
    @obj[:enc].start_with?('AQAB').must_equal true
  end

  it "should support case insensitive searching columns encrypted with previous keys" do
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>:case_insensitive
    end
    @obj.reencrypt
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>:case_insensitive do |cenc|
        cenc.key 1, "1"*32
        cenc.key 0, "0"*32
      end
    end
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal true
    @obj[:enc].start_with?('AgAA').must_equal true

    @obj.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal true
    @obj.enc.must_equal 'Abc'
    @obj[:enc].start_with?('AgAB').must_equal true

    have_matching_search(@model.with_encrypted_value(:enc, 'Abd'), @obj).must_equal false
  end

  it "should support searching columns encrypted with previous keys and different case sensitivity setting" do
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true
    end
    @obj.reencrypt
    obj2 = @model.new(:not_enc=>'234', :enc=>'Def')
    obj2.valid?
    def obj2.save(*) end

    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.key 0, "0"*32

      enc.column :enc, :searchable=>:case_insensitive
    end
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal false
    have_matching_search(@model.with_encrypted_value(:enc, 'Def'), obj2).must_equal false

    @model.plugin :column_encryption do |enc|
      enc.key 2, "2"*32
      enc.key 1, "1"*32
      enc.key 0, "0"*32

      enc.column :enc, :searchable=>:case_insensitive, :search_both=>true
    end
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal false
    have_matching_search(@model.with_encrypted_value(:enc, 'Def'), obj2).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'def'), obj2).must_equal false

    @obj.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal true
    @obj[:enc].start_with?('AgAC').must_equal true

    have_matching_search(@model.with_encrypted_value(:enc, 'Def'), obj2).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'def'), obj2).must_equal false
    obj2.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Def'), obj2).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'def'), obj2).must_equal true
    obj2[:enc].start_with?('AgAC').must_equal true

    @model.plugin :column_encryption do |enc|
      enc.key 3, "3"*32
      enc.key 2, "2"*32
      enc.key 1, "1"*32
      enc.key 0, "0"*32

      enc.column :enc, :searchable=>true, :search_both=>true
    end

    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal true

    @obj.reencrypt
    have_matching_search(@model.with_encrypted_value(:enc, 'Abc'), @obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'abc'), @obj).must_equal false
    @obj[:enc].start_with?('AQAD').must_equal true

    have_matching_search(@model.with_encrypted_value(:enc, 'Abd'), @obj).must_equal false
  end

  it "should keep existing column encryption keys when reloading the plugin without keys" do
    @model.plugin(:column_encryption) do |enc|
      enc.column :enc
    end
    @obj.deserialized_values.clear
    @obj.enc.must_equal "Abc"
  end

  it "should clear existing column encryption keys when reloading the plugin with keys" do
    @model.plugin(:column_encryption) do |enc|
      enc.key 1, "1"*32
      enc.column :enc
    end
    @obj.deserialized_values.clear
    proc{@obj.enc}.must_raise Sequel::Error
  end

  it "should not affect existing column encryption keys when reloading the plugin with keys" do
    @model.plugin(:column_encryption) do |enc|
      enc.key 1, "1"*32
      enc.column :not_enc
    end
    @obj.deserialized_values.clear
    @obj.enc.must_equal "Abc"
  end

  it "should raise an error when trying to decrypt with missing key" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.column :enc, :searchable=>true
    end
    obj = @model.first
    proc{obj.enc}.must_raise Sequel::Error
  end

  it "should raise an error when trying to decrypt without any keys set" do
    @model = Class.new(Sequel::Model)
    @model.set_dataset @db[:ce_test]
    @model.columns :id, :not_enc, :enc
    proc do
      @model.plugin :column_encryption do |enc|
        enc.column :enc
      end
    end.must_raise Sequel::Error
  end

  it "should raise an error when trying to decrypt with invalid key" do
    @model.plugin :column_encryption do |enc|
      enc.key 0, "1"*32
      enc.column :enc, :searchable=>true
    end
    obj = @model.first
    proc{obj.enc}.must_raise 
  end

  it "should raise an error when trying to decrypt with invalid auth data" do
    @model.plugin :column_encryption do |enc|
      enc.key 0, "0"*32, :auth_data=>'Foo'
      enc.column :enc, :searchable=>true
    end
    obj = @model.first
    proc{obj.enc}.must_raise Sequel::Error
    obj = @model.new(:enc=>"Abc")

    obj.valid?
    obj.deserialized_values.clear
    obj.enc.must_equal "Abc"
  end

  it "should support a configurable amount of padding" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "0"*32, :padding=>110
      enc.key 0, "0"*32
      enc.column :enc
    end
    encrypt_len = @obj[:enc].bytesize
    @obj.reencrypt
    @obj[:enc].bytesize.must_be(:>, encrypt_len + 100)
  end

  it "should support not using padding" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "0"*32, :padding=>false
      enc.key 0, "0"*32
      enc.column :enc
    end
    encrypt_len = @obj[:enc].bytesize
    @obj.reencrypt
    @obj[:enc].bytesize.must_be(:<, encrypt_len)
  end

  it "should support reencrypting rows that need reencryption" do
    obj = @model.new(:not_enc=>'234', :enc=>'Def')
    obj.valid?
    def obj.save(*); end

    need_reencrypt = lambda do
      sql = @model.needing_reencryption.sql
      [@obj, obj].count{|o| !(sql.include?("< '#{o[:enc][0, 4]}'") && sql.include?("> '#{o[:enc][0, 4]}B'")) }
    end

    need_reencrypt.call.must_equal 0

    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.key 0, "0"*32
      enc.column :enc
    end

    need_reencrypt.call.must_equal 2
    @obj.reencrypt
    need_reencrypt.call.must_equal 1
    obj.reencrypt
    need_reencrypt.call.must_equal 0

    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.column :enc
    end

    need_reencrypt.call.must_equal 0

    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true
    end

    need_reencrypt.call.must_equal 2
    @obj.reencrypt
    need_reencrypt.call.must_equal 1
    obj.reencrypt
    need_reencrypt.call.must_equal 0

    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>:case_insensitive
    end

    need_reencrypt.call.must_equal 2
    @obj.reencrypt
    need_reencrypt.call.must_equal 1
    obj.reencrypt
    need_reencrypt.call.must_equal 0
  end

  it "should not support searching encrypted columns not marked searchable" do
    proc{@model.with_encrypted_value(:enc, 'Abc')}.must_raise Sequel::Error
  end

  it "should not allow column encryption configuration with empty keys" do
    proc do 
      @model.plugin :column_encryption do |enc|
        enc.column(:enc){}
      end
    end.must_raise Sequel::Error
  end

  it "should not allow column encryption configuration with invalid :searchable option" do
    proc do 
      @model.plugin :column_encryption do |enc|
        enc.column(:enc, :searchable=>Object.new)
      end
    end.must_raise Sequel::Error
  end

  it "should require key ids are integers between 0 and 255" do
    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key Object.new, "1"*32
      end
    end.must_raise Sequel::Error

    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key(-1, "1"*32)
      end
    end.must_raise Sequel::Error

    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 256, "1"*32
      end
    end.must_raise Sequel::Error
  end

  it "should require keys are strings with 32 bytes" do
    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 0, Object.new
      end
    end.must_raise Sequel::Error

    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 0, "1"*31
      end
    end.must_raise Sequel::Error

    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 0, "1"*33
      end
    end.must_raise Sequel::Error
  end

  it "should require padding is integer between 1 and 120" do
    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 1, "1"*32, :padding=>Object.new
      end
    end.must_raise Sequel::Error

    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 1, "1"*32, :padding=>0
      end
    end.must_raise Sequel::Error

    proc do 
      @model.plugin :column_encryption do |enc|
        enc.key 1, "1"*32, :padding=>121
      end
    end.must_raise Sequel::Error
  end

  it "should handle empty data" do
    @obj.enc = ''
    @obj.valid?
    @obj.enc.must_equal ''
    @obj[:enc].start_with?('AAAA').must_equal true
  end

  it "should check for errors during decryption" do
    @obj.deserialized_values.clear
    enc = @obj[:enc].dup

    @obj[:enc] = enc.dup.tap{|x| x[0] = '%'}
    proc{@obj.enc}.must_raise Sequel::Error # invalid base-64

    @obj[:enc] = enc.dup.tap{|x| x[0,4] = "BAAA"} # "\4\0\0" base64
    proc{@obj.enc}.must_raise Sequel::Error # invalid flags

    @obj[:enc] = enc.dup.tap{|x| x[0,4] = "AAEA"} # "\0\1\0" base64
    proc{@obj.enc}.must_raise Sequel::Error # invalid reserved byte

    @obj[:enc] = enc.dup.tap{|x| x[0,4] = "AAAB"} # "\0\0\1" base64
    proc{@obj.enc}.must_raise Sequel::Error # invalid key id

    @obj[:enc] = enc.dup.tap{|x| x[0,4] = "AQAA"} # "\1\0\0" base64
    proc{@obj.enc}.must_raise Sequel::Error # invalid minimum size for searchable

    @obj[:enc] = enc.dup.tap{|x| x.slice!(60, 1000)}
    proc{@obj.enc}.must_raise Sequel::Error # invalid minimum size for nonsearchable

    @obj[:enc] = enc.dup.tap{|x| x[63..-3] = x[63..-3].reverse}
    proc{@obj.enc}.must_raise Sequel::Error # corrupt encrypted data
  end

  it "should work in subclasses" do
    sc = Class.new(@model)
    obj = sc.first
    obj.not_enc.must_equal '123'
    obj[:not_enc].must_equal '123'
    obj.enc.must_equal 'Abc'
    obj[:enc].start_with?('AAAA').must_equal true

    sc.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.column :not_enc
    end

    obj = sc.new
    obj.not_enc = "123"
    obj.not_enc.must_equal '123'
    obj.valid?
    obj[:not_enc].start_with?('AAAB').must_equal true

    obj = @model.first
    obj.not_enc.must_equal '123'
    obj[:not_enc].must_equal '123'
  end

  it "#reencrypt should save only if it modified a column" do
    @obj.reencrypt.must_be_nil

    @model.plugin :column_encryption do |enc|
      enc.column :not_enc
    end

    obj = @model.new(:not_enc=>'123', :enc=>'Abc')
    obj.valid?
    def obj.save(*) self; end
    obj.reencrypt.must_be_nil

    @model.plugin :column_encryption do |enc|
      enc.column :not_enc do |cenc|
        cenc.key 2, "2"*32
        cenc.key 0, "0"*32
      end
    end

    obj.reencrypt.must_be_same_as obj
    obj[:not_enc].start_with?('AAAC').must_equal true
    obj[:enc].start_with?('AAAA').must_equal true

    @model.plugin :column_encryption do |enc|
      enc.column :enc do |cenc|
        cenc.key 1, "1"*32
        cenc.key 0, "0"*32
      end
    end

    obj.reencrypt.must_be_same_as obj
    obj[:not_enc].start_with?('AAAC').must_equal true
    obj[:enc].start_with?('AAAB').must_equal true

    @model.plugin :column_encryption do |enc|
      enc.key 3, "3"*32
      enc.key 2, "2"*32
      enc.key 1, "1"*32
      enc.key 0, "0"*32

      enc.column :not_enc
      enc.column :enc
    end

    obj.reencrypt.must_be_same_as obj
    obj[:not_enc].start_with?('AAAD').must_equal true
    obj[:enc].start_with?('AAAD').must_equal true

    obj[:enc] = nil
    obj.reencrypt.must_be_nil
  end

  it "should support encrypted columns with a registered serialization format" do
    require 'json'
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true, :format=>:json
    end

    obj = @model.new(:not_enc=>'123', :enc=>{'a'=>1})
    obj.id = 1
    obj.valid?
    @db.fetch = obj.values
    @model[obj.id].enc['a'].must_equal 1
    obj[:enc].start_with?('AQAA').must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>1), obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>2), obj).must_equal false

    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true, :format=>:json do |cenc|
        cenc.key 1, "1"*32
        cenc.key 0, "0"*32
      end
    end

    @model[obj.id].enc['a'].must_equal 1
    obj[:enc].start_with?('AQAA').must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>1), obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>2), obj).must_equal false

    db = @db
    obj.define_singleton_method(:save) do |*|
      valid?
      db.fetch = values
    end
    obj.reencrypt
    @model[obj.id].enc['a'].must_equal 1
    obj[:enc].start_with?('AQAB').must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>1), obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>2), obj).must_equal false
  end

  it "should support encrypted columns with a custom serialization format" do
    require 'json'
    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true, :format=>[:to_json.to_proc, JSON.method(:parse)]
    end

    obj = @model.new(:not_enc=>'123', :enc=>{'a'=>1})
    obj.id = 1
    obj.valid?
    @db.fetch = obj.values
    @model[obj.id].enc['a'].must_equal 1
    obj[:enc].start_with?('AQAA').must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>1), obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>2), obj).must_equal false

    @model.plugin :column_encryption do |enc|
      enc.column :enc, :searchable=>true, :format=>[:to_json.to_proc, JSON.method(:parse)] do |cenc|
        cenc.key 1, "1"*32
        cenc.key 0, "0"*32
      end
    end

    @model[obj.id].enc['a'].must_equal 1
    obj[:enc].start_with?('AQAA').must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>1), obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>2), obj).must_equal false

    db = @db
    obj.define_singleton_method(:save) do |*|
      valid?
      db.fetch = values
    end
    obj.reencrypt
    @model[obj.id].enc['a'].must_equal 1
    obj[:enc].start_with?('AQAB').must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>1), obj).must_equal true
    have_matching_search(@model.with_encrypted_value(:enc, 'a'=>2), obj).must_equal false
  end

  it "should raise an error if trying to use an unregistered serialization format" do
    proc do
      @model.plugin :column_encryption do |enc|
        enc.column :enc, :searchable=>true, :format=>:test_ce
      end
    end.must_raise Sequel::Error
  end

  it "should require a single column primary key for rotate_encryption" do
    @model.set_primary_key nil
    proc{@model.rotate_encryption}.must_raise Sequel::Error

    @model.set_primary_key [:id, :not_enc]
    proc{@model.rotate_encryption}.must_raise Sequel::Error
  end

  it "should validate rotate_encryption options" do
    proc{@model.rotate_encryption(:batch_size=>0)}.must_raise Sequel::Error
    proc{@model.rotate_encryption(:batch_size=>'1')}.must_raise Sequel::Error
    proc{@model.rotate_encryption(:max_batches=>-1)}.must_raise Sequel::Error
    proc{@model.rotate_encryption(:checkpoint=>Object.new)}.must_raise Sequel::Error
    proc{@model.rotate_encryption(:on_error=>Object.new)}.must_raise Sequel::Error
    proc{@model.rotate_encryption(:on_conflict=>Object.new)}.must_raise Sequel::Error
  end

  it "should rotate encrypted columns in batches using conditional updates" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.key 0, "0"*32
      enc.column :enc
    end

    old_value = @obj[:enc]
    @db.sqls
    @db.fetch = [{:id=>1, :enc=>old_value}]
    @db.numrows = 1

    result = @model.rotate_encryption(:batch_size=>10)
    sqls = @db.sqls

    result.processed.must_equal 1
    result.rotated.must_equal 1
    result.skipped.must_equal 0
    result.batches.must_equal 1
    result.last_pk.must_equal 1
    result.errors.must_equal []
    result.conflicts.must_equal []

    select_sql, update_sql = sqls
    select_sql.must_include "SELECT id, enc FROM ce_test"
    update_sql.must_include "UPDATE ce_test SET enc = '"
    update_sql.must_include "WHERE ((id = 1) AND (enc = '#{old_value}'))"
    update_sql.wont_include "not_enc"
  end

  it "should record rows that cannot be rotated and continue with later rows" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.key 0, "0"*32
      enc.column :enc
    end

    @db.sqls
    @db.fetch = [{:id=>1, :enc=>"AAAAcorrupt"}, {:id=>2, :enc=>@obj[:enc]}]
    @db.numrows = 1

    result = @model.rotate_encryption(:batch_size=>10)
    result.processed.must_equal 2
    result.rotated.must_equal 1
    result.errors.length.must_equal 1
    result.errors.first.primary_key.must_equal 1
    result.errors.first.columns.must_equal [:enc]
    result.errors.first.exception.must_be_kind_of Sequel::Error
    result.last_pk.must_equal 2

    @db.fetch = [{:id=>1, :enc=>"AAAAcorrupt"}]
    result = @model.rotate_encryption
    result.errors.length.must_equal 1
    result.rotated.must_equal 0
    result.skipped.must_equal 0

    @db.fetch = [{:id=>1, :enc=>"AAAAcorrupt"}]
    proc{@model.rotate_encryption(:raise_on_error=>true)}.must_raise Sequel::Error

    errors = []
    @db.fetch = [{:id=>1, :enc=>"AAAAcorrupt"}]
    result = @model.rotate_encryption(:on_error=>errors.method(:push))
    errors.length.must_equal 1
    errors.first.must_be_same_as result.errors.first
    errors.first.primary_key.must_equal 1
  end

  it "should call the checkpoint after each batch" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.key 0, "0"*32
      enc.column :enc
    end

    @db.fetch = [
      [{:id=>1, :enc=>@obj[:enc]}, {:id=>2, :enc=>@obj[:enc]}],
      [{:id=>3, :enc=>@obj[:enc]}],
    ]
    @db.numrows = 1

    checkpoints = []
    result = @model.rotate_encryption(:batch_size=>2, :checkpoint=>checkpoints.method(:<<))
    checkpoints.must_equal [2, 3]
    result.batches.must_equal 2
    result.last_pk.must_equal 3
  end

  it "should allow resuming from a checkpoint" do
    @model.plugin :column_encryption do |enc|
      enc.key 1, "1"*32
      enc.key 0, "0"*32
      enc.column :enc
    end

    @db.sqls
    @db.fetch = []
    result = @model.rotate_encryption(:after=>5)
    result.last_pk.must_equal 5
    @db.sqls.first.must_include "id > 5"
  end

  begin
    require 'sqlite3'
  rescue LoadError
    warn "Skipping SQLite tests of column_encryption rotation: can't load sqlite3"
  else
    describe "with SQLite" do
      before do
        @db = Sequel.sqlite
        @db.create_table(:ce_rotation_test) do
          primary_key :id
          String :name
          String :enc
        end
        @model = Class.new(Sequel::Model(@db[:ce_rotation_test]))
        @model.plugin :column_encryption do |enc|
          enc.key 0, "0"*32
          enc.column :enc
        end
      end

      def create_rows(count)
        count.times do |i|
          @model.create(:name=>"row#{i + 1}", :enc=>"value#{i + 1}")
        end
      end

      def rotate_to_new_key
        @model.plugin :column_encryption do |enc|
          enc.key 1, "1"*32
          enc.key 0, "0"*32
          enc.column :enc
        end
      end

      def values
        @model.order(:id).all.map{|obj| [obj.id, obj.name, obj.enc]}
      end

      it "should rotate all rows in batches and keep rows readable during the transition" do
        create_rows 5
        rotate_to_new_key
        expected = values

        result = @model.rotate_encryption(:batch_size=>2, :max_batches=>1)
        result.processed.must_equal 2
        result.rotated.must_equal 2
        result.last_pk.must_equal 2
        @model.needing_reencryption.count.must_equal 3

        # Rows rotated with the new key and rows still encrypted with the old key
        # are both readable during the transition.
        values.must_equal expected

        result = @model.rotate_encryption(:batch_size=>2, :after=>result.last_pk, :max_batches=>1)
        result.processed.must_equal 2
        result.last_pk.must_equal 4

        result = @model.rotate_encryption(:batch_size=>2, :after=>result.last_pk)
        result.processed.must_equal 1
        result.batches.must_equal 1
        result.last_pk.must_equal 5

        @model.needing_reencryption.count.must_equal 0
        values.must_equal expected

        # Running the rotation again does nothing.
        result = @model.rotate_encryption
        result.processed.must_equal 0
        result.rotated.must_equal 0
        result.batches.must_equal 0
        values.must_equal expected
      end

      it "should resume from the last checkpoint after exiting in the middle of a run" do
        create_rows 25
        rotate_to_new_key
        expected = values

        checkpoints = []
        # Exit after two batches have been committed, before the checkpoint for
        # the second batch is recorded.
        result = @model.rotate_encryption(
          :batch_size=>10,
          :checkpoint=>lambda{|pk| checkpoints << pk; raise "exit" if checkpoints.length == 2}
        ) rescue $!
        result.must_be_kind_of RuntimeError
        checkpoints.must_equal [10, 20]
        @model.needing_reencryption.count.must_equal 5

        # Resume from the last confirmed position.  Rows rotated after that
        # position are skipped, and only the remaining rows are processed.
        result = @model.rotate_encryption(:batch_size=>10, :after=>checkpoints.last)
        result.processed.must_equal 5
        result.rotated.must_equal 5
        result.last_pk.must_equal 25

        @model.needing_reencryption.count.must_equal 0
        values.must_equal expected
      end

      it "should resume after exiting in the middle of a batch" do
        create_rows 25
        rotate_to_new_key
        expected = values
        db = @db

        # Simulate the process exiting after updating 15 rows, in the middle of
        # the second batch.  No checkpoint is recorded for the partial batch.
        update_count = 0
        test = self
        hook = Module.new do
          define_method(:update) do |*args|
            update_count += 1
            test.assert(false, "expected process exit") if update_count == 15
            super(*args)
          end
        end
        @model.dataset = @model.dataset.with_extend(hook)

        e = assert_raises(Minitest::Assertion) do
          @model.rotate_encryption(:batch_size=>10, :checkpoint=>proc{})
        end
        e.message.must_include "expected process exit"

        @model.set_dataset(db[:ce_rotation_test])
        @model.needing_reencryption.count.must_equal 11
        values.must_equal expected

        # Rows rotated before the exit are skipped, and all remaining rows are
        # rotated.
        result = @model.rotate_encryption(:batch_size=>10)
        result.rotated.must_equal 11
        result.batches.must_equal 2
        @model.needing_reencryption.count.must_equal 0
        values.must_equal expected
      end

      it "should record rows with errors separately and continue processing the batch" do
        create_rows 5
        expected = values
        rotate_to_new_key
        @db[:ce_rotation_test].where(:id=>3).update(:enc=>"AAAAcorrupt")

        result = @model.rotate_encryption(:batch_size=>10)
        result.processed.must_equal 5
        result.rotated.must_equal 4
        result.errors.length.must_equal 1
        result.errors.first.primary_key.must_equal 3
        result.errors.first.columns.must_equal [:enc]
        result.errors.first.exception.must_be_kind_of Sequel::Error
        result.last_pk.must_equal 5

        @model.needing_reencryption.select_map(:id).must_equal [3]

        # Repeating the run retries the error row and skips the completed rows.
        result = @model.rotate_encryption(:batch_size=>10)
        result.processed.must_equal 1
        result.rotated.must_equal 0
        result.skipped.must_equal 0
        result.errors.length.must_equal 1
        result.errors.first.primary_key.must_equal 3

        # Fixing the row allows a later run to see it no longer needs rotation.
        @db[:ce_rotation_test].where(:id=>3).update(:enc=>@model.send(:column_encryption_metadata)[:enc].encryptor.call("value3"))
        result = @model.rotate_encryption
        result.processed.must_equal 0
        result.rotated.must_equal 0
        @model.needing_reencryption.count.must_equal 0
        values.must_equal expected
      end

      it "should not overwrite encrypted columns changed concurrently by the application" do
        create_rows 3
        rotate_to_new_key
        metadata = @model.send(:column_encryption_metadata)
        db = @db

        # Simulate the application updating the encrypted column after the
        # rotation fetched the row, but before the rotation updates it.
        state = {:updated=>false}
        hook = Module.new do
          define_method(:update) do |*args|
            unless state[:updated]
              state[:updated] = true
              db[:ce_rotation_test].where(:id=>1).update(
                :name=>"business name",
                :enc=>metadata[:enc].encryptor.call("business value")
              )
            end
            super(*args)
          end
        end
        @model.dataset = @model.dataset.with_extend(hook)

        result = @model.rotate_encryption(:batch_size=>10)
        result.processed.must_equal 3
        result.rotated.must_equal 2
        result.skipped.must_equal 1
        result.errors.must_equal []
        result.conflicts.must_equal []

        obj = @model[1]
        obj.name.must_equal "business name"
        obj.enc.must_equal "business value"
        @model[2].enc.must_equal "value2"
        @model[3].enc.must_equal "value3"
        @model.needing_reencryption.count.must_equal 0
      end

      it "should preserve non-encrypted columns changed concurrently by the application" do
        create_rows 2
        rotate_to_new_key
        db = @db

        # Simulate the application changing a non-encrypted column after the
        # rotation fetched the row.
        state = {:updated=>false}
        hook = Module.new do
          define_method(:update) do |*args|
            unless state[:updated]
              state[:updated] = true
              db[:ce_rotation_test].where(:id=>1).update(:name=>"renamed")
            end
            super(*args)
          end
        end
        @model.dataset = @model.dataset.with_extend(hook)

        result = @model.rotate_encryption(:batch_size=>10)
        result.rotated.must_equal 2
        result.conflicts.must_equal []

        obj = @model[1]
        obj.name.must_equal "renamed"
        obj.enc.must_equal "value1"
        @model.needing_reencryption.count.must_equal 0
      end

      it "should record a conflict if the application rewrites the row with an old key" do
        create_rows 3
        old_encryptor = @model.send(:column_encryption_metadata)[:enc].encryptor
        rotate_to_new_key
        db = @db

        state = {:updated=>false}
        hook = Module.new do
          define_method(:update) do |*args|
            unless state[:updated]
              state[:updated] = true
              db[:ce_rotation_test].where(:id=>1).update(
                :name=>"business name",
                :enc=>old_encryptor.call("business value")
              )
            end
            super(*args)
          end
        end
        @model.dataset = @model.dataset.with_extend(hook)

        result = @model.rotate_encryption(:batch_size=>10)
        result.processed.must_equal 3
        result.rotated.must_equal 2
        result.conflicts.length.must_equal 1
        result.conflicts.first.primary_key.must_equal 1
        result.conflicts.first.columns.must_equal [:enc]
        result.errors.must_equal []

        # The concurrently written value is still readable.
        @model[1].enc.must_equal "business value"
        @model[1].name.must_equal "business name"

        # A later run rotates the conflicting row.
        @model.set_dataset(@db[:ce_rotation_test])
        result = @model.rotate_encryption
        result.rotated.must_equal 1
        result.conflicts.must_equal []
        @model.needing_reencryption.count.must_equal 0
        @model[1].enc.must_equal "business value"
        @model[1].name.must_equal "business name"
      end

      it "should skip rows deleted concurrently by the application" do
        create_rows 3
        rotate_to_new_key
        db = @db

        state = {:updated=>false}
        hook = Module.new do
          define_method(:update) do |*args|
            unless state[:updated]
              state[:updated] = true
              db[:ce_rotation_test].where(:id=>1).delete
            end
            super(*args)
          end
        end
        @model.dataset = @model.dataset.with_extend(hook)

        result = @model.rotate_encryption(:batch_size=>10)
        result.processed.must_equal 3
        result.rotated.must_equal 2
        result.skipped.must_equal 1
        result.errors.must_equal []
        result.conflicts.must_equal []
        @model.select_order_map(:id).must_equal [2, 3]
      end

      it "should only update encrypted columns that need rotation" do
        @db.drop_table(:ce_rotation_test)
        @db.create_table(:ce_rotation_test) do
          primary_key :id
          String :name
          String :enc
          String :enc2
        end
        @model = Class.new(Sequel::Model(@db[:ce_rotation_test]))
        @model.plugin :column_encryption do |enc|
          enc.key 0, "0"*32
          enc.column :enc
          enc.column :enc2 do |cenc|
            cenc.key 0, "0"*32
          end
        end
        3.times do |i|
          @model.create(:name=>"row#{i + 1}", :enc=>"value#{i + 1}", :enc2=>"second#{i + 1}")
        end

        @model.plugin :column_encryption do |enc|
          enc.key 1, "1"*32
          enc.key 0, "0"*32
          enc.column :enc
          enc.column :enc2 do |cenc|
            cenc.key 2, "2"*32
            cenc.key 0, "0"*32
          end
        end

        expected = @model.order(:id).all.map{|obj| [obj.id, obj.name, obj.enc, obj.enc2]}
        result = @model.rotate_encryption(:batch_size=>10)
        result.rotated.must_equal 3

        @model.needing_reencryption.count.must_equal 0
        @model.order(:id).all.map{|obj| [obj.id, obj.name, obj.enc, obj.enc2]}.must_equal expected
      end

      it "should rotate searchable columns and allow searching during the transition" do
        @db.drop_table(:ce_rotation_test)
        @db.create_table(:ce_rotation_test) do
          primary_key :id
          String :name
          String :enc
        end
        @model = Class.new(Sequel::Model(@db[:ce_rotation_test]))
        @model.plugin :column_encryption do |enc|
          enc.key 0, "0"*32
          enc.column :enc, :searchable=>true
        end
        3.times{|i| @model.create(:name=>"row#{i + 1}", :enc=>"value#{i + 1}")}

        @model.plugin :column_encryption do |enc|
          enc.key 1, "1"*32
          enc.key 0, "0"*32
          enc.column :enc, :searchable=>true
        end

        # Search finds values encrypted with both the new and old keys during
        # the transition.
        @model.rotate_encryption(:batch_size=>1, :max_batches=>1)
        @model.with_encrypted_value(:enc, "value1").select_map(:id).must_equal [1]
        @model.with_encrypted_value(:enc, "value2").select_map(:id).must_equal [2]
        @model.with_encrypted_value(:enc, "value3").select_map(:id).must_equal [3]

        @model.rotate_encryption(:batch_size=>10)
        @model.with_encrypted_value(:enc, "value1").select_map(:id).must_equal [1]
        @model.with_encrypted_value(:enc, "value2").select_map(:id).must_equal [2]
        @model.with_encrypted_value(:enc, "value3").select_map(:id).must_equal [3]
        @model.with_encrypted_value(:enc, "value4").must_be_empty
        @model.needing_reencryption.count.must_equal 0
      end
    end
  end
end if RUBY_VERSION >= '2.3' && (begin; require 'sequel/plugins/column_encryption'; true; rescue LoadError; false end)
