# frozen_string_literal: true
require_relative "spec_helper"

describe "AssociationDependencies plugin" do
  before do
    @mods = []
    @c = Class.new(Sequel::Model)
    @c.plugin :association_dependencies
    @Artist = Class.new(@c).set_dataset(:artists)
    @Artist.dataset = @Artist.dataset.with_fetch(:id=>2, :name=>'Ar')
    @Album = Class.new(@c).set_dataset(:albums)
    @Album.dataset = @Album.dataset.with_fetch(:id=>1, :name=>'Al', :artist_id=>2)
    @Artist.columns :id, :name
    @Album.columns :id, :name, :artist_id
    @Artist.one_to_many :albums, :class=>@Album, :key=>:artist_id
    @Artist.one_to_one :first_album, :class=>@Album, :key=>:artist_id, :conditions=>{:position=>1}
    @Artist.many_to_many :other_artists, :class=>@Artist, :join_table=>:aoa, :left_key=>:l, :right_key=>:r
    @Album.many_to_one :artist, :class=>@Artist
    DB.reset
  end

  it "should allow destroying associated many_to_one associated object" do
    @Album.add_association_dependencies :artist=>:destroy
    @Album.load(:id=>1, :name=>'Al', :artist_id=>2).destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE id = 1', 'SELECT * FROM artists WHERE (artists.id = 2) LIMIT 1', 'DELETE FROM artists WHERE id = 2']
  end

  it "should allow deleting associated many_to_one associated object" do
    @Album.add_association_dependencies :artist=>:delete
    @Album.load(:id=>1, :name=>'Al', :artist_id=>2).destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE id = 1', 'DELETE FROM artists WHERE (artists.id = 2)']
  end
  
  it "should allow destroying associated one_to_one associated object" do
    @Artist.add_association_dependencies :first_album=>:destroy
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['SELECT * FROM albums WHERE ((position = 1) AND (albums.artist_id = 2)) LIMIT 1', 'DELETE FROM albums WHERE id = 1', 'DELETE FROM artists WHERE id = 2']
  end

  it "should allow deleting associated one_to_one associated object" do
    @Artist.add_association_dependencies :first_album=>:delete
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE ((position = 1) AND (albums.artist_id = 2))', 'DELETE FROM artists WHERE id = 2']
  end

  it "should allow destroying associated one_to_many objects" do
    @Artist.add_association_dependencies :albums=>:destroy
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['SELECT * FROM albums WHERE (albums.artist_id = 2)', 'DELETE FROM albums WHERE id = 1', 'DELETE FROM artists WHERE id = 2']
  end

  it "should allow deleting associated one_to_many objects" do
    @Artist.add_association_dependencies :albums=>:delete
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE (albums.artist_id = 2)', 'DELETE FROM artists WHERE id = 2']
  end
  
  it "should allow nullifying associated one_to_one objects" do
    @Artist.add_association_dependencies :first_album=>:nullify
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['UPDATE albums SET artist_id = NULL WHERE ((position = 1) AND (artist_id = 2))', 'DELETE FROM artists WHERE id = 2']
  end

  it "should allow nullifying associated one_to_many objects" do
    @Artist.add_association_dependencies :albums=>:nullify
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['UPDATE albums SET artist_id = NULL WHERE (artist_id = 2)', 'DELETE FROM artists WHERE id = 2']
  end

  it "should allow nullifying associated many_to_many associations" do
    @Artist.add_association_dependencies :other_artists=>:nullify
    @Artist.load(:id=>2, :name=>'Ar').destroy
    DB.sqls.must_equal ['DELETE FROM aoa WHERE (l = 2)', 'DELETE FROM artists WHERE id = 2']
  end

  it "should not allow modifications if class is frozen" do
    @Artist.add_association_dependencies :other_artists=>:nullify
    @Artist.freeze
    proc{@Artist.add_association_dependencies :albums=>:nullify}.must_raise RuntimeError, TypeError
    @Artist.association_dependencies.frozen?.must_equal true
    @Artist.association_dependencies[:before_nullify].frozen?.must_equal true
  end

  it "should raise an error if attempting to nullify a many_to_one association" do
    proc{@Album.add_association_dependencies :artist=>:nullify}.must_raise(Sequel::Error)
  end

  it "should raise an error if using an unrecognized dependence action" do
    proc{@Album.add_association_dependencies :artist=>:blah}.must_raise(Sequel::Error)
  end

  it "should raise an error if a nonexistent association is used" do
    proc{@Album.add_association_dependencies :blah=>:delete}.must_raise(Sequel::Error)
  end

  it "should raise an error if a invalid association type is used" do
    @Artist.plugin :many_through_many
    @Artist.many_through_many :other_albums, [[:id, :id, :id]]
    proc{@Artist.add_association_dependencies :other_albums=>:nullify}.must_raise(Sequel::Error)
  end

  it "should raise an error if using a many_to_many association type without nullify" do
    proc{@Artist.add_association_dependencies :other_artists=>:delete}.must_raise(Sequel::Error)
  end

  it "should allow specifying association dependencies in the plugin call" do
    @Album.plugin :association_dependencies, :artist=>:destroy
    @Album.load(:id=>1, :name=>'Al', :artist_id=>2).destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE id = 1', 'SELECT * FROM artists WHERE (artists.id = 2) LIMIT 1', 'DELETE FROM artists WHERE id = 2']
  end

  it "should work with subclasses" do
    c = Class.new(@Album)
    c.add_association_dependencies :artist=>:destroy
    c.load(:id=>1, :name=>'Al', :artist_id=>2).destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE id = 1', 'SELECT * FROM artists WHERE (artists.id = 2) LIMIT 1', 'DELETE FROM artists WHERE id = 2']

    @Album.load(:id=>1, :name=>'Al', :artist_id=>2).destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE id = 1']

    @Album.add_association_dependencies :artist=>:destroy
    c2 = Class.new(@Album)
    c2.load(:id=>1, :name=>'Al', :artist_id=>2).destroy
    DB.sqls.must_equal ['DELETE FROM albums WHERE id = 1', 'SELECT * FROM artists WHERE (artists.id = 2) LIMIT 1', 'DELETE FROM artists WHERE id = 2']
  end

  describe "with instance_filters" do
    before do
      @Artist.plugin :instance_filters
      @Artist.add_association_dependencies :albums=>:delete
      @Album.columns :id, :name, :artist_id, :tenant_id
      @Artist.columns :id, :name, :tenant_id
      @orig_artist_dataset = @Artist.dataset
      @orig_album_dataset = @Album.dataset
    end

    after do
      @Artist.dataset = @orig_artist_dataset
      @Album.dataset = @orig_album_dataset
      @orig_album_dataset.db.numrows = 1
    end

    # Set the row returned when querying artists, and load an artist object
    # with the given tenant.
    def load_artist(rows, tenant=1)
      @Artist.dataset = @orig_artist_dataset.with_fetch(rows)
      @artist = @Artist.load(:id=>2, :name=>'Ar', :tenant_id=>tenant)
    end

    it "should check that the object matches its filters before deleting associated objects" do
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.instance_dependency_filter(:tenant_id=>1)
      @artist.destroy
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 1)) LIMIT 1',
        'DELETE FROM albums WHERE ((albums.artist_id = 2) AND (tenant_id = 1))',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 1))',
        'COMMIT'
      ]
    end

    it "should not modify associated objects when the object does not match its filters" do
      load_artist([], 1)
      @artist.instance_dependency_filter(:tenant_id=>2)

      proc{@artist.destroy}.must_raise(Sequel::Plugins::InstanceFilters::Error)
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 2)) LIMIT 1',
        'ROLLBACK'
      ]

      @artist.send(:instance_filters).wont_be_empty
    end

    it "should check filters again when retrying after a failed destroy" do
      load_artist([], 1)
      @artist.instance_dependency_filter(:tenant_id=>2)
      proc{@artist.destroy}.must_raise(Sequel::Plugins::InstanceFilters::Error)
      DB.sqls

      # Still belongs to tenant 1, so a tenant 2 filter still doesn't match.
      @Artist.dataset = @orig_artist_dataset.with_fetch([])
      proc{@artist.destroy}.must_raise(Sequel::Plugins::InstanceFilters::Error)
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 2)) LIMIT 1',
        'ROLLBACK'
      ]

      # The object really is tenant 2, and the retry is now authorized.
      # The failed attempt did not consume the filters.
      @Artist.dataset = @orig_artist_dataset.with_fetch(:id=>2, :name=>'Ar', :tenant_id=>2)
      @artist = @Artist.load(:id=>2, :name=>'Ar', :tenant_id=>2)
      @artist.instance_dependency_filter(:tenant_id=>2)
      @artist.destroy
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 2)) LIMIT 1',
        'DELETE FROM albums WHERE ((albums.artist_id = 2) AND (tenant_id = 2))',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 2))',
        'COMMIT'
      ]
    end

    it "should apply dependency filters to associated objects but not to the object itself" do
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.instance_dependency_filter(:tenant_id=>2)
      @artist.destroy
      # The object check uses tenant_id = 2 for both the object and the
      # associated objects.  The important part is the associated object
      # delete uses the dependency filter.
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 2)) LIMIT 1',
        'DELETE FROM albums WHERE ((albums.artist_id = 2) AND (tenant_id = 2))',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 2))',
        'COMMIT'
      ]
    end

    it "should not apply instance filters that were not added as dependency filters to associated objects" do
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.instance_filter(:tenant_id=>1)
      @artist.destroy
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 1)) LIMIT 1',
        'DELETE FROM albums WHERE (albums.artist_id = 2)',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 1))',
        'COMMIT'
      ]
    end

    it "should apply dependency filters when nullifying associated objects" do
      @Artist.association_dependencies[:before_delete].clear
      @Artist.add_association_dependencies :albums=>:nullify
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.instance_dependency_filter(:tenant_id=>1)
      @artist.destroy
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 1)) LIMIT 1',
        'UPDATE albums SET artist_id = NULL WHERE ((albums.artist_id = 2) AND (tenant_id = 1))',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 1))',
        'COMMIT'
      ]
    end

    it "should force a transaction for destroy so dependent writes are rolled back if the object delete fails" do
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.instance_dependency_filter(:tenant_id=>1)
      DB.numrows = [1, 0]

      proc{@artist.destroy}.must_raise(Sequel::NoExistingObject)
      DB.sqls.must_equal [
        'BEGIN',
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 1)) LIMIT 1',
        'DELETE FROM albums WHERE ((albums.artist_id = 2) AND (tenant_id = 1))',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 1))',
        'ROLLBACK'
      ]
    end

    it "should not force a transaction if an explicit transaction option is given" do
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.instance_dependency_filter(:tenant_id=>1)
      @artist.destroy(:transaction=>false)
      DB.sqls.must_equal [
        'SELECT 1 AS v FROM artists WHERE ((id = 2) AND (tenant_id = 1)) LIMIT 1',
        'DELETE FROM albums WHERE ((albums.artist_id = 2) AND (tenant_id = 1))',
        'DELETE FROM artists WHERE ((id = 2) AND (tenant_id = 1))'
      ]
    end

    it "should not check filters for dependent writes if the object has no instance filters" do
      load_artist(:id=>2, :name=>'Ar', :tenant_id=>1)
      @artist.destroy
      DB.sqls.must_equal [
        'DELETE FROM albums WHERE (albums.artist_id = 2)',
        'DELETE FROM artists WHERE id = 2'
      ]
    end
  end
end
