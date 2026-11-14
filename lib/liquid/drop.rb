# frozen_string_literal: true

require 'set'

module Liquid
  # A drop in liquid is a class which allows you to export DOM like things to liquid.
  # Methods of drops are callable.
  # The main use for liquid drops is to implement lazy loaded objects.
  # If you would like to make data available to the web designers which you don't want loaded unless needed then
  # a drop is a great way to do that.
  #
  # Example:
  #
  #   class ProductDrop < Liquid::Drop
  #     def top_sales
  #       Shop.current.products.find(:all, :order => 'sales', :limit => 10 )
  #     end
  #   end
  #
  #   tmpl = Liquid::Template.parse( ' {% for product in product.top_sales %} {{ product.name }} {%endfor%} '  )
  #   tmpl.render('product' => ProductDrop.new ) # will invoke top_sales query.
  #
  # Your drop can either implement the methods sans any parameters
  # or implement the liquid_method_missing(name) method which is a catch all.
  #
  # By default every public method is exportable, which means that adding a new
  # public method to an existing drop also exposes it to every template. If a
  # drop should only expose an approved set of data methods, declare it
  # explicitly:
  #
  #   class ProductDrop < Liquid::Drop
  #     liquid_expose :title, :price
  #
  #     def title
  #       product.title
  #     end
  #
  #     def price
  #       product.price
  #     end
  #
  #     def recalculate_cache!
  #       # Not exported: it is public, but it was never approved above.
  #     end
  #   end
  #
  # A declaration is inherited, but it is bound to the method implementation
  # that was current when it was sealed. If a subclass overrides an exposed
  # method, the override is not automatically exported and must call
  # +liquid_expose+ again. Redefining, aliasing over, prepending a module, or
  # changing the visibility of a sealed method has the same effect. Calling
  # +liquid_expose+ again re-confirms the declaration against the current
  # implementation.
  #
  # Dynamic fields returned by +liquid_method_missing+ require a separate
  # declaration. They are disabled as soon as a drop declares an exposure list,
  # because the catch all must not become a way around that list. Opt in to
  # dynamic fields explicitly when they are needed:
  #
  #   class SettingsDrop < Liquid::Drop
  #     liquid_expose :title
  #     liquid_expose_missing
  #
  #     def title
  #       @settings["title"]
  #     end
  #
  #     def liquid_method_missing(name)
  #       @settings[name.to_s]
  #     end
  #   end
  #
  # +liquid_expose_missing+ can also receive the only dynamic keys that are
  # allowed, or a block that decides whether a key is allowed:
  #
  #   liquid_expose_missing :theme, :locale
  #   liquid_expose_missing { |name| name.start_with?("section.") }
  #
  # Even then, +liquid_method_missing+ is only called for names that are not
  # actual methods on the drop. This keeps the catch all from being used to
  # reach an unexposed +admin_token+ (or any other Ruby method).
  #
  # == Migrating an existing drop
  #
  # A drop that previously relied on "every public method" can move to an
  # allow list without changing how templates read its values:
  #
  #   # Before: any new public method became callable from templates.
  #   class AccountDrop < Liquid::Drop
  #     def initialize(account)
  #       super()
  #       @account = account
  #     end
  #
  #     def name
  #       @account.name
  #     end
  #
  #     def plan
  #       @account.plan
  #     end
  #
  #     def suspend!
  #       @account.suspend!
  #     end
  #   end
  #
  #   # After: only name and plan are approved. suspend! stays public for
  #   # internal callers but is not reachable from a template.
  #   class AccountDrop < Liquid::Drop
  #     liquid_expose :name, :plan
  #
  #     def initialize(account)
  #       super()
  #       @account = account
  #     end
  #
  #     def name
  #       @account.name
  #     end
  #
  #     def plan
  #       @account.plan
  #     end
  #
  #     def suspend!
  #       @account.suspend!
  #     end
  #   end
  #
  # If the old drop also served computed keys through liquid_method_missing,
  # add +liquid_expose_missing+ (optionally with names or a block). Otherwise
  # those keys become unavailable, which is the safe default.
  class Drop
    ExposureSeal = Struct.new(:implementation, :public_visibility, :sealed, :revoked)
    MissingContract = Struct.new(:kind, :names, :predicate)
    private_constant :ExposureSeal, :MissingContract

    attr_writer :context

    def initialize
      @context = nil
    end

    # Catch all for the method
    def liquid_method_missing(method)
      return unless @context&.strict_variables
      raise Liquid::UndefinedDropMethod, "undefined method #{method}"
    end

    BASE_METHOD_MISSING = instance_method(:liquid_method_missing)
    private_constant :BASE_METHOD_MISSING

    # Declares the methods that may be invoked from a template. Calling this
    # switches the class (and its subclasses) from the legacy "every public
    # method" behaviour to an allow list. The declaration is inherited and
    # additive; a subclass may declare additional methods, and must declare a
    # method again if it overrides an inherited declaration.
    def self.liquid_expose(*method_names)
      liquid_reject_base_declaration!

      names = method_names.flatten.compact.map do |name|
        unless name.is_a?(String) || name.is_a?(Symbol)
          raise ArgumentError, "liquid_expose expects method names, got #{name.class}"
        end

        name.to_sym
      end
      exposed = (@liquid_exposed_methods ||= {})

      names.each do |name|
        seal = ExposureSeal.new(nil, nil, false, false)

        # Seal immediately only when the class owns the implementation. An
        # inherited method (or one not defined yet) stays pending until first
        # use, so a declaration placed above its method definition does not
        # accidentally approve an ancestor's implementation.
        implementation = liquid_resolve_instance_method(name)
        if implementation && implementation.owner == self
          seal.implementation = implementation
          seal.public_visibility = public_method_defined?(name)
          seal.sealed = true
        end

        exposed[name] = seal
      end

      @invokable_methods = nil
      @liquid_core_method_blacklist = nil
      names
    end

    # Opts a drop into dynamic fields through +liquid_method_missing+. Dynamic
    # fields are disabled by default once an exposure list is declared. Passing
    # names restricts the contract to those names, and passing a block uses the
    # block as a predicate. Passing +false+ disables the inherited contract.
    # Names that resolve to actual methods on the drop are never handed to the
    # catch all, so it cannot be used to reach an unexposed method.
    #
    # Declaring a dynamic contract also switches the class to explicit mode
    # with an empty static allow list, so public methods must be approved with
    # +liquid_expose+ as well.
    def self.liquid_expose_missing(*allowed_names, &predicate)
      liquid_reject_base_declaration!

      contract =
        if allowed_names.length == 1 && (allowed_names.first == false || allowed_names.first.nil?)
          MissingContract.new(:disabled, nil, nil)
        elsif predicate
          MissingContract.new(:predicate, nil, predicate)
        elsif allowed_names.empty? || (allowed_names.length == 1 && allowed_names.first == true)
          MissingContract.new(:all, nil, nil)
        else
          names = allowed_names.flatten.compact.map(&:to_s)
          MissingContract.new(:names, Set.new(names), nil)
        end

      @liquid_exposed_methods ||= {}
      @liquid_expose_missing = contract
      @invokable_methods = nil
      @liquid_core_method_blacklist = nil
      contract
    end

    # Whether this class (or an ancestor) uses an explicit exposure
    # declaration. Legacy drops without one keep exposing all public methods.
    def self.liquid_exposure_declared?
      klass = self
      while klass
        return true if klass.instance_variable_defined?(:@liquid_exposed_methods)
        klass = klass.superclass
      end
      false
    end

    # Whether dynamic +liquid_method_missing+ fields are enabled for +name+.
    def self.liquid_expose_missing?(name = nil)
      contract = liquid_missing_contract
      return false unless contract

      case contract.kind
      when :all
        true
      when :names
        name.nil? ? !contract.names.empty? : contract.names.include?(name.to_s)
      when :predicate
        name.nil? ? true : !!contract.predicate.call(name.to_s)
      else
        false
      end
    end

    # called by liquid to invoke a drop
    def invoke_drop(method_or_key)
      if self.class.invokable?(method_or_key)
        public_send(method_or_key)
      elsif !self.class.liquid_exposure_declared?
        liquid_method_missing(method_or_key)
      elsif self.class.liquid_expose_missing?(method_or_key) &&
          !self.class.send(:liquid_declared_name?, method_or_key) &&
          !self.class.send(:liquid_instance_method_defined?, method_or_key) &&
          !liquid_dynamic_field_defined?(method_or_key)
        liquid_method_missing(method_or_key)
      else
        BASE_METHOD_MISSING.bind_call(self, method_or_key)
      end
    end

    # A drop may compute fields that do not exist as methods at all (for
    # example from a backing hash). Private and protected Ruby methods are
    # still treated as real methods, so the catch all cannot reach them.
    def liquid_dynamic_field_defined?(name)
      return false unless name.is_a?(String) || name.is_a?(Symbol)

      singleton_class.method_defined?(name) ||
        singleton_class.private_method_defined?(name) ||
        self.class.method_defined?(name) ||
        self.class.private_method_defined?(name)
    end
    private :liquid_dynamic_field_defined?

    def key?(_name)
      true
    end

    def inspect
      self.class.to_s
    end

    def to_liquid
      self
    end

    def to_s
      self.class.name
    end

    alias_method :[], :invoke_drop

    # Check for method existence without invoking respond_to?, which creates symbols
    def self.invokable?(method_name)
      if liquid_exposure_declared?
        liquid_explicit_invokable?(method_name)
      else
        invokable_methods.include?(method_name.to_s)
      end
    end

    def self.invokable_methods
      if liquid_exposure_declared?
        names = ['to_liquid']
        seen = Set.new

        liquid_declaration_chain.each do |klass|
          declarations = klass.instance_variable_get(:@liquid_exposed_methods)
          next unless declarations

          declarations.each_key do |name|
            next if seen.include?(name)
            seen << name

            names << name.to_s if liquid_exposure_allowed?(name, klass)
          end
        end

        Set.new(names)
      else
        @invokable_methods ||= begin
          blacklist = Liquid::Drop.public_instance_methods + [:each]

          if include?(Enumerable)
            blacklist += Enumerable.public_instance_methods
            blacklist -= [:sort, :count, :first, :min, :max]
          end

          whitelist = [:to_liquid] + (public_instance_methods - blacklist)
          Set.new(whitelist.map(&:to_s))
        end
      end
    end

    # Hot path for an explicit exposure declaration. Only the requested name is
    # resolved, so a template lookup costs one method resolution regardless of
    # how many methods are declared.
    def self.liquid_explicit_invokable?(method_name) # :nodoc:
      return true if method_name.to_s == 'to_liquid'
      return false unless method_name.is_a?(String) || method_name.is_a?(Symbol)

      name = method_name.to_sym
      declaring_class = liquid_declaring_class(name)
      return false unless declaring_class

      liquid_exposure_allowed?(name, declaring_class)
    end
    private_class_method :liquid_explicit_invokable?

    # Confirms that +name+ is still bound to the implementation approved by
    # +declaring_class+. The first call seals a pending declaration. A method
    # that was replaced, removed, or had its visibility changed is revoked
    # until the class declares it again.
    def self.liquid_exposure_allowed?(name, declaring_class) # :nodoc:
      return false if liquid_core_method_blacklist.include?(name)

      declarations = declaring_class.instance_variable_get(:@liquid_exposed_methods)
      seal = declarations[name]
      return false unless seal
      return false if seal.revoked

      return false unless declaring_class.send(:liquid_exposure_verified?, seal, name)
      return false unless seal.sealed && seal.public_visibility

      implementation = liquid_resolve_instance_method(name)
      !implementation.nil? && implementation == seal.implementation
    end
    private_class_method :liquid_exposure_allowed?

    # The nearest class that declared +name+ wins, so a subclass can redeclare
    # a method (and thereby re-approve its own implementation) without
    # inheriting the parent approval.
    def self.liquid_declaring_class(name) # :nodoc:
      klass = self
      while klass
        declarations = klass.instance_variable_get(:@liquid_exposed_methods)
        return klass if declarations&.key?(name)
        klass = klass.superclass
      end
      nil
    end
    private_class_method :liquid_declaring_class

    # Binds a pending declaration to the implementation currently visible from
    # its declaring class, or revokes a sealed declaration when the method has
    # been replaced or its visibility changed. A declaration made before the
    # method is defined stays pending, so macros placed above a method
    # definition still work. Revocation is permanent until the class declares
    # the method again; restoring the old implementation does not silently
    # restore permission.
    def self.liquid_exposure_verified?(seal, name) # :nodoc:
      implementation = liquid_resolve_instance_method(name)

      if !seal.sealed
        return false unless implementation

        seal.implementation = implementation
        seal.public_visibility = public_method_defined?(name)
        seal.sealed = true
        return true
      end

      current_public = public_method_defined?(name)
      if implementation != seal.implementation || current_public != seal.public_visibility
        seal.revoked = true
        return false
      end

      true
    end
    private_class_method :liquid_exposure_verified?

    def self.liquid_core_method_blacklist # :nodoc:
      @liquid_core_method_blacklist ||= begin
        blacklist = Liquid::Drop.public_instance_methods + [:each]

        if include?(Enumerable)
          blacklist += Enumerable.public_instance_methods
          blacklist -= [:sort, :count, :first, :min, :max]
        end

        Set.new(blacklist)
      end
    end
    private_class_method :liquid_core_method_blacklist

    def self.liquid_missing_contract # :nodoc:
      klass = self
      while klass
        if klass.instance_variable_defined?(:@liquid_expose_missing)
          return klass.instance_variable_get(:@liquid_expose_missing)
        end
        klass = klass.superclass
      end
      nil
    end
    private_class_method :liquid_missing_contract

    def self.liquid_reject_base_declaration! # :nodoc:
      if equal?(Liquid::Drop)
        raise ArgumentError, "declare exposures on a Drop subclass, not on Liquid::Drop itself"
      end
    end
    private_class_method :liquid_reject_base_declaration!

    def self.liquid_declaration_chain # :nodoc:
      chain = []
      klass = self
      while klass
        chain << klass if klass.instance_variable_defined?(:@liquid_exposed_methods)
        klass = klass.superclass
      end
      chain
    end
    private_class_method :liquid_declaration_chain

    def self.liquid_resolve_instance_method(name) # :nodoc:
      instance_method(name)
    rescue NameError, TypeError
      nil
    end
    private_class_method :liquid_resolve_instance_method

    # A name that was declared for static exposure must never be served by the
    # dynamic contract, even if its method was later removed or revoked.
    def self.liquid_declared_name?(name) # :nodoc:
      return false unless name.is_a?(String) || name.is_a?(Symbol)

      key = name.to_sym
      klass = self
      while klass
        declarations = klass.instance_variable_get(:@liquid_exposed_methods)
        return true if declarations&.key?(key)
        klass = klass.superclass
      end
      false
    end
    private_class_method :liquid_declared_name?

    def self.liquid_instance_method_defined?(name) # :nodoc:
      return false unless name.is_a?(String) || name.is_a?(Symbol)

      method_defined?(name) || private_method_defined?(name)
    end
    private_class_method :liquid_instance_method_defined?

    class << self
      # Compatibility names for the declaration API.
      alias_method :liquid_expose_methods, :liquid_expose
      alias_method :liquid_methods, :liquid_expose
      alias_method :liquid_expose_dynamic_fields, :liquid_expose_missing
    end
  end
end
