# frozen_string_literal: true
require_relative 'omap'
require_relative 'set'

module Psych
  class ClassLoader # :nodoc:
    BIG_DECIMAL = 'BigDecimal'
    COMPLEX     = 'Complex'
    DATA        = 'Data' unless RUBY_VERSION < "3.2"
    DATE        = 'Date'
    DATE_TIME   = 'DateTime'
    ENCODING    = 'Encoding'
    EXCEPTION   = 'Exception'
    OBJECT      = 'Object'
    PSYCH_OMAP  = 'Psych::Omap'
    PSYCH_SET   = 'Psych::Set'
    RANGE       = 'Range'
    RATIONAL    = 'Rational'
    REGEXP      = 'Regexp'
    STRUCT      = 'Struct'
    SYMBOL      = 'Symbol'

    def initialize
      @cache = CACHE.dup
    end

    def load klassname
      return nil if !klassname || klassname.empty?

      find klassname
    end

    def symbolize sym
      symbol
      sym.to_sym
    end

    constants.each do |const|
      konst = const_get const
      class_eval <<~RUBY, __FILE__, __LINE__ + 1
        def #{const.to_s.downcase}
          load #{konst.inspect}
        end
      RUBY
    end

    private

    def find klassname
      @cache[klassname] ||= resolve(klassname)
    end

    def resolve klassname
      name    = klassname
      retried = false

      begin
        path2class(name)
      rescue ArgumentError, NameError => ex
        unless retried
          name    = "Struct::#{name}"
          retried = ex
          retry
        end
        raise retried
      end
    end

    CACHE = Hash[constants.map { |const|
      val = const_get const
      begin
        [val, ::Object.const_get(val)]
      rescue
        nil
      end
    }.compact].freeze

    class Restricted < ClassLoader
      CONST_DEFINED = ::Module.instance_method(:const_defined?)
      CONST_GET     = ::Module.instance_method(:const_get)
      AUTOLOAD      = ::Module.instance_method(:autoload?)
      ANCESTORS     = ::Module.instance_method(:ancestors)
      MODULE_NAME   = ::Module.instance_method(:name)
      MODULE_LT     = ::Module.instance_method(:<)
      private_constant :CONST_DEFINED, :CONST_GET, :AUTOLOAD, :ANCESTORS,
                       :MODULE_NAME, :MODULE_LT

      # Permission entries in +classes+ are either Class or Module objects, or
      # (for backwards compatibility) class names.
      #
      # In the default +:auto+ mode, Class and Module entries grant permission
      # to that exact object, while String and Symbol entries keep the legacy
      # name-based behaviour.  +:identity+ requires every entry to be a Class or
      # Module and binds all permissions to the object identity.  +:name+ keeps
      # the original name-based behaviour for every entry.
      def initialize classes, symbols, mode: :auto
        @symbols = Array(symbols)
        @mode = case mode
                when :auto, nil then :auto
                when :identity then :identity
                when :name then :name
                else
                  raise ArgumentError, "unknown class permission mode: #{mode.inspect}"
                end

        @class_identities = {}.compare_by_identity
        @class_names = {}
        @struct_names = {}
        @ambiguous_class_names = {}
        @ambiguous_struct_names = {}
        @name_permitted = {}

        Array(classes).each do |entry|
          case entry
          when ::Module
            if @mode == :name
              @name_permitted[entry.to_s] = true
            else
              @class_identities[entry] = true
              register_class_name(entry)
            end
          when ::String, ::Symbol
            if @mode == :identity
              raise ArgumentError,
                "permitted_classes must contain Class or Module objects when class permissions are strict"
            end
            @name_permitted[entry.to_s] = true
          else
            if @mode == :identity
              raise ArgumentError,
                "permitted_classes must contain Class or Module objects when class permissions are strict (got #{entry.class})"
            end
            # Compatibility with the original name-based API, which called
            # +to_s+ on every entry.
            @name_permitted[entry.to_s] = true
          end
        end
        super()
      end

      def symbolize sym
        return super if @symbols.empty?

        if @symbols.include? sym
          super
        else
          raise DisallowedClass.new('load', 'Symbol')
        end
      end

      private

      def register_class_name klass
        name = MODULE_NAME.bind(klass).call
        return unless name && !name.empty?

        register_name(@class_names, @ambiguous_class_names, name, klass)

        # Legacy dumps of Structs created with a String name use the short
        # name ("Foo" for Struct::Foo).  Bind that spelling to the same class
        # object rather than re-resolving it through the current constants.
        if MODULE_LT.bind(klass).call(::Struct) && name.start_with?('Struct::')
          short_name = name.sub(/\AStruct::/, '')
          register_name(@struct_names, @ambiguous_struct_names, short_name, klass) unless short_name.empty?
        end
      end

      # Bind +name+ to +klass+.  If two different approved classes claim the
      # same spelling, the name is ambiguous and must not grant either.
      def register_name table, ambiguous, name, klass
        return if ambiguous[name]

        if table.key?(name) && !table[name].equal?(klass)
          table.delete(name)
          ambiguous[name] = true
        else
          table[name] = klass
        end
      end

      def find klassname
        # A name recorded when permission was granted keeps referring to the
        # approved class object even if that constant is rebound later.
        if (klass = @class_names[klassname])
          return klass
        end

        if @name_permitted[klassname]
          return super
        end

        if @class_identities.empty?
          raise DisallowedClass.new('load', klassname)
        end

        # Otherwise the tag must name the approved class object itself, or an
        # alias of it.  Resolve the alias without triggering autoload.
        klass = resolve_constant_alias(klassname)
        if klass
          return klass if @class_identities[klass]
          raise DisallowedClass.new('load', klassname)
        end

        # Legacy dumps may name a Struct by its short name ("Foo" for
        # Struct::Foo).  Keep that fallback, but only when it lands on an
        # approved class object.
        unless klassname.to_s.start_with?('Struct::')
          if (klass = @struct_names[klassname])
            return klass
          end

          klass = resolve_constant_alias("Struct::#{klassname}")
          return klass if klass && @class_identities[klass]
        end

        raise DisallowedClass.new('load', klassname)
      end

      def resolve_constant_alias klassname
        return nil unless klassname.is_a?(::String)
        return nil if klassname.empty?

        parts = klassname.split('::', -1)
        return nil if parts.empty? || parts.any? { |part| part.empty? }

        mod = ::Object
        parts.each do |part|
          mod = lookup_constant(mod, part)
          return nil unless mod
        end
        mod
      rescue ::NameError, ::ArgumentError
        nil
      end

      # Resolve +name+ in normal constant lookup order, but without executing
      # autoloads or falling back to +const_missing+.  Bound Module methods are
      # used so a class cannot hijack this security check by overriding
      # +const_get+ on itself.
      def lookup_constant mod, name
        return nil unless ::Module === mod

        ANCESTORS.bind(mod).call.each do |ancestor|
          next unless CONST_DEFINED.bind(ancestor).call(name, false)

          # A pending autoload is refused rather than executed.
          return nil if AUTOLOAD.bind(ancestor).call(name)

          return CONST_GET.bind(ancestor).call(name, false)
        end

        nil
      rescue ::NameError, ::ArgumentError
        nil
      end
    end
  end
end
