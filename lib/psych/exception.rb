# frozen_string_literal: true
module Psych
  class Exception < RuntimeError
  end

  class BadAlias < Exception
  end

  # Subclasses `BadAlias` for backwards compatibility
  class AliasesNotEnabled < BadAlias
    def initialize
      super "Alias parsing was not enabled. To enable it, pass `aliases: true` to `Psych::load` or `Psych::safe_load`."
    end
  end

  # Subclasses `BadAlias` for backwards compatibility
  class AnchorNotDefined < BadAlias
    def initialize anchor_name
      super "An alias referenced an unknown anchor: #{anchor_name}"
    end
  end

  class DisallowedClass < Exception
    def initialize action, klass_name
      super "Tried to #{action} unspecified class: #{klass_name}"
    end
  end

  # Raised when a hand-built or plugin-modified YAML AST fails the structural
  # validation performed by Psych::Nodes::ASTValidator.  A parser-produced AST
  # can never trigger this; it only guards trees whose shape is not guaranteed
  # to match what libyaml emits.
  class InvalidAST < Exception
    def initialize reason
      super "Invalid YAML AST: #{reason}"
    end
  end
end
