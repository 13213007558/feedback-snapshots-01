require 'brakeman/checks/base_check'
require 'brakeman/checks/validation_regex_parser'

#Reports any calls to +validates_format_of+ which do not use +\A+ and +\z+
#as anchors in the given regular expression.
#
#For example:
#
# #Allows anything after new line
# validates_format_of :user_name, :with => /^\w+$/
class Brakeman::CheckValidationRegex < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Report uses of validates_format_of with improper anchors"

  WITH = Sexp.new(:lit, :with)
  FORMAT = Sexp.new(:lit, :format)

  def run_check
    tracker.models.each do |name, model|
      @current_model = model
      format_validations = model.options[:validates_format_of]

      if format_validations
        format_validations.each do |v|
          process_validates_format_of v
        end
      end

      validates = model.options[:validates]

      if validates
        validates.each do |v|
          process_validates v
        end
      end
    end
  end

  #Check validates_format_of
  def process_validates_format_of validator
    if value = hash_access(validator.last, WITH)
      check_regex value, validator
    end
  end

  #Check validates ..., :format => ...
  def process_validates validator
    hash_arg = validator.last
    return unless hash? hash_arg

    value = hash_access(hash_arg, FORMAT)

    if hash? value
      value = hash_access(value, WITH)
    end

    if value
      check_regex value, validator
    end
  end

  #Issue warning if the regular expression does not use
  #+\A+ and +\z+
  def check_regex value, validator
    return unless regexp? value

    regex = value.value
    parser = Brakeman::ValidationRegexParser.new(regex.source, extended: extended?(regex))

    unless parser.anchored?
      warn :model => @current_model,
      :warning_type => "Format Validation",
      :warning_code => :validation_regex,
      :message => msg("Insufficient validation for ", msg_code(get_name validator), " using ", msg_code(regex.inspect), ". ", parser.problem, " Use ", msg_code("\\A"), " and ", msg_code("\\z"), " as anchors"),
      :line => value.line,
      :confidence => :high,
      :cwe_id => [777],
      :code => validator
    end
  end

  #Get the name of the attribute being validated.
  def get_name validator
    name = validator[1]

    if sexp? name
      name.value
    else
      name
    end
  end

  private

  def extended? regex
    regex.options & Regexp::EXTENDED != 0
  end
end
