class Coupon < ActiveRecord::Base
  validates_format_of :code, with: /\A(pre|post\z)/
  validates_format_of :region, with: /\A(?:pre|post)\z/
  validates_format_of :line_end, with: /\Alegacy\Z/
end
