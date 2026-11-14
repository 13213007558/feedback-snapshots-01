class Account < ApplicationRecord
  has_many :orders
  has_many :invoices, class_name: 'Order'
end
