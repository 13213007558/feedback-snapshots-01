class Order < ApplicationRecord
  belongs_to :account
  belongs_to :approver, class_name: 'User', optional: true
end
