# frozen_string_literal: true

class User < ApplicationRecord
  attr_accessor :remember_token

  # Chuyển email thành chữ thường
  before_save { email.downcase! }

  # Kiểm tra name(User) empty + độ dài <= 50
  validates :name, presence: true, length: { maximum: 50 }

  # Định nghĩa format cho email
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i

  # Kiểm tra email(User) empty + độ dài <= 255 + format + không trùng lặp
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: true

  # Có mật khẩu an toàn
  has_secure_password

  # Kiểm tra password empty + độ dài >= 6
  validates :password, presence: true, length: { minimum: 6 }

  # Returns the hash digest of the given string.
  def self.digest(string)
    cost = if ActiveModel::SecurePassword.min_cost
             BCrypt::Engine::MIN_COST
           else
             BCrypt::Engine.cost
           end
    BCrypt::Password.create(string, cost:)
  end

  # Trả về 1 chuỗi token ngẫu nhiên
  def self.new_token
    SecureRandom.urlsafe_base64
  end

  # Ghi nhớ User vào trong database bằng mã session
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end

  # Trả về True nếu mã digest giống mã token
  def authenticated?(remember_token)
    return false if remember_digest.nil?

    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end

  # Forgets a user.
  def forget
    update_attribute(:remember_digest, nil)
  end
end
