# frozen_string_literal: true

require "test_helper"

class UserTest < ActiveSupport::TestCase
  # Khởi tạo 1 User mặc định
  def setup
    @user = User.new(name: "Example User", email: "user@example.com",
                     password: "foobar", password_confirmation: "foobar")
  end

  # Kiểm tra User có tồn tại không?
  test "should be valid" do
    assert @user.valid?
  end

  # Kiểm tra name(User) empty
  test "name should be present" do
    @user.name = ""
    assert_not @user.valid?
  end

  # Kiểm tra email(User) empty
  test "email should be present" do
    @user.email = ""
    assert_not @user.valid?
  end

  # Kiểm tra độ dài email(User)
  test "name should not be too long" do
    @user.name = "a" * 51
    assert_not @user.valid?
  end

  # Kiểm tra độ dài email(User)
  test "email should not be too long" do
    @user.email = "#{"a" * 244}@example.com"
    assert_not @user.valid?
  end

  # Xác thực email nên chấp nhận địa chỉ hợp lệ
  test "email validation should accept valid addresses" do
    valid_addresses = %w[user@example.com USER@foo.COM A_US-ER@foo.bar.org
                         first.last@foo.jp alice+bob@baz.cn]
    valid_addresses.each do |valid_address|
      @user.email = valid_address
      assert @user.valid?, "#{valid_address.inspect} should be valid"
    end
  end

  # Xác thực email nên từ chối địa chỉ hợp lệ
  test "email validation should reject invalid addresses" do
    invalid_addresses = %w[user@example,com user_at_foo.org user.name@example.
                           foo@bar_baz.com foo@bar+baz.com]
    invalid_addresses.each do |invalid_address|
      @user.email = invalid_address
      assert_not @user.valid?, "#{invalid_address.inspect} should be invalid"
    end
  end

  # Email không được trùng lặp
  test "email addresses should be unique" do
    duplicate_user = @user.dup
    @user.save
    assert_not duplicate_user.valid?
  end

  # Kiểm tra password empty
  test "password should be present (nonblank)" do
    @user.password = @user.password_confirmation = " " * 6
    assert_not @user.valid?
  end

  # Kiểm tra độ dài của password
  test "password should have a minimum length" do
    @user.password = @user.password_confirmation = "a" * 5
    assert_not @user.valid?
  end

  # Xác thực ngườ dùng
  test "authenticated? should return false for a user with nil digest" do
    assert_not @user.authenticated?(:remember, "")
  end
end
