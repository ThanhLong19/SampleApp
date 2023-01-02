# frozen_string_literal: true

class SessionsController < ApplicationController
  def new; end

  def create
    user = User.find_by(email: params[:session][:email].downcase)
    if user&.authenticate(params[:session][:password])
      # Đăng nhập thành công => Chuyển sang page "/show"
      reset_session
      log_in user
      params[:session][:remember_me] == '1' ? remember(user) : forget(user)
      # session[:session_token] = user.session_token
      remember user
      redirect_to user
    else
      # Đăng nhập không thành công => Hiện message
      flash.now[:danger] = 'Invalid email/password combination'
      render 'new'
    end
  end

  def destroy
    log_out if logged_in?
    redirect_to root_url
  end
end
