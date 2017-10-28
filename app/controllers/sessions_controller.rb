class SessionsController < ApplicationController
  def new
    render :new
  end
  def create
    user = User.find_by_credientials(
      params[:user][:email],
      params[:user][:password]
    )
    if user
      log_in!(user)
      redirect_to user_url(user)
    else
      flash.now[:errors] = ['invalid credentials!']
      render :new
    end
  end

  def destroy
    current_user.reset_session_token!
    session[:session_token] = nil

    redirect_to new_session_url
  end
end
