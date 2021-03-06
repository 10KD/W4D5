class UsersController < ApplicationController
  def new
    @user = User.new
    render :new
  end

  def create # log in immediately after sign up
    @user = User.new(user_params)

    if @user.save

      redirect_to new_session_url
    else
      flash.now[:errors] = @user.errors.full_messages
      render :new
    end
  end



  def show
    render :show
  end

  def user_params
    params.require(:user).permit(:email, :password)
  end
end
