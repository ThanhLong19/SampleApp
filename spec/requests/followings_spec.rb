require 'rails_helper'

RSpec.describe "Followings", type: :request do
  describe "GET /followings" do
    it "works! (now write some real specs)" do
      get followings_path
      expect(response).to have_http_status(200)
    end
  end
end
