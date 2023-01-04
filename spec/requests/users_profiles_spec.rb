# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'UsersProfiles', type: :request do
  describe 'GET /users_profiles' do
    it 'works! (now write some real specs)' do
      get users_profiles_path
      expect(response).to have_http_status(200)
    end
  end
end
