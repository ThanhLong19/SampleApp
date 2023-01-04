# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'MicropostsInterfaces', type: :request do
  describe 'GET /microposts_interfaces' do
    it 'works! (now write some real specs)' do
      get microposts_interfaces_path
      expect(response).to have_http_status(200)
    end
  end
end
