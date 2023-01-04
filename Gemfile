# frozen_string_literal: true

source 'https://rubygems.org'
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

ruby '3.1.3'

# Bundle edge Rails instead: gem "rails", github: "rails/rails", branch: "main"
gem 'rails', '~> 7.0.4'

# The original asset pipeline for Rails [https://github.com/rails/sprockets-rails]
gem 'sprockets-rails'

# Use sqlite3 as the database for Active Record
# gem "sqlite3", "~> 1.4"

# Use the Puma web server [https://github.com/puma/puma]
gem 'puma', '~> 5.0'

# Use JavaScript with ESM import maps [https://github.com/rails/importmap-rails]
gem 'importmap-rails'

# Hotwire's SPA-like page accelerator [https://turbo.hotwired.dev]
gem 'turbo-rails'

# Hotwire's modest JavaScript framework [https://stimulus.hotwired.dev]
gem 'stimulus-rails'

# Build JSON APIs with ease [https://github.com/rails/jbuilder]
# gem "jbuilder"

# Use Redis adapter to run Action Cable in production
# gem "redis", "~> 4.0"

# Use Kredis to get higher-level data types in Redis [https://github.com/rails/kredis]
# gem "kredis"

# Use Active Model has_secure_password [https://guides.rubyonrails.org/active_model_basics.html#securepassword]
# gem "bcrypt", "~> 3.1.7"

# Windows does not include zoneinfo files, so bundle the tzinfo-data gem
gem 'tzinfo-data', platforms: %i[mingw mswin x64_mingw jruby]

# Reduces boot times through caching; required in config/boot.rb
gem 'bootsnap', require: false

# Use Sass to process CSS
# gem "sassc-rails"

# Use Active Storage variants [https://guides.rubyonrails.org/active_storage_overview.html#transforming-images]
# gem "image_processing", "~> 1.2"

group :development, :test do
  # See https://guides.rubyonrails.org/debugging_rails_applications.html#debugging-with-the-debug-gem
  gem 'debug', platforms: %i[mri mingw x64_mingw]
end

# group :development do
# # Use console on exceptions pages [https://github.com/rails/web-console]
# gem "web-console"

# # Add speed badges [https://github.com/MiniProfiler/rack-mini-profiler]
# # gem "rack-mini-profiler"

# # Speed up commands on slow machines / big apps [https://github.com/rails/spring]
# # gem "spring"
# end

# group :test do
# # Use system testing [https://guides.rubyonrails.org/testing.html#system-testing]
# gem "capybara"
# gem "selenium-webdriver"
# gem "webdrivers"
# end

gem 'active_storage_validations', '~> 1.0', '>= 1.0.3'
gem 'bcrypt', '~> 3.1', '>= 3.1.18'
gem 'bootstrap-sass', '~> 3.4', '>= 3.4.1'
gem 'bootstrap-will_paginate', '~> 1.0'
gem 'coffee-rails', '~> 5.0'
gem 'faker', '~> 3.1'
gem 'image_processing', '~> 1.12', '>= 1.12.2'
gem 'jbuilder', '~> 2.11', '>= 2.11.5'
gem 'jquery-rails', '~> 4.5', '>= 4.5.1'
gem 'mini_magick', '~> 4.12'
gem 'rspec', '~> 3.12'
gem 'rspec-rails', '~> 6.0', '>= 6.0.1'
gem 'rubocop', '~> 1.40'
gem 'sassc-rails', '~> 2.1', '>= 2.1.2'
gem 'sass-rails', '~> 6.0'
gem 'turbolinks', '~> 5.2', '>= 5.2.1'
gem 'uglifier', '~> 4.2'
gem 'webpacker', '~> 5.4', '>= 5.4.3'
gem 'will_paginate', '~> 3.3', '>= 3.3.1'

group :production do
  gem 'aws-sdk-s3', '~> 1.117', '>= 1.117.2'
  gem 'pg', '~> 1.4', '>= 1.4.5'
  gem 'rails_12factor', '~> 0.0.3'
end

group :development, :test do
  gem 'listen', '~> 3.7', '>= 3.7.1'
  gem 'spring', '~> 4.1'
  gem 'spring-watcher-listen', '~> 2.1'
end

group :development, :test do
  gem 'byebug', '~> 11.1', '>= 11.1.3'
  gem 'sqlite3', '~> 1.4'
end

group :development do
  gem 'web-console', '~> 4.2'
end

group :test do
  gem 'capybara'
  gem 'guard', '~> 2.18'
  gem 'guard-minitest', '~> 2.4', '>= 2.4.6'
  gem 'mini_backtrace', '~> 0.1.3'
  gem 'minitest', '~> 5.16', '>= 5.16.3'
  gem 'minitest-reporters', '~> 1.5'
  gem 'rails-controller-testing', '~> 1.0', '>= 1.0.5'
  gem 'selenium-webdriver'
  gem 'webdrivers'
end
