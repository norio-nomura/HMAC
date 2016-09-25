require 'xcjobs'

def destinations
  [ 'name=iPad 2',
    'name=iPad Air',
    'name=iPhone 4s',
    'name=iPhone 5',
    'name=iPhone 5s',
    'name=iPhone 6',
    'name=iPhone 6 Plus'
  ]
end

namespace :test do
  xcode_test :ios do |t|
    t.project = 'HMAC'
    t.scheme = 'HMAC-iOS'
    t.sdk = 'iphonesimulator'
    t.configuration = 'Release'
    destinations.each do |destination|
      t.add_destination(destination)
    end
    t.formatter = 'xcpretty -c'
  end

  xcode_test :osx do |t|
    t.project = 'HMAC'
    t.scheme = 'HMAC-Mac'
    t.sdk = 'macosx'
    t.configuration = 'Release'
    t.formatter = 'xcpretty -c'
  end
end
