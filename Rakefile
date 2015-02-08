require 'xcjobs'

def destinations
  [ 'name=iPad 2,OS=8.1',
    'name=iPad Air,OS=8.1',
    'name=iPhone 4s,OS=8.1',
    'name=iPhone 5,OS=8.1',
    'name=iPhone 5s,OS=8.1',
    'name=iPhone 6,OS=8.1',
    'name=iPhone 6 Plus,OS=8.1'
  ]
end

XCJobs::Test.new('test:ios') do |t|
  t.project = 'HMAC'
  t.scheme = 'HMAC-iOS'
  t.sdk = 'iphonesimulator'
  t.configuration = 'Release'
  destinations.each do |destination|
    t.add_destination(destination)
  end
  t.formatter = 'xcpretty -c'
end

XCJobs::Test.new('test:osx') do |t|
  t.project = 'HMAC'
  t.scheme = 'HMAC-Mac'
  t.sdk = 'macosx'
  t.configuration = 'Release'
  t.formatter = 'xcpretty -c'
end
