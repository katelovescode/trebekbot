class AuthService
  def self.verify_signature(timestamp, signature, body)
    secret = ENV['SLACK_APP_SIGNING_SECRET']
    version = 'v0' # always v0 for now

    # could be a replay attack
    return false if (Time.now - Time.at(timestamp.to_i)) > 60 * 5

    sig_basestring = [version, timestamp, body].join(':')
    digest = OpenSSL::Digest::SHA256.new
    hex_hash = OpenSSL::HMAC.hexdigest(digest, secret, sig_basestring)
    computed_signature = [version, hex_hash].join('=')

    computed_signature == signature
  end
end