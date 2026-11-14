class Net::SMTP
  class AuthLogin < Net::SMTP::Authenticator
    auth_type :login
    auth_credential :password

    def auth(user, secret)
      continue('AUTH LOGIN')
      continue(base64_encode(user))
      finish(base64_encode(secret))
    end
  end
end
