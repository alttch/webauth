SELECT provider, sub, name, picture FROM webauth_user_auth
  WHERE user_id=:id ORDER BY provider, name
