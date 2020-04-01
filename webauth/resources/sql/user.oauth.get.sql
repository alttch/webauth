SELECT user_id AS id, provider, sub FROM webauth_user_auth
  WHERE provider=:provider AND sub=:sub
