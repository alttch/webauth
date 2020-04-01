DELETE
FROM webauth_user_auth
WHERE user_id=:id
  AND provider=:provider
  AND sub=:sub
