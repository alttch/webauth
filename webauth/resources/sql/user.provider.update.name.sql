UPDATE webauth_user_auth
SET name=:name
WHERE user_id=:id
  AND provider=:provider
  AND sub=:sub
