SELECT count(id) AS c
FROM webauth_user_auth
WHERE user_id=:id
  AND (provider!=:provider
       OR sub!=:sub)
