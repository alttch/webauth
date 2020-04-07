SELECT id
FROM webauth_user
WHERE id=:id
  AND (password=:password
       OR password IS NULL)
