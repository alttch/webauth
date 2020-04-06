SELECT id,
       confirmed
FROM webauth_user
WHERE email=:email
  AND password=:password
