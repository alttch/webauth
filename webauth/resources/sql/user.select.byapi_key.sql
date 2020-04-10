SELECT id,
       email,
       d_created,
       d_active,
       confirmed,
       otp
FROM webauth_user
WHERE api_key=:api_key
