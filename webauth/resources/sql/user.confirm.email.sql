UPDATE webauth_user
SET confirmed='1', email=:email,
    d_active=:d
WHERE id=:id
