UPDATE webauth_user
SET confirmed='1',
    d_active=:d
WHERE id=:id and email=:email
