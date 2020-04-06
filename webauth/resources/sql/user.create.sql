INSERT INTO webauth_user(email, password, d_created, d_active, confirmed)
VALUES (:email, :password, :d_created, :d_created, :confirmed) RETURNING id
