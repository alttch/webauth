INSERT INTO webauth_user(confirmed, d_created)
VALUES ('1', :d_created) RETURNING id
